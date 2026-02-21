use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::address::{addr_for_key, subnet_for_key};
use crate::core::Core;

/// JSON-RPC request format.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdminRequest {
    pub request: String,
    #[serde(default)]
    pub arguments: serde_json::Value,
    #[serde(default)]
    pub keepalive: bool,
}

/// JSON-RPC response format.
#[derive(Debug, Serialize)]
pub struct AdminResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub request: AdminRequest,
    pub response: serde_json::Value,
}

/// Admin socket for monitoring and controlling the node.
pub struct AdminSocket {
    cancel: CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl AdminSocket {
    /// Start the admin socket on the given address.
    /// Address format: "tcp://host:port"
    pub async fn new(listen_addr: &str, core: Arc<Core>) -> Result<Self, String> {
        if listen_addr.is_empty() || listen_addr == "none" {
            return Ok(Self {
                cancel: CancellationToken::new(),
                handle: None,
            });
        }

        let addr = listen_addr
            .strip_prefix("tcp://")
            .ok_or_else(|| format!("admin listen must start with tcp://, got: {}", listen_addr))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("admin socket bind failed: {}", e))?;

        let actual_addr = listener
            .local_addr()
            .map_err(|e| format!("admin local_addr: {}", e))?;
        tracing::info!("Admin socket listening on tcp://{}", actual_addr);

        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _)) => {
                                let core = core.clone();
                                tokio::spawn(async move {
                                    handle_admin_conn(stream, core).await;
                                });
                            }
                            Err(e) => {
                                tracing::error!("Admin accept error: {}", e);
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            cancel,
            handle: Some(handle),
        })
    }

    /// Stop the admin socket.
    pub fn close(&self) {
        self.cancel.cancel();
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

async fn handle_admin_conn(stream: tokio::net::TcpStream, core: Arc<Core>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let req: AdminRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let resp = AdminResponse {
                    status: "error".to_string(),
                    error: Some(format!("failed to parse request: {}", e)),
                    request: AdminRequest {
                        request: String::new(),
                        arguments: serde_json::Value::Null,
                        keepalive: false,
                    },
                    response: serde_json::Value::Null,
                };
                let _ = write_response(&mut writer, &resp).await;
                break;
            }
        };

        let keepalive = req.keepalive;
        let result = handle_request(&req, &core).await;

        let resp = match result {
            Ok(response) => AdminResponse {
                status: "success".to_string(),
                error: None,
                request: req,
                response,
            },
            Err(e) => AdminResponse {
                status: "error".to_string(),
                error: Some(e),
                request: req,
                response: serde_json::Value::Null,
            },
        };

        let _ = write_response(&mut writer, &resp).await;

        if !keepalive {
            break;
        }
    }
}

async fn handle_request(req: &AdminRequest, core: &Arc<Core>) -> Result<serde_json::Value, String> {
    match req.request.to_lowercase().as_str() {
        "list" => Ok(serde_json::json!({
            "list": ["list", "getself", "getpeers", "gettree", "getpaths", "getsessions", "gettun", "addpeer", "removepeer", "getdebug", "getlookup", "forcelookup", "getnodeinfo", "debug_remotegetself", "debug_remotegetpeers", "debug_remotegettree"],
        })),

        "getself" => {
            let routing_entries = core.routing_entries().await;
            let coordinates = core.tree_coordinates().await;
            Ok(serde_json::json!({
                "build_name": env!("CARGO_PKG_NAME"),
                "build_version": env!("CARGO_PKG_VERSION"),
                "key": hex::encode(core.public_key()),
                "address": core.address().to_string(),
                "subnet": core.subnet().to_string(),
                "coordinates": coordinates,
                "routing_entries": routing_entries,
            }))
        }

        "getpeers" => {
            let peers = core.get_peers().await;
            let peers_json: Vec<serde_json::Value> = peers
                .iter()
                .map(|p| {
                    let address = addr_for_key(&p.key);
                    let subnet = subnet_for_key(&p.key);
                    serde_json::json!({
                        "uri": p.uri,
                        "up": p.up,
                        "inbound": p.inbound,
                        "key": hex::encode(p.key),
                        "address": address.to_string(),
                        "subnet": subnet.to_string(),
                        "priority": p.priority,
                        "cost": p.cost,
                        "latency": p.latency_ms,
                        "bytes_recvd": p.rx_bytes,
                        "bytes_sent": p.tx_bytes,
                        "rx_rate": p.rx_rate,
                        "tx_rate": p.tx_rate,
                        "uptime": p.uptime_secs,
                        "last_error": p.last_error,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "peers": peers_json }))
        }

        "gettree" => {
            let tree = core.get_tree().await;
            let tree_json: Vec<serde_json::Value> = tree
                .iter()
                .map(|t| {
                    let address = addr_for_key(&t.key);
                    serde_json::json!({
                        "key": hex::encode(t.key),
                        "address": address.to_string(),
                        "parent": hex::encode(t.parent),
                        "sequence": t.sequence,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "tree": tree_json }))
        }

        "addpeer" => {
            let uri = req
                .arguments
                .get("uri")
                .and_then(|v| v.as_str())
                .ok_or("missing 'uri' argument")?;
            core.add_peer(uri)
                .await
                .map_err(|e| format!("addPeer failed: {}", e))?;
            Ok(serde_json::json!({}))
        }

        "removepeer" => {
            let uri = req
                .arguments
                .get("uri")
                .and_then(|v| v.as_str())
                .ok_or("missing 'uri' argument")?;
            core.remove_peer(uri)
                .await
                .map_err(|e| format!("removePeer failed: {}", e))?;
            Ok(serde_json::json!({}))
        }

        "getpaths" => {
            let paths = core.get_paths().await;
            let paths_json: Vec<serde_json::Value> = paths
                .iter()
                .map(|p| {
                    let address = addr_for_key(&p.key);
                    serde_json::json!({
                        "key": hex::encode(p.key),
                        "address": address.to_string(),
                        "path": p.path,
                        "sequence": p.sequence,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "paths": paths_json }))
        }

        "getsessions" => {
            let sessions = core.get_sessions().await;
            let sessions_json: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    let address = addr_for_key(&s.key);
                    serde_json::json!({
                        "key": hex::encode(s.key),
                        "address": address.to_string(),
                        "bytes_sent": s.bytes_sent,
                        "bytes_recvd": s.bytes_recvd,
                        "uptime": s.uptime_seconds,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "sessions": sessions_json }))
        }

        "gettun" => {
            let (enabled, name, mtu) = core.get_tun_status();
            Ok(serde_json::json!({
                "enabled": enabled,
                "name": name,
                "mtu": mtu,
            }))
        }

        "getdebug" => {
            let snap = core.get_debug_snapshot().await;
            let sessions = core.get_sessions().await;
            let peers = core.get_peers().await;

            let peer_latencies: Vec<serde_json::Value> = snap.peer_latencies_ms
                .iter()
                .map(|(key, ms)| {
                    let address = addr_for_key(key);
                    serde_json::json!({
                        "key": hex::encode(key),
                        "address": address.to_string(),
                        "latency_ms": ms,
                    })
                })
                .collect();

            let peers_down: Vec<serde_json::Value> = peers
                .iter()
                .filter(|p| !p.up)
                .map(|p| serde_json::json!({
                    "uri": p.uri,
                    "last_error": p.last_error,
                }))
                .collect();

            let sessions_json: Vec<serde_json::Value> = sessions
                .iter()
                .map(|s| {
                    let address = addr_for_key(&s.key);
                    serde_json::json!({
                        "key": hex::encode(s.key),
                        "address": address.to_string(),
                        "uptime": s.uptime_seconds,
                        "bytes_sent": s.bytes_sent,
                        "bytes_recvd": s.bytes_recvd,
                    })
                })
                .collect();

            let pending_lookups: Vec<serde_json::Value> = snap.pending_lookups
                .iter()
                .map(|p| {
                    let dest_info = p.dest_key.map(|k| {
                        let address = addr_for_key(&k);
                        serde_json::json!({
                            "key": hex::encode(k),
                            "address": address.to_string(),
                        })
                    });
                    serde_json::json!({
                        "dest": dest_info,
                        "xformed_key": hex::encode(p.xformed_key),
                        "age_secs": p.age_secs,
                        "sent": p.sent,
                        "multicast_count": p.multicast_count,
                    })
                })
                .collect();

            Ok(serde_json::json!({
                "tree_node_count": snap.tree_node_count,
                "routing_peer_count": snap.routing_peer_count,
                "tree_root": hex::encode(snap.tree_root),
                "our_coords": snap.our_coords,
                "path_cache_count": snap.path_cache_count,
                "broken_path_count": snap.broken_path_count,
                "pending_lookups": pending_lookups,
                "unresponded_peers": snap.unresponded_peers,
                "delivery_queue_bytes": snap.delivery_queue_bytes,
                "peer_latencies": peer_latencies,
                "peers_down": peers_down,
                "sessions": sessions_json,
            }))
        }

        "getlookup" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let address = addr_for_key(&key);
            let (xformed_key, multicast_count) = core.count_lookup_targets(key).await;

            Ok(serde_json::json!({
                "key": hex::encode(key),
                "address": address.to_string(),
                "xformed_key": hex::encode(xformed_key),
                "multicast_count": multicast_count,
            }))
        }

        "forcelookup" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let address = addr_for_key(&key);
            let (xformed_key, bloom_targets) = core.count_lookup_targets(key).await;
            let sent_to = core.force_lookup(key).await;

            Ok(serde_json::json!({
                "key": hex::encode(key),
                "address": address.to_string(),
                "xformed_key": hex::encode(xformed_key),
                "bloom_targets": bloom_targets,
                "sent_to": sent_to,
            }))
        }

        "getnodeinfo" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let response = core.proto_handler().send_nodeinfo_request(key).await
                .map_err(|e| format!("getNodeInfo failed: {}", e))?;

            Ok(serde_json::json!({
                hex::encode(key): response
            }))
        }

        "debug_remotegetself" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let response = core.proto_handler().send_get_self_request(key).await
                .map_err(|e| format!("debug_remoteGetSelf failed: {}", e))?;

            let address = addr_for_key(&key);
            Ok(serde_json::json!({
                address.to_string(): response
            }))
        }

        "debug_remotegetpeers" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let peer_keys = core.proto_handler().send_get_peers_request(key).await
                .map_err(|e| format!("debug_remoteGetPeers failed: {}", e))?;

            let keys_json: Vec<String> = peer_keys.iter()
                .map(|k| hex::encode(k))
                .collect();

            let address = addr_for_key(&key);
            Ok(serde_json::json!({
                address.to_string(): {
                    "keys": keys_json
                }
            }))
        }

        "debug_remotegettree" => {
            let key_str = req
                .arguments
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("missing 'key' argument")?;
            let key_bytes = hex::decode(key_str)
                .map_err(|_| "invalid hex key")?;
            if key_bytes.len() != 32 {
                return Err("key must be 32 bytes".to_string());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);

            let tree_keys = core.proto_handler().send_get_tree_request(key).await
                .map_err(|e| format!("debug_remoteGetTree failed: {}", e))?;

            let keys_json: Vec<String> = tree_keys.iter()
                .map(|k| hex::encode(k))
                .collect();

            let address = addr_for_key(&key);
            Ok(serde_json::json!({
                address.to_string(): {
                    "keys": keys_json
                }
            }))
        }

        other => Err(format!(
            "unknown action '{}', try 'list' for help",
            other
        )),
    }
}

async fn write_response(writer: &mut tokio::net::tcp::OwnedWriteHalf, resp: &AdminResponse) -> Result<(), std::io::Error> {
    let json = serde_json::to_string(resp).unwrap_or_default();
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
