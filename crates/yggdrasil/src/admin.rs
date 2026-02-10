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

async fn handle_request(
    req: &AdminRequest,
    core: &Arc<Core>,
) -> Result<serde_json::Value, String> {
    match req.request.to_lowercase().as_str() {
        "list" => Ok(serde_json::json!({
            "list": ["list", "getself", "getpeers", "gettree", "addpeer", "removepeer"],
        })),

        "getself" => {
            let routing_entries = core.routing_entries().await;
            Ok(serde_json::json!({
                "build_name": env!("CARGO_PKG_NAME"),
                "build_version": env!("CARGO_PKG_VERSION"),
                "key": hex::encode(core.public_key()),
                "address": core.address().to_string(),
                "subnet": core.subnet().to_string(),
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

        other => Err(format!(
            "unknown action '{}', try 'list' for help",
            other
        )),
    }
}

async fn write_response(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    resp: &AdminResponse,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_string(resp).unwrap_or_default();
    writer.write_all(json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
