//! Mobile FFI layer for Yggdrasil-ng.
//!
//! Exposes a UniFFI-compatible API that bridges the async Rust Core
//! with synchronous Android/iOS threads.

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use tokio::sync::{broadcast, Notify};

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use tokio::io::{unix::AsyncFd, Interest};

use yggdrasil::address::addr_for_key;
use yggdrasil::config;
use yggdrasil::core::Core;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::multicast::NetworkInterface;

// ── Tracing initialisation ──────────────────────────────────────────────────

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;

        let env_filter =
            EnvFilter::new("ironwood=info,yggdrasil=info,yggdrasil_mobile=info,info");

        #[cfg(target_os = "android")]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_android::layer("Yggdrasil").unwrap())
                .init();
        }
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    });
}

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum YggdrasilError {
    #[error("Config: {0}")]
    Config(String),
    #[error("Runtime: {0}")]
    Runtime(String),
    #[error("Io: {0}")]
    Io(String),
}

// ── UDL types ───────────────────────────────────────────────────────────────

pub struct MulticastInterfaceConfig {
    pub filter: String,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub priority: u8,
    pub password: String,
}

pub struct YggdrasilConfig {
    pub private_key: String,
    pub peers: Vec<String>,
    pub listen: Vec<String>,
    pub if_mtu: u64,
    pub multicast_interfaces: Vec<MulticastInterfaceConfig>,
    pub node_info_name: String,
    pub tunnel_routing: TunnelRoutingConfig,
    pub group_password: String,
}

pub struct CkrRemoteSubnet {
    pub public_key: String,
    pub cidrs: Vec<String>,
}

pub struct TunnelRoutingConfig {
    pub enable: bool,
    pub ipv4_address: String,
    pub ip_addresses: Vec<String>,
    pub remote_subnets: Vec<CkrRemoteSubnet>,
}

pub struct YggdrasilState {
    pub address: String,
    pub subnet: String,
    pub public_key: String,
    pub routing_entries: i64,
    pub peers_json: String,
    pub tree_json: String,
}

pub struct AndroidNetworkInterface {
    pub name: String,
    pub index: u32,
    pub addrs: Vec<String>,
}

pub trait YggdrasilStateListener: Send + Sync {
    fn on_connectivity_changed(&self, is_online: bool);
}

// ── Config conversion ───────────────────────────────────────────────────────

fn convert_config(cfg: &YggdrasilConfig) -> config::Config {
    let mut node_info = toml::map::Map::new();
    if !cfg.node_info_name.is_empty() {
        node_info.insert(
            "name".to_string(),
            toml::Value::String(cfg.node_info_name.clone()),
        );
    }

    let remote_subnets: std::collections::HashMap<String, Vec<String>> = cfg
        .tunnel_routing
        .remote_subnets
        .iter()
        .map(|r| (r.public_key.clone(), r.cidrs.clone()))
        .collect();

    let mut firewall = config::FirewallConfig::default();
    firewall.enable = true;
    config::Config {
        private_key: cfg.private_key.clone(),
        peers: cfg.peers.clone(),
        listen: cfg.listen.clone(),
        admin_listen: "none".to_string(),
        if_name: "none".to_string(),
        if_mtu: cfg.if_mtu,
        node_info: toml::Value::Table(node_info),
        node_info_privacy: false,
        allowed_public_keys: Vec::new(),
        multicast_interfaces: cfg
            .multicast_interfaces
            .iter()
            .map(|m| config::MulticastInterfaceConfig {
                filter: m.filter.clone(),
                beacon: m.beacon,
                listen: m.listen,
                port: m.port,
                priority: m.priority,
                password: m.password.clone(),
            })
            .collect(),
        tunnel_routing: config::TunnelRoutingConfig {
            enable: cfg.tunnel_routing.enable,
            // ckrYggdrasilRouting is always on for the Android app.
            yggdrasil_routing: true,
            ipv4_address: cfg.tunnel_routing.ipv4_address.clone(),
            ip_addresses: cfg.tunnel_routing.ip_addresses.clone(),
            remote_subnets,
            // Android's VpnService owns system routing; never let the core
            // try to install OS routes from the unprivileged app process.
            install_system_routes: false,
        },
        firewall,
        group_password: cfg.group_password.clone(),
    }
}

fn config_to_udl(cfg: &config::Config) -> YggdrasilConfig {
    let node_info_name = cfg
        .node_info
        .as_table()
        .and_then(|t| t.get("name"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    YggdrasilConfig {
        private_key: cfg.private_key.clone(),
        peers: cfg.peers.clone(),
        listen: cfg.listen.clone(),
        if_mtu: cfg.if_mtu,
        multicast_interfaces: cfg
            .multicast_interfaces
            .iter()
            .map(|m| MulticastInterfaceConfig {
                filter: m.filter.clone(),
                beacon: m.beacon,
                listen: m.listen,
                port: m.port,
                priority: m.priority,
                password: m.password.clone(),
            })
            .collect(),
        node_info_name,
        tunnel_routing: TunnelRoutingConfig {
            enable: false,
            ipv4_address: String::new(),
            ip_addresses: Vec::new(),
            remote_subnets: Vec::new(),
        },
        group_password: cfg.group_password.clone(),
    }
}

// ── Namespace functions ─────────────────────────────────────────────────────

pub fn generate_config() -> YggdrasilConfig {
    let cfg = config::Config::generate();
    config_to_udl(&cfg)
}

pub fn expand_ckr_cidrs(config: TunnelRoutingConfig) -> Vec<String> {
    if !config.enable {
        return Vec::new();
    }
    let mut out = Vec::new();
    for subnet in &config.remote_subnets {
        match yggdrasil::ckr::expand_cidrs(&subnet.cidrs) {
            Ok(prefixes) => {
                for p in prefixes {
                    let s = p.to_string();
                    if !out.contains(&s) {
                        out.push(s);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("expand_ckr_cidrs: {}", e);
            }
        }
    }
    out
}

pub fn get_version() -> String {
    format!(
        "{}.{}",
        yggdrasil::version::PROTOCOL_VERSION_MAJOR,
        yggdrasil::version::PROTOCOL_VERSION_MINOR,
    )
}

// ── Internal state ──────────────────────────────────────────────────────────

struct NodeState {
    core: Arc<Core>,
    rwc: Arc<ReadWriteCloser>,
    stop_tx: broadcast::Sender<()>,
    #[cfg(unix)]
    tun: Option<TunState>,
}

#[cfg(unix)]
struct TunState {
    tun_stop: broadcast::Sender<()>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
    // The Arc is shared with the spawned tasks; when they exit and drop their
    // clones, the final drop here closes the underlying fd via File's Drop.
    _async_fd: Arc<AsyncFd<std::fs::File>>,
}

// ── YggdrasilMobile ─────────────────────────────────────────────────────────

pub struct YggdrasilMobile {
    rt: Arc<tokio::runtime::Runtime>,
    state: Mutex<Option<NodeState>>,
    listener: Arc<dyn YggdrasilStateListener>,
    // Notify has "at most one pending permit" semantics: if notify_one() fires
    // before notified().await, the await returns immediately. That is exactly
    // the behaviour we want for state updates — we don't want to miss a peer
    // event that lands while the Kotlin updater thread is being spawned.
    state_notify: Arc<Notify>,
}

impl YggdrasilMobile {
    pub fn new(listener: Box<dyn YggdrasilStateListener>) -> Result<Self, YggdrasilError> {
        init_tracing();

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| YggdrasilError::Runtime(e.to_string()))?;

        Ok(Self {
            rt: Arc::new(rt),
            state: Mutex::new(None),
            listener: Arc::from(listener),
            state_notify: Arc::new(Notify::new()),
        })
    }

    pub fn start(&self, config: YggdrasilConfig) -> Result<(), YggdrasilError> {
        let rust_config = convert_config(&config);
        let signing_key = rust_config
            .signing_key()
            .map_err(|e| YggdrasilError::Config(e))?;

        let ckr_cfg = rust_config.tunnel_routing.clone();

        let core = self.rt.block_on(async {
            let core = Core::new(signing_key, rust_config);
            core.init_links().await;
            core.start().await;
            core
        });

        let rwc = ReadWriteCloser::new(core.clone(), core.mtu(), Some(&ckr_cfg), None);
        core.set_path_notify(rwc.clone());

        let (stop_tx, _) = broadcast::channel(1);

        // Spawn peer-event monitor
        {
            let cb = Arc::clone(&self.listener);
            let core_ref = Arc::clone(&core);
            let notify = Arc::clone(&self.state_notify);
            let mut peer_rx = core.subscribe_peer_events();
            let mut stop_rx = stop_tx.subscribe();

            self.rt.spawn(async move {
                let mut is_online = false;
                loop {
                    tokio::select! {
                        _ = stop_rx.recv() => break,
                        result = peer_rx.recv() => {
                            match result {
                                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                                    let peers = core_ref.get_peers().await;
                                    let now_online = peers.iter().any(|p| p.up);
                                    if now_online != is_online {
                                        is_online = now_online;
                                        cb.on_connectivity_changed(now_online);
                                    }
                                    notify.notify_one();
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    }
                }
            });
        }

        let mut guard = self.state.lock().unwrap();
        *guard = Some(NodeState {
            core,
            rwc,
            stop_tx,
            #[cfg(unix)]
            tun: None,
        });

        Ok(())
    }

    pub fn recv_buffer(&self) -> Result<Vec<u8>, YggdrasilError> {
        let rwc = {
            let guard = self.state.lock().unwrap();
            guard
                .as_ref()
                .map(|s| Arc::clone(&s.rwc))
                .ok_or_else(|| YggdrasilError::Runtime("node not started".to_string()))?
        };

        let mut buf = vec![0u8; 65535];
        let n = self
            .rt
            .block_on(rwc.read(&mut buf))
            .map_err(|e| YggdrasilError::Io(e))?;

        buf.truncate(n);
        Ok(buf)
    }

    pub fn send_buffer(&self, buf: Vec<u8>) -> Result<(), YggdrasilError> {
        let rwc = {
            let guard = self.state.lock().unwrap();
            guard
                .as_ref()
                .map(|s| Arc::clone(&s.rwc))
                .ok_or_else(|| YggdrasilError::Runtime("node not started".to_string()))?
        };

        // Silently ignore write errors — the TUN sends all traffic through us,
        // including non-Yggdrasil packets that the RWC rightly rejects.
        // This matches the Go behavior: `_, _ = m.iprwc.Write(p[:length])`.
        let _ = self.rt.block_on(rwc.write(&buf));

        Ok(())
    }

    #[cfg(unix)]
    pub fn start_tun(&self, fd: i32) -> Result<(), YggdrasilError> {
        use std::os::fd::{FromRawFd, OwnedFd};

        let mut guard = self.state.lock().unwrap();
        let ns = guard
            .as_mut()
            .ok_or_else(|| YggdrasilError::Runtime("node not started".to_string()))?;

        if ns.tun.is_some() {
            return Err(YggdrasilError::Runtime("tun already started".to_string()));
        }

        // Adopt the fd. Ownership transfers here; closed on Drop.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let file = std::fs::File::from(owned);

        // AsyncFd registers the fd with the tokio reactor; must be called inside
        // a runtime context. Creation is synchronous (no await).
        let async_fd = {
            let _enter = self.rt.enter();
            Arc::new(
                AsyncFd::with_interest(file, Interest::READABLE | Interest::WRITABLE)
                    .map_err(|e| YggdrasilError::Io(e.to_string()))?,
            )
        };

        let (tun_stop_tx, _) = broadcast::channel::<()>(1);

        // Reader task: TUN -> network
        let reader = {
            let async_fd = Arc::clone(&async_fd);
            let rwc = Arc::clone(&ns.rwc);
            let mut stop_rx = tun_stop_tx.subscribe();
            self.rt.spawn(async move {
                let mut buf = vec![0u8; 65536].into_boxed_slice();
                loop {
                    let mut rguard = tokio::select! {
                        _ = stop_rx.recv() => break,
                        r = async_fd.readable() => match r {
                            Ok(g) => g,
                            Err(e) => {
                                tracing::warn!("tun readable() failed: {}", e);
                                break;
                            }
                        },
                    };
                    match rguard.try_io(|inner| (&*inner.get_ref()).read(&mut buf[..])) {
                        Ok(Ok(0)) => break, // EOF — tun closed
                        Ok(Ok(n)) => {
                            // Ignore write errors: the TUN forwards non-Yggdrasil
                            // packets too, which rwc rightly rejects. Matches the
                            // behavior of the old send_buffer path.
                            let _ = rwc.write(&buf[..n]).await;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("tun read error: {}", e);
                            break;
                        }
                        Err(_would_block) => continue,
                    }
                }
            })
        };

        // Writer task: network -> TUN
        let writer = {
            let async_fd = Arc::clone(&async_fd);
            let rwc = Arc::clone(&ns.rwc);
            let mut stop_rx = tun_stop_tx.subscribe();
            self.rt.spawn(async move {
                let mut buf = vec![0u8; 65536].into_boxed_slice();
                loop {
                    let n = tokio::select! {
                        _ = stop_rx.recv() => break,
                        r = rwc.read(&mut buf[..]) => match r {
                            Ok(n) if n > 0 => n,
                            Ok(_) => continue,
                            Err(e) => {
                                tracing::warn!("rwc read error: {}", e);
                                continue;
                            }
                        },
                    };
                    // Drive the write to completion, yielding on EAGAIN.
                    loop {
                        let mut wguard = tokio::select! {
                            _ = stop_rx.recv() => return,
                            w = async_fd.writable() => match w {
                                Ok(g) => g,
                                Err(e) => {
                                    tracing::warn!("tun writable() failed: {}", e);
                                    return;
                                }
                            },
                        };
                        match wguard.try_io(|inner| (&*inner.get_ref()).write(&buf[..n])) {
                            Ok(Ok(_)) => break,
                            Ok(Err(e)) => {
                                tracing::warn!("tun write error: {}", e);
                                break;
                            }
                            Err(_would_block) => continue,
                        }
                    }
                }
            })
        };

        ns.tun = Some(TunState {
            tun_stop: tun_stop_tx,
            reader,
            writer,
            _async_fd: async_fd,
        });

        Ok(())
    }

    #[cfg(not(unix))]
    pub fn start_tun(&self, _fd: i32) -> Result<(), YggdrasilError> {
        Err(YggdrasilError::Io(
            "start_tun is only supported on Unix targets".to_string(),
        ))
    }

    pub fn stop_tun(&self) -> Result<(), YggdrasilError> {
        #[cfg(unix)]
        {
            let tun = {
                let mut guard = self.state.lock().unwrap();
                guard.as_mut().and_then(|ns| ns.tun.take())
            };
            if let Some(tun) = tun {
                let _ = tun.tun_stop.send(());
                self.rt.block_on(async {
                    let _ = tokio::join!(tun.reader, tun.writer);
                });
                // tun._async_fd drops here; fd closes with it.
            }
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<(), YggdrasilError> {
        let node_state = {
            let mut guard = self.state.lock().unwrap();
            guard.take()
        };

        if let Some(ns) = node_state {
            #[cfg(unix)]
            if let Some(tun) = ns.tun {
                let _ = tun.tun_stop.send(());
                self.rt.block_on(async {
                    let _ = tokio::join!(tun.reader, tun.writer);
                });
            }

            let _ = ns.stop_tx.send(());
            self.rt.block_on(async {
                ns.core.close_multicast().await;
                let _ = ns.core.close().await;
            });
        }

        Ok(())
    }

    pub fn retry_peers_now(&self) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let core = Arc::clone(&ns.core);
            self.rt.block_on(core.retry_peers_now());
        }
    }

    /// Force an immediate router refresh / re-announce. Called by Android's
    /// AlarmManager during Doze to nudge the mesh before our tree info is
    /// expired downstream.
    pub fn force_router_refresh(&self) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            ns.core.force_router_refresh();
        }
    }

    pub fn wait_for_state_update(&self, timeout_ms: u64) -> YggdrasilState {
        // Notify::notified() returns immediately if notify_one() was called
        // since the last consumption, and otherwise waits. That means a peer
        // event that lands between start() and the Kotlin updater's first call
        // here is NOT lost — we return right away and the UI reflects the
        // connected state without waiting out the timeout.
        let notify = Arc::clone(&self.state_notify);
        self.rt.block_on(async {
            let _ = tokio::time::timeout(
                Duration::from_millis(timeout_ms),
                notify.notified(),
            )
            .await;
        });

        self.build_state_snapshot()
    }

    pub fn get_address_string(&self) -> String {
        self.with_core(|core| core.address().to_string())
            .unwrap_or_default()
    }

    pub fn get_subnet_string(&self) -> String {
        self.with_core(|core| core.subnet().to_string())
            .unwrap_or_default()
    }

    pub fn get_public_key_string(&self) -> String {
        self.with_core(|core| hex::encode(core.public_key()))
            .unwrap_or_default()
    }

    pub fn get_mtu(&self) -> i64 {
        self.with_core(|core| core.mtu() as i64).unwrap_or(0)
    }

    pub fn get_routing_entries(&self) -> i64 {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return 0,
        };
        self.rt.block_on(core.routing_entries()) as i64
    }

    pub fn get_peers_json(&self) -> String {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return "[]".to_string(),
        };
        let peers = self.rt.block_on(core.get_peers());
        peers_to_json(&peers)
    }

    pub fn get_tree_json(&self) -> String {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => return "[]".to_string(),
        };
        let tree = self.rt.block_on(core.get_tree());
        tree_to_json(&tree)
    }

    pub fn update_network_interfaces(&self, interfaces: Vec<AndroidNetworkInterface>) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let ifaces: Vec<NetworkInterface> = interfaces
                .into_iter()
                .map(|i| NetworkInterface {
                    name: i.name,
                    index: i.index,
                    addrs: i
                        .addrs
                        .iter()
                        .filter_map(|a| a.parse::<Ipv6Addr>().ok())
                        .collect(),
                })
                .collect();
            ns.core.update_network_interfaces(ifaces);
        }
    }

    pub fn start_multicast(&self) {
        if let Some(ns) = self.state.lock().unwrap().as_ref() {
            let core = Arc::clone(&ns.core);
            self.rt.block_on(async {
                if let Err(e) = core.start_multicast().await {
                    tracing::warn!("Multicast peer discovery disabled: {}", e);
                }
            });
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn with_core<T>(&self, f: impl FnOnce(&Core) -> T) -> Option<T> {
        self.state.lock().unwrap().as_ref().map(|ns| f(&ns.core))
    }

    fn build_state_snapshot(&self) -> YggdrasilState {
        let core = match self.state.lock().unwrap().as_ref() {
            Some(ns) => Arc::clone(&ns.core),
            None => {
                return YggdrasilState {
                    address: String::new(),
                    subnet: String::new(),
                    public_key: String::new(),
                    routing_entries: 0,
                    peers_json: "[]".to_string(),
                    tree_json: "[]".to_string(),
                }
            }
        };

        let (routing_entries, peers, tree) = self.rt.block_on(async {
            let re = core.routing_entries().await;
            let peers = core.get_peers().await;
            let tree = core.get_tree().await;
            (re, peers, tree)
        });

        YggdrasilState {
            address: core.address().to_string(),
            subnet: core.subnet().to_string(),
            public_key: hex::encode(core.public_key()),
            routing_entries: routing_entries as i64,
            peers_json: peers_to_json(&peers),
            tree_json: tree_to_json(&tree),
        }
    }
}

// ── JSON serialization for peers/tree ───────────────────────────────────────

fn peers_to_json(peers: &[yggdrasil::links::LinkPeerInfo]) -> String {
    let json_peers: Vec<serde_json::Value> = peers
        .iter()
        .map(|p| {
            let ip = if p.key != [0u8; 32] {
                let addr = addr_for_key(&p.key);
                std::net::Ipv6Addr::from(addr.0).to_string()
            } else {
                String::new()
            };

            serde_json::json!({
                "URI": p.uri,
                "Up": p.up,
                "Inbound": p.inbound,
                "PublicKey": hex::encode(p.key),
                "Priority": p.priority,
                "RxBytes": p.rx_bytes,
                "TxBytes": p.tx_bytes,
                "RxRate": p.rx_rate,
                "TxRate": p.tx_rate,
                "UptimeSecs": p.uptime_secs,
                "Latency": p.latency_ms / 1000.0,
                "Cost": p.cost,
                "LastError": p.last_error,
                "IP": ip,
            })
        })
        .collect();

    serde_json::to_string(&json_peers).unwrap_or_else(|_| "[]".to_string())
}

fn tree_to_json(tree: &[ironwood::TreeEntry]) -> String {
    let json_tree: Vec<serde_json::Value> = tree
        .iter()
        .map(|e| {
            serde_json::json!({
                "Key": hex::encode(e.key),
                "Parent": hex::encode(e.parent),
                "Sequence": e.sequence,
            })
        })
        .collect();

    serde_json::to_string(&json_tree).unwrap_or_else(|_| "[]".to_string())
}
