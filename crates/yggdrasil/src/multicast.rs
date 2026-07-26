use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU16, Ordering};

use blake2::Blake2b512;
use getifaddrs::{self, InterfaceFlags};
use glob_match::glob_match;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{watch, Mutex};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::config::MulticastInterfaceConfig;
use crate::core::Core;
use crate::links::{self, LinkOptions, LinkType, Stream};
use crate::version::{PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR};

const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0114);
static MULTICAST_PORT: AtomicU16 = AtomicU16::new(9001);
const BEACON_MAX_INTERVAL: Duration = Duration::from_secs(15);
const RECV_BUF_SIZE: usize = 2048;

/// Override the multicast UDP port (default 9001). Call once at startup.
pub fn set_multicast_port(port: u16) {
    MULTICAST_PORT.store(port, Ordering::Relaxed);
}

// ── External interface info ──────────────────────────────────────────────

/// Network interface info provided externally (e.g. from Android ConnectivityManager).
/// On platforms where `getifaddrs()` is restricted, the app can supply this data instead.
#[derive(Clone, Debug)]
pub struct NetworkInterface {
    pub name: String,
    pub index: u32,
    pub addrs: Vec<Ipv6Addr>,
}

// ── Advertisement wire format ────────────────────────────────────────────

/// Multicast advertisement matching Go's wire format.
struct Advertisement {
    major_version: u16,
    minor_version: u16,
    public_key: [u8; 32],
    port: u16,
    hash: Vec<u8>,
}

impl Advertisement {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40 + self.hash.len());
        buf.extend_from_slice(&self.major_version.to_be_bytes());
        buf.extend_from_slice(&self.minor_version.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.hash);
        buf
    }

    fn decode(data: &[u8]) -> Result<Self, &'static str> {
        // Minimum size: 2+2+32+2+2 = 40 bytes (with empty hash)
        if data.len() < 40 {
            return Err("advertisement too short");
        }
        let major_version = u16::from_be_bytes([data[0], data[1]]);
        let minor_version = u16::from_be_bytes([data[2], data[3]]);
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[4..36]);
        let port = u16::from_be_bytes([data[36], data[37]]);
        let hash_len = u16::from_be_bytes([data[38], data[39]]) as usize;
        if data.len() < 40 + hash_len {
            return Err("advertisement hash truncated");
        }
        let hash = data[40..40 + hash_len].to_vec();
        Ok(Self { major_version, minor_version, public_key, port, hash })
    }
}

// ── Auth hash ────────────────────────────────────────────────────────────

/// Compute BLAKE2b-512 auth hash matching Go's blake2b.New512(password).Write(publicKey).
fn compute_auth_hash(public_key: &[u8; 32], password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        // Unkeyed BLAKE2b-512
        use blake2::Digest;
        let mut hasher = Blake2b512::new();
        hasher.update(public_key);
        hasher.finalize().to_vec()
    } else {
        // Keyed BLAKE2b-512 (password as MAC key)
        use blake2::digest::Mac;
        use blake2::Blake2bMac512;
        let mut mac = Blake2bMac512::new_from_slice(password)
            .expect("BLAKE2b accepts any key length up to 64 bytes");
        mac.update(public_key);
        mac.finalize().into_bytes().to_vec()
    }
}

// ── Per-interface state ──────────────────────────────────────────────────

struct InterfaceState {
    index: u32,
    addrs: Vec<Ipv6Addr>,
    beacon: bool,
    listen: bool,
    port: u16,
    priority: u8,
    password: Vec<u8>,
    hash: Vec<u8>,
    beacon_interval: Duration,
    last_beacon: Instant,
}

/// Info about a TLS listener started for beaconing.
struct ListenerInfo {
    port: u16,
    cancel: CancellationToken,
    _handle: tokio::task::JoinHandle<()>,
}

// ── Public API ───────────────────────────────────────────────────────────

/// Info returned by admin API.
pub struct MulticastInterfaceInfo {
    pub name: String,
    pub beacon: bool,
    pub listen: bool,
    pub port: u16,
    pub password: bool,
}

/// Manages multicast peer discovery.
pub struct Multicast {
    cancel: CancellationToken,
    interfaces: Arc<Mutex<HashMap<String, InterfaceState>>>,
    listeners: Arc<Mutex<HashMap<String, ListenerInfo>>>,
    _monitor_handle: tokio::task::JoinHandle<()>,
    _receiver_handle: tokio::task::JoinHandle<()>,
}

impl Multicast {
    /// Create and start the multicast discovery engine.
    ///
    /// If `external_rx` is `Some`, interface info is taken from the watch channel
    /// instead of enumerating system interfaces via `getifaddrs()`. This is needed
    /// on Android API 30+ where interface enumeration is restricted.
    pub async fn new(
        core: Arc<Core>,
        config: Vec<MulticastInterfaceConfig>,
        external_rx: Option<watch::Receiver<Vec<NetworkInterface>>>,
    ) -> Result<Self, String> {
        // Check if any interface has beacon or listen enabled
        let any_enabled = config.iter().any(|c| c.beacon || c.listen);
        if !any_enabled {
            return Err("no multicast interfaces enabled".to_string());
        }

        // Collect glob patterns
        let patterns: Vec<MulticastInterfaceConfig> = config.clone();

        // Create UDP6 socket for multicast
        let socket = create_multicast_socket()
            .map_err(|e| format!("failed to create multicast socket: {}", e))?;
        let std_socket: std::net::UdpSocket = socket.into();
        let udp = UdpSocket::from_std(std_socket)
            .map_err(|e| format!("failed to wrap UDP socket: {}", e))?;
        let udp = Arc::new(udp);

        let cancel = CancellationToken::new();
        let interfaces: Arc<Mutex<HashMap<String, InterfaceState>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let listeners: Arc<Mutex<HashMap<String, ListenerInfo>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Spawn the combined monitor + sender task
        let monitor_handle = {
            let cancel = cancel.clone();
            let core = core.clone();
            let interfaces = interfaces.clone();
            let listeners = listeners.clone();
            let udp = udp.clone();
            let patterns = patterns.clone();
            tokio::spawn(async move {
                monitor_and_announce_loop(cancel, core, interfaces, listeners, udp, patterns, external_rx).await;
            })
        };

        // Spawn the receiver task
        let receiver_handle = {
            let cancel = cancel.clone();
            let core = core.clone();
            let interfaces = interfaces.clone();
            let udp = udp.clone();
            tokio::spawn(async move {
                receiver_loop(cancel, core, interfaces, udp).await;
            })
        };

        Ok(Self {
            cancel,
            interfaces,
            listeners,
            _monitor_handle: monitor_handle,
            _receiver_handle: receiver_handle,
        })
    }

    /// Stop the multicast discovery engine.
    pub fn close(&self) {
        self.cancel.cancel();
    }

    /// Get the list of active multicast interfaces (for admin API).
    pub async fn get_interfaces(&self) -> Vec<MulticastInterfaceInfo> {
        let ifaces = self.interfaces.lock().await;
        let listeners = self.listeners.lock().await;
        let mut result = Vec::new();
        for (name, state) in ifaces.iter() {
            let port = listeners.get(name).map(|l| l.port).unwrap_or(0);
            result.push(MulticastInterfaceInfo {
                name: name.clone(),
                beacon: state.beacon,
                listen: state.listen,
                port,
                password: !state.password.is_empty(),
            });
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }
}

// ── Socket creation ──────────────────────────────────────────────────────

fn create_multicast_socket() -> std::io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_only_v6(true)?;

    let bind_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MULTICAST_PORT.load(Ordering::Relaxed), 0, 0);
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;

    Ok(socket)
}

// ── Interface discovery ──────────────────────────────────────────────────

/// Intermediate: collects per-interface data from the getifaddrs iterator.
struct IfInfo {
    index: u32,
    addrs: Vec<Ipv6Addr>,
}

/// Get the display name for an interface entry.
/// On Windows, getifaddrs returns internal names like "ethernet_32778" in `name`,
/// but the human-readable name ("Ethernet", "Wi-Fi") is in `description`.
fn interface_display_name(entry: &getifaddrs::Interface) -> String {
    #[cfg(windows)]
    {
        if !entry.description.is_empty() {
            return entry.description.clone();
        }
    }
    entry.name.clone()
}

/// Enumerate system interfaces and match against configured patterns.
/// Returns map of display_name -> InterfaceState.
fn discover_interfaces(core: &Core, patterns: &[MulticastInterfaceConfig]) -> HashMap<String, InterfaceState> {
    let mut result = HashMap::new();

    let entries = match getifaddrs::getifaddrs() {
        Ok(it) => it,
        Err(e) => {
            tracing::warn!("Failed to enumerate network interfaces: {}", e);
            return result;
        }
    };

    // getifaddrs returns one entry per (interface, address) pair.
    // Group by display name, collecting link-local IPv6 addresses and flags.
    let mut by_name: HashMap<String, IfInfo> = HashMap::new();

    for entry in entries {
        let flags = entry.flags;

        // Apply Go-equivalent flag filters:
        // - Must be up
        // - Must be running
        // - Must support multicast
        // - Must NOT be point-to-point (VPN tunnels, PPP)
        // - Must NOT be loopback
        if !flags.contains(InterfaceFlags::UP) { continue; }
        if !flags.contains(InterfaceFlags::RUNNING) { continue; }
        if !flags.contains(InterfaceFlags::MULTICAST) { continue; }
        if flags.contains(InterfaceFlags::POINTTOPOINT) { continue; }
        if flags.contains(InterfaceFlags::LOOPBACK) { continue; }

        let index = entry.index.unwrap_or(0);
        let display_name = interface_display_name(&entry);

        // Check for IPv6 link-local address
        if let getifaddrs::Address::V6(v6) = &entry.address {
            let ip = v6.address;
            let segments = ip.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                let info = by_name.entry(display_name).or_insert_with(|| IfInfo {
                    index,
                    addrs: Vec::new(),
                });
                info.addrs.push(ip);
            }
        }
    }

    let pk = core.public_key();

    for (name, info) in &by_name {
        if info.addrs.is_empty() {
            continue;
        }

        // Match against configured patterns (first match wins)
        for cfg in patterns {
            if !cfg.beacon && !cfg.listen {
                continue;
            }
            if !glob_match(&cfg.filter, name) {
                continue;
            }

            let password = cfg.password.as_bytes().to_vec();
            let hash = compute_auth_hash(pk, &password);

            result.insert(name.clone(), InterfaceState {
                index: info.index,
                addrs: info.addrs.clone(),
                beacon: cfg.beacon,
                listen: cfg.listen,
                port: cfg.port,
                priority: cfg.priority,
                password,
                hash,
                beacon_interval: Duration::from_secs(1),
                last_beacon: Instant::now() - Duration::from_secs(60), // trigger immediate first beacon
            });

            break; // first match wins
        }
    }

    result
}

/// Build interface map from externally provided interface info (e.g. Android ConnectivityManager).
/// Applies the same glob pattern matching as `discover_interfaces`.
fn discover_from_external(
    core: &Core,
    patterns: &[MulticastInterfaceConfig],
    external: &[NetworkInterface],
) -> HashMap<String, InterfaceState> {
    let mut result = HashMap::new();
    let pk = core.public_key();

    for iface in external {
        if iface.addrs.is_empty() {
            continue;
        }

        // Match against configured patterns (first match wins)
        for cfg in patterns {
            if !cfg.beacon && !cfg.listen {
                continue;
            }
            if !glob_match(&cfg.filter, &iface.name) {
                continue;
            }

            let password = cfg.password.as_bytes().to_vec();
            let hash = compute_auth_hash(pk, &password);

            result.insert(iface.name.clone(), InterfaceState {
                index: iface.index,
                addrs: iface.addrs.clone(),
                beacon: cfg.beacon,
                listen: cfg.listen,
                port: cfg.port,
                priority: cfg.priority,
                password,
                hash,
                beacon_interval: Duration::from_secs(1),
                last_beacon: Instant::now() - Duration::from_secs(60),
            });

            break; // first match wins
        }
    }

    result
}

// ── Monitor + announce loop ──────────────────────────────────────────────

async fn monitor_and_announce_loop(
    cancel: CancellationToken,
    core: Arc<Core>,
    interfaces: Arc<Mutex<HashMap<String, InterfaceState>>>,
    listeners: Arc<Mutex<HashMap<String, ListenerInfo>>>,
    udp: Arc<UdpSocket>,
    patterns: Vec<MulticastInterfaceConfig>,
    external_rx: Option<watch::Receiver<Vec<NetworkInterface>>>,
) {
    let dest = SocketAddrV6::new(MULTICAST_GROUP, MULTICAST_PORT.load(Ordering::Relaxed), 0, 0);

    loop {
        // Update interfaces: use external source if provided, otherwise enumerate via getifaddrs
        let new_ifaces = if let Some(rx) = &external_rx {
            discover_from_external(&core, &patterns, &rx.borrow())
        } else {
            discover_interfaces(&core, &patterns)
        };

        // Update shared state, preserving beacon timing for existing interfaces
        {
            let mut ifaces = interfaces.lock().await;

            // Remove interfaces that are no longer present
            let old_names: Vec<String> = ifaces.keys().cloned().collect();
            for name in &old_names {
                if !new_ifaces.contains_key(name) {
                    ifaces.remove(name);
                    // Stop listener for removed interface
                    let mut lsns = listeners.lock().await;
                    if let Some(info) = lsns.remove(name) {
                        info.cancel.cancel();
                        tracing::debug!("Stopped multicast listener on {}", name);
                    }
                }
            }

            // Add/update interfaces
            for (name, new_state) in &new_ifaces {
                if let Some(existing) = ifaces.get_mut(name) {
                    // Preserve beacon timing, update addresses
                    existing.addrs = new_state.addrs.clone();
                    existing.index = new_state.index;
                } else {
                    // New interface
                    ifaces.insert(name.clone(), InterfaceState {
                        index: new_state.index,
                        addrs: new_state.addrs.clone(),
                        beacon: new_state.beacon,
                        listen: new_state.listen,
                        port: new_state.port,
                        priority: new_state.priority,
                        password: new_state.password.clone(),
                        hash: new_state.hash.clone(),
                        beacon_interval: Duration::from_secs(1),
                        last_beacon: Instant::now() - Duration::from_secs(60),
                    });
                    tracing::debug!("Discovered multicast interface: {}", name);
                }
            }
        }

        // Join multicast group on listening interfaces and manage listeners
        {
            let mut ifaces = interfaces.lock().await;
            let mut lsns = listeners.lock().await;

            // Remove listeners for interfaces that no longer exist
            let listener_names: Vec<String> = lsns.keys().cloned().collect();
            for name in &listener_names {
                if !ifaces.contains_key(name) {
                    if let Some(info) = lsns.remove(name) {
                        info.cancel.cancel();
                    }
                }
            }

            for (name, state) in ifaces.iter_mut() {
                // Join multicast group on each link-local address
                if state.listen {
                    for addr in &state.addrs {
                        let _ = join_multicast_on_interface(&udp, state.index, addr);
                    }
                }

                // Start TLS listener for beaconing interfaces
                if state.beacon && !lsns.contains_key(name) {
                    if let Some(link_local) = state.addrs.first() {
                        match start_tls_listener(&core, *link_local, state.port, state.index, state.priority, &state.password).await {
                            Ok((actual_port, lcancel, handle)) => {
                                tracing::info!("Multicast beacon listener on {} port {}", name, actual_port);
                                lsns.insert(name.clone(), ListenerInfo {
                                    port: actual_port,
                                    cancel: lcancel,
                                    _handle: handle,
                                });
                            }
                            Err(e) => {
                                tracing::warn!("Failed to start multicast listener on {}: {}", name, e);
                            }
                        }
                    }
                }

                // Send beacon if interval elapsed
                if state.beacon {
                    if let Some(listener_info) = lsns.get(name) {
                        if state.last_beacon.elapsed() >= state.beacon_interval {
                            let adv = Advertisement {
                                major_version: PROTOCOL_VERSION_MAJOR,
                                minor_version: PROTOCOL_VERSION_MINOR,
                                public_key: *core.public_key(),
                                port: listener_info.port,
                                hash: state.hash.clone(),
                            };
                            let msg = adv.encode();

                            // Send to multicast group on this interface
                            let dest_with_scope = SocketAddrV6::new(
                                *dest.ip(),
                                dest.port(),
                                0,
                                state.index,
                            );
                            if let Err(e) = udp.send_to(&msg, dest_with_scope).await {
                                tracing::debug!("Failed to send multicast beacon on {}: {}", name, e);
                            }

                            // Backoff
                            if state.beacon_interval < BEACON_MAX_INTERVAL {
                                state.beacon_interval += Duration::from_secs(1);
                            }
                            state.last_beacon = Instant::now();
                        }
                    }
                }
            }
        }

        // Sleep with jitter (1s + random 0-1048575 microseconds, matching Go)
        let jitter = rand::random::<u32>() % 1_048_576;
        let sleep_dur = Duration::from_secs(1) + Duration::from_micros(jitter as u64);

        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(sleep_dur) => {}
        }
    }
}

// ── Receiver loop ────────────────────────────────────────────────────────

async fn receiver_loop(
    cancel: CancellationToken,
    core: Arc<Core>,
    interfaces: Arc<Mutex<HashMap<String, InterfaceState>>>,
    udp: Arc<UdpSocket>,
) {
    let mut buf = vec![0u8; RECV_BUF_SIZE];

    loop {
        let (n, from) = tokio::select! {
            _ = cancel.cancelled() => break,
            result = udp.recv_from(&mut buf) => {
                match result {
                    Ok(r) => r,
                    Err(e) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                        tracing::debug!("Multicast recv error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            }
        };

        // Parse advertisement
        let adv = match Advertisement::decode(&buf[..n]) {
            Ok(a) => a,
            Err(e) => {
                tracing::trace!("Invalid multicast beacon: {}", e);
                continue;
            }
        };

        // Version check
        if adv.major_version != PROTOCOL_VERSION_MAJOR {
            continue;
        }
        if adv.minor_version != PROTOCOL_VERSION_MINOR {
            continue;
        }

        // Skip our own beacons
        if adv.public_key == *core.public_key() {
            continue;
        }

        // Check if we already have a connection to this key
        if core.active_links.has_key(&adv.public_key).await {
            continue;
        }

        // Get source address info
        let from_v6 = match from {
            std::net::SocketAddr::V6(v6) => v6,
            _ => continue,
        };

        // Find the interface this came from and verify hash
        let scope_id = from_v6.scope_id();
        let (password, priority, iface_name) = {
            let ifaces = interfaces.lock().await;
            // Find interface by scope_id (index)
            let found = ifaces.iter().find(|(_, state)| state.index == scope_id && state.listen);
            match found {
                Some((name, state)) => {
                    // Verify auth hash
                    let expected_hash = compute_auth_hash(&adv.public_key, &state.password);
                    if expected_hash != adv.hash {
                        tracing::debug!("Multicast auth hash mismatch from {} on {}", from, name);
                        continue;
                    }
                    (state.password.clone(), state.priority, name.clone())
                }
                None => continue,
            }
        };

        // Connect to the discovered peer
        let peer_addr = SocketAddrV6::new(*from_v6.ip(), adv.port, 0, scope_id);
        let uri = format!(
            "tls://[{}%{}]:{}",
            from_v6.ip(),
            iface_name,
            adv.port,
        );

        tracing::info!(
            "Discovered multicast peer {} on {}",
            hex::encode(&adv.public_key[..8]),
            iface_name
        );

        let core = core.clone();
        tokio::spawn(async move {
            if let Err(e) = connect_to_peer(&core, peer_addr, &uri, priority, &password).await {
                tracing::debug!("Failed to connect to multicast peer {}: {}", uri, e);
            }
        });
    }
}

// ── Connecting to discovered peers ───────────────────────────────────────

async fn connect_to_peer(
    core: &Arc<Core>,
    addr: SocketAddrV6,
    uri: &str,
    priority: u8,
    password: &[u8],
) -> Result<(), String> {
    // TCP connect
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("TCP connect: {}", e))?;
    tcp.set_nodelay(true).ok();

    // TLS handshake
    let client_config = core.tls_client_config.read().await.clone();
    let connector = TlsConnector::from(client_config);
    let server_name = rustls::pki_types::ServerName::IpAddress(
        std::net::IpAddr::V6(*addr.ip()).into(),
    );
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake: {}", e))?;

    let stream = Stream::TlsClient(tls_stream);
    let options = LinkOptions {
        pinned_keys: Vec::new(),
        priority,
        password: password.to_vec(),
        max_backoff: Duration::from_secs(0), // not used for ephemeral
        tls_sni: None,
    };

    links::handle_connection(
        LinkType::Ephemeral,
        options,
        stream,
        core,
        &core.active_links,
        uri,
    )
    .await
    .map_err(|e| format!("handshake: {}", e))
}

// ── TLS listener for beaconing ───────────────────────────────────────────

async fn start_tls_listener(
    core: &Arc<Core>,
    bind_addr: Ipv6Addr,
    port: u16,
    scope_id: u32,
    priority: u8,
    password: &[u8],
) -> Result<(u16, CancellationToken, tokio::task::JoinHandle<()>), String> {
    let bind = SocketAddrV6::new(bind_addr, port, 0, scope_id);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {}: {}", bind, e))?;

    let actual_port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {}", e))?
        .port();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let core = core.clone();
    let password = password.to_vec();

    let handle = tokio::spawn(async move {
        let server_config = core.tls_server_config.read().await.clone();
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        loop {
            tokio::select! {
                _ = cancel_clone.cancelled() => break,
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote)) => {
                            stream.set_nodelay(true).ok();
                            let core = core.clone();
                            let active = core.active_links.clone();
                            let acceptor = acceptor.clone();
                            let password = password.clone();
                            let remote_str = format!("tls://{}", remote);

                            tokio::spawn(async move {
                                let tls_stream = match acceptor.accept(stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::debug!("Multicast TLS accept failed from {}: {}", remote, e);
                                        return;
                                    }
                                };

                                let opts = LinkOptions {
                                    pinned_keys: Vec::new(),
                                    priority,
                                    password,
                                    max_backoff: Duration::from_secs(0),
                                    tls_sni: None,
                                };

                                let _ = links::handle_connection(
                                    LinkType::Incoming,
                                    opts,
                                    Stream::Tls(tls_stream),
                                    &core,
                                    &active,
                                    &remote_str,
                                ).await;
                            });
                        }
                        Err(e) => {
                            tracing::debug!("Multicast listener accept error: {}", e);
                        }
                    }
                }
            }
        }
    });

    Ok((actual_port, cancel, handle))
}

// ── Multicast group management ───────────────────────────────────────────

fn join_multicast_on_interface(
    udp: &UdpSocket,
    interface_index: u32,
    _addr: &Ipv6Addr,
) -> std::io::Result<()> {
    // Use the raw socket fd to join the multicast group on a specific interface.
    // tokio::net::UdpSocket doesn't expose join_multicast_v6 directly,
    // so we use socket2 via the raw fd.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = udp.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        let result = socket.join_multicast_v6(&MULTICAST_GROUP, interface_index);
        // Don't close the fd - it's owned by the UdpSocket
        std::mem::forget(socket);
        result
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = udp.as_raw_socket();
        let socket = unsafe { Socket::from_raw_socket(raw) };
        let result = socket.join_multicast_v6(&MULTICAST_GROUP, interface_index);
        // Don't close the socket - it's owned by the UdpSocket
        std::mem::forget(socket);
        result
    }
}

#[cfg(unix)]
use std::os::unix::io::FromRawFd;
#[cfg(windows)]
use std::os::windows::io::FromRawSocket;
