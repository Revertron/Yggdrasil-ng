//! Multicast discovery module — wire-compatible with yggdrasil-go.
//!
//! Discovers peers on the local network via IPv6 link-local multicast beacons.
//! When a beacon is received, the node connects to the sender via TLS as an
//! ephemeral peer (no automatic reconnection on disconnect).
//!
//! Protocol: UDP beacons on `[ff02::114]:9001` containing version, public key,
//! TLS listen port, and an optional BLAKE2b-512 keyed MAC for authentication.

pub mod advertisement;

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use nix::ifaddrs::getifaddrs;
use nix::libc;
use nix::net::if_::InterfaceFlags;
use regex::Regex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use crate::config::MulticastInterfaceConfig;
use crate::core::Core;
use crate::transport::interface_name_to_index;
use crate::version::{PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR};

use advertisement::{compute_beacon_hash, verify_beacon_hash, MulticastAdvertisement};

/// Default multicast group address (matches yggdrasil-go).
const MULTICAST_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0114);
const MULTICAST_PORT: u16 = 9001;

/// Maximum beacon send interval per interface (matches Go's 15 second cap).
const MAX_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(15);

/// Receive buffer size for beacons.
const RECV_BUF_SIZE: usize = 2048;

/// State for a discovered network interface.
struct InterfaceState {
    /// OS interface index (for multicast join/send).
    index: u32,
    /// Link-local IPv6 addresses on this interface.
    addrs: Vec<Ipv6Addr>,
    /// Send beacons on this interface.
    beacon: bool,
    /// Listen for beacons on this interface.
    listen: bool,
    /// Override TLS listen port (0 = auto).
    port: u16,
    /// Link priority for peers discovered on this interface.
    priority: u8,
    /// Password bytes for BLAKE2b keyed MAC.
    password: Vec<u8>,
    /// Precomputed hash = BLAKE2b-512(our_public_key, key=password).
    hash: Vec<u8>,
}

/// Per-interface listener tracking (TLS listener for incoming connections).
struct ListenerInfo {
    /// Last time we sent a beacon on this interface.
    last_announce: Instant,
    /// Current announce interval (grows from 0 to 15 seconds).
    interval: Duration,
    /// The port we're listening on for TLS connections.
    port: u16,
    /// The listen address string (for cleanup via Links).
    _listen_addr: String,
}

/// Per-interface state visible to the admin API.
#[derive(Clone, Debug)]
pub struct MulticastInterfaceState {
    pub name: String,
    pub address: String,
    pub beacon: bool,
    pub listen: bool,
    pub password: bool,
}

/// The multicast discovery engine.
pub struct Multicast {
    core: Arc<Core>,
    sock: Arc<UdpSocket>,
    interfaces: Arc<RwLock<HashMap<String, InterfaceState>>>,
    listeners: Arc<RwLock<HashMap<String, ListenerInfo>>>,
    config: Vec<MulticastInterfaceConfig>,
    compiled_regexes: Vec<(Regex, usize)>,
    cancel: CancellationToken,
}

impl Multicast {
    /// Create a new multicast module. Does NOT start the announce/listen loops yet.
    pub async fn new(
        core: Arc<Core>,
        config: Vec<MulticastInterfaceConfig>,
    ) -> Result<Arc<Self>, String> {
        // Check if any interfaces have beacon or listen enabled
        let any_enabled = config.iter().any(|c| c.beacon || c.listen);
        if !any_enabled {
            return Err("no multicast interfaces configured".to_string());
        }

        // Compile regexes upfront
        let mut compiled_regexes = Vec::new();
        for (i, c) in config.iter().enumerate() {
            let re = Regex::new(&c.regex)
                .map_err(|e| format!("invalid regex '{}': {}", c.regex, e))?;
            compiled_regexes.push((re, i));
        }

        // Create the UDP6 socket with address reuse
        let sock = create_multicast_socket()?;

        Ok(Arc::new(Self {
            core,
            sock: Arc::new(sock),
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            listeners: Arc::new(RwLock::new(HashMap::new())),
            config,
            compiled_regexes,
            cancel: CancellationToken::new(),
        }))
    }

    /// Start the announce and listen loops.
    pub async fn start(self: &Arc<Self>) {
        tracing::info!("Starting multicast discovery module");

        // Initial interface scan
        self.update_interfaces().await;

        // Spawn the announce loop
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.announce_loop().await;
        });

        // Spawn the listen loop
        let self_clone = self.clone();
        tokio::spawn(async move {
            self_clone.listen_loop().await;
        });
    }

    /// Stop the multicast module.
    pub async fn stop(&self) {
        tracing::info!("Stopping multicast discovery module");
        self.cancel.cancel();
    }

    /// Get current multicast interface states (for admin API).
    pub async fn get_interfaces(&self) -> Vec<MulticastInterfaceState> {
        let interfaces = self.interfaces.read().await;
        let listeners = self.listeners.read().await;
        let mut result = Vec::new();

        for (name, info) in interfaces.iter() {
            let address = if let Some(linfo) = listeners.get(name) {
                if let Some(addr) = info.addrs.first() {
                    format!("tls://[{}%{}]:{}", addr, name, linfo.port)
                } else {
                    "-".to_string()
                }
            } else {
                "-".to_string()
            };

            result.push(MulticastInterfaceState {
                name: name.clone(),
                address,
                beacon: info.beacon,
                listen: info.listen,
                password: !info.password.is_empty(),
            });
        }

        result
    }

    /// Scan system interfaces and update the active set.
    async fn update_interfaces(&self) {
        let mut new_interfaces = HashMap::new();
        let public_key = *self.core.public_key();

        // Get all system interfaces via getifaddrs
        let ifaddrs = match getifaddrs() {
            Ok(addrs) => addrs,
            Err(e) => {
                tracing::debug!("Failed to enumerate interfaces: {}", e);
                return;
            }
        };

        // Group addresses by interface name, collecting flags and link-local IPv6 addrs
        let mut iface_map: HashMap<String, (InterfaceFlags, u32, Vec<Ipv6Addr>)> = HashMap::new();

        for ifaddr in ifaddrs {
            let name = ifaddr.interface_name.clone();
            let flags = ifaddr.flags;

            let entry = iface_map
                .entry(name.clone())
                .or_insert_with(|| {
                    // Get the interface index
                    let idx = interface_name_to_index(&name).unwrap_or(0);
                    (flags, idx, Vec::new())
                });

            // Update flags (they should be the same for all addresses of an interface)
            entry.0 = flags;

            // Check if this is a link-local IPv6 address
            if let Some(addr) = ifaddr.address {
                if let Some(sockaddr) = addr.as_sockaddr_in6() {
                    let ip = sockaddr.ip();
                    // Only include link-local unicast (fe80::/10)
                    if is_link_local_unicast(&ip) {
                        entry.2.push(ip);
                    }
                }
            }
        }

        // Filter interfaces by flags and regex
        for (name, (flags, index, addrs)) in &iface_map {
            // Skip interfaces that don't meet our criteria (match Go exactly)
            if !flags.contains(InterfaceFlags::IFF_UP) {
                continue;
            }
            if !flags.contains(InterfaceFlags::IFF_RUNNING) {
                continue;
            }
            if !flags.contains(InterfaceFlags::IFF_MULTICAST) {
                continue;
            }
            if flags.contains(InterfaceFlags::IFF_POINTOPOINT) {
                continue;
            }

            // Skip interfaces with no link-local IPv6 addresses
            if addrs.is_empty() {
                continue;
            }

            // Match against config regexes (first match wins, like Go)
            for (re, cfg_idx) in &self.compiled_regexes {
                let cfg = &self.config[*cfg_idx];

                if !cfg.beacon && !cfg.listen {
                    continue;
                }

                if !re.is_match(name) {
                    continue;
                }

                let password = cfg.password.as_bytes().to_vec();
                let hash = compute_beacon_hash(&public_key, &password);

                new_interfaces.insert(name.clone(), InterfaceState {
                    index: *index,
                    addrs: addrs.clone(),
                    beacon: cfg.beacon,
                    listen: cfg.listen,
                    port: cfg.port,
                    priority: cfg.priority,
                    password,
                    hash,
                });

                break; // First matching config wins
            }
        }

        // Join/leave multicast groups
        for (name, info) in &new_interfaces {
            if info.listen {
                if let Err(e) = join_multicast_group(&self.sock, info.index) {
                    tracing::debug!(
                        "Failed to join multicast group on {} (index {}): {}",
                        name, info.index, e
                    );
                }
            }
        }

        *self.interfaces.write().await = new_interfaces;
    }

    /// Periodic beacon announce loop.
    async fn announce_loop(&self) {
        loop {
            if self.cancel.is_cancelled() {
                return;
            }

            // Update interfaces each cycle
            self.update_interfaces().await;

            // Clean up listeners for interfaces that are no longer active
            self.cleanup_listeners().await;

            // Send beacons on each interface that has beacon=true
            self.send_beacons().await;

            // Random delay: 1s + rand(0..1048576)µs ≈ 1-2 seconds (matches Go)
            let jitter = rand::random::<u32>() % 1_048_576;
            let delay = Duration::from_secs(1) + Duration::from_micros(jitter as u64);

            tokio::select! {
                _ = self.cancel.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// Remove listeners for interfaces that are no longer in the active set.
    async fn cleanup_listeners(&self) {
        let interfaces = self.interfaces.read().await;
        let mut listeners = self.listeners.write().await;

        let stale: Vec<String> = listeners
            .keys()
            .filter(|name| !interfaces.contains_key(*name))
            .cloned()
            .collect();

        for name in stale {
            if let Some(_linfo) = listeners.remove(&name) {
                tracing::debug!("Stopped multicast listener on {}", name);
                // Note: The Links listener will keep running — it was started
                // via core.listen() and is managed by the Links module.
                // We just remove our tracking entry.
            }
        }
    }

    /// Send beacons on all interfaces with beacon=true.
    async fn send_beacons(&self) {
        let interfaces = self.interfaces.read().await;
        let mut listeners = self.listeners.write().await;
        let public_key = *self.core.public_key();

        for (name, info) in interfaces.iter() {
            if !info.beacon {
                continue;
            }

            // Ensure there's at least one link-local address on this interface
            if info.addrs.is_empty() {
                continue;
            }

            // Ensure we have a TLS listener for this interface
            if !listeners.contains_key(name) {
                // Create a TLS listener. We bind to [::]:port so we accept
                // connections on any interface. The beacon advertises the port,
                // and peers connect using the link-local source address from
                // the beacon's UDP packet. TLS handshake validates identity.
                let listen_addr = format!("tls://[::]:{}",info.port);

                match self.core.listen_local(&listen_addr).await {
                    Ok(bound_addr) => {
                        tracing::info!(
                            "Started multicast TLS listener on {} ({})",
                            name, bound_addr
                        );
                        listeners.insert(name.clone(), ListenerInfo {
                            last_announce: Instant::now(),
                            interval: Duration::ZERO, // Announce immediately first time
                            port: bound_addr.port(),
                            _listen_addr: listen_addr,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to start multicast listener on {}: {}", name, e);
                        continue;
                    }
                }
            }

            let linfo = match listeners.get_mut(name) {
                Some(l) => l,
                None => continue,
            };

            // Check if enough time has passed since last announcement
            if linfo.last_announce.elapsed() < linfo.interval {
                continue;
            }

            // Build and send the beacon
            let adv = MulticastAdvertisement {
                major_version: PROTOCOL_VERSION_MAJOR,
                minor_version: PROTOCOL_VERSION_MINOR,
                public_key,
                port: linfo.port,
                hash: info.hash.clone(),
            };

            let msg = adv.marshal();
            let dest = SocketAddrV6::new(MULTICAST_GROUP, MULTICAST_PORT, 0, info.index);

            match self.sock.send_to(&msg, SocketAddr::V6(dest)).await {
                Ok(sent) => {
                    tracing::debug!(
                        "Sent multicast beacon on {} ({} bytes, port {}, iface_idx={}, interval {:?})",
                        name, sent, linfo.port, info.index, linfo.interval
                    );
                }
                Err(e) => {
                    tracing::debug!("Failed to send multicast beacon on {}: {}", name, e);
                }
            }

            // Update interval: grows by 1s each time, caps at 15s
            if linfo.interval < MAX_ANNOUNCE_INTERVAL {
                linfo.interval += Duration::from_secs(1);
            }
            linfo.last_announce = Instant::now();
        }
    }

    /// Listen for incoming beacons and connect to discovered peers.
    async fn listen_loop(&self) {
        let mut buf = vec![0u8; RECV_BUF_SIZE];
        let our_key = *self.core.public_key();

        tracing::debug!("Multicast listen loop started, waiting for beacons on [::]:{}",
            MULTICAST_PORT);

        loop {
            let recv_result = tokio::select! {
                _ = self.cancel.cancelled() => return,
                result = self.sock.recv_from(&mut buf) => result,
            };

            let (n, from_addr) = match recv_result {
                Ok((n, addr)) => (n, addr),
                Err(e) => {
                    if self.cancel.is_cancelled() {
                        return;
                    }
                    tracing::debug!("Multicast recv error: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            tracing::debug!("Received {} bytes from {} on multicast socket", n, from_addr);

            // Parse the beacon
            let adv = match MulticastAdvertisement::unmarshal(&buf[..n]) {
                Ok(adv) => adv,
                Err(e) => {
                    tracing::debug!("Beacon parse failed from {}: {}", from_addr, e);
                    continue;
                }
            };

            // Version check
            if adv.major_version != PROTOCOL_VERSION_MAJOR {
                tracing::debug!("Beacon version mismatch: {}.{} (want {}.{})",
                    adv.major_version, adv.minor_version,
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
                continue;
            }
            if adv.minor_version != PROTOCOL_VERSION_MINOR {
                tracing::debug!("Beacon minor version mismatch: {}.{} (want {}.{})",
                    adv.major_version, adv.minor_version,
                    PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR);
                continue;
            }

            // Ignore our own beacons
            if adv.public_key == our_key {
                tracing::trace!("Ignoring our own beacon");
                continue;
            }

            // Determine the interface this came from (by scope_id for IPv6)
            let (from_ip, scope_id) = match from_addr {
                SocketAddr::V6(v6) => (*v6.ip(), v6.scope_id()),
                _ => continue, // Only IPv6 multicast
            };

            // Find the interface name for this scope_id
            let iface_name = match interface_index_to_name(scope_id) {
                Some(name) => name,
                None => {
                    tracing::debug!(
                        "Received beacon from {} but can't resolve scope_id {}",
                        from_ip, scope_id
                    );
                    continue;
                }
            };

            tracing::debug!(
                "Beacon from {} on {} (scope_id={}): key={}, port={}",
                from_ip, iface_name, scope_id,
                hex::encode(&adv.public_key[..8]),
                adv.port
            );

            // Check if we're listening on this interface
            let interfaces = self.interfaces.read().await;
            let info = match interfaces.get(&iface_name) {
                Some(info) if info.listen => info,
                _ => {
                    tracing::debug!("Not listening on interface {}, skipping", iface_name);
                    continue;
                }
            };

            // Verify beacon hash (password authentication)
            if !verify_beacon_hash(&adv.public_key, &adv.hash, &info.password) {
                tracing::debug!(
                    "Beacon from {} on {} failed hash verification",
                    hex::encode(&adv.public_key[..8]),
                    iface_name
                );
                continue;
            }

            let priority = info.priority;
            drop(interfaces);

            // Connect to the discovered peer via TLS.
            // Include the zone ID (%iface) so the URL parser can resolve
            // the correct scope_id for link-local address routing.
            let peer_addr = format!(
                "tls://[{}%{}]:{}?key={}&priority={}",
                from_ip,
                iface_name,
                adv.port,
                hex::encode(adv.public_key),
                priority,
            );

            // Skip if we already have an active connection to this peer's key.
            // Without this check every incoming beacon (every 1-15 s) would
            // spawn a new ephemeral connection, accumulating dozens of sessions
            // to the same peer over time.
            let already_connected = self
                .core
                .get_peers()
                .await
                .iter()
                .any(|p| p.up && p.key == adv.public_key);

            if already_connected {
                tracing::trace!(
                    "Already connected to multicast peer {}, skipping",
                    hex::encode(&adv.public_key[..8])
                );
                continue;
            }

            tracing::info!(
                "Discovered peer via multicast on {}: {}",
                iface_name,
                peer_addr
            );

            if let Err(e) = self.core.call_peer(&peer_addr, &iface_name).await {
                tracing::debug!("Multicast call to {} failed: {}", peer_addr, e);
            }
        }
    }
}

/// Create and configure the UDP6 multicast socket.
fn create_multicast_socket() -> Result<UdpSocket, String> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| format!("socket creation failed: {}", e))?;

    // Platform-specific socket options
    #[cfg(target_os = "linux")]
    {
        socket
            .set_reuse_address(true)
            .map_err(|e| format!("SO_REUSEADDR: {}", e))?;
    }

    #[cfg(target_os = "macos")]
    {
        socket
            .set_reuse_port(true)
            .map_err(|e| format!("SO_REUSEPORT: {}", e))?;

        // SO_RECV_ANYIF = 0x1104 — required on macOS to receive multicast
        // on interfaces not matching the default route
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                std::os::unix::io::AsRawFd::as_raw_fd(&socket),
                libc::SOL_SOCKET,
                0x1104, // SO_RECV_ANYIF
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                tracing::debug!("SO_RECV_ANYIF failed (non-fatal): {}", std::io::Error::last_os_error());
            }
        }
    }

    // IPV6_ONLY — don't receive IPv4 mapped addresses (must be set before bind)
    socket
        .set_only_v6(true)
        .map_err(|e| format!("IPV6_ONLY: {}", e))?;

    // Bind to [::]:9001
    let bind_addr: SocketAddrV6 = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MULTICAST_PORT, 0, 0);
    socket
        .bind(&socket2::SockAddr::from(SocketAddr::V6(bind_addr)))
        .map_err(|e| format!("bind [::]:9001 failed: {}", e))?;

    // Set non-blocking for tokio
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("set_nonblocking: {}", e))?;

    // Convert to tokio UdpSocket
    let std_sock: std::net::UdpSocket = socket.into();
    let tokio_sock = UdpSocket::from_std(std_sock)
        .map_err(|e| format!("tokio UdpSocket conversion: {}", e))?;

    Ok(tokio_sock)
}

/// Join the multicast group on a specific interface.
fn join_multicast_group(sock: &UdpSocket, iface_index: u32) -> Result<(), String> {
    sock.join_multicast_v6(&MULTICAST_GROUP, iface_index)
        .map_err(|e| format!("join_multicast_v6: {}", e))
}

/// Check if an IPv6 address is link-local unicast (fe80::/10).
fn is_link_local_unicast(addr: &Ipv6Addr) -> bool {
    let segments = addr.segments();
    (segments[0] & 0xffc0) == 0xfe80
}

/// Get the interface name for a given OS index.
fn interface_index_to_name(index: u32) -> Option<String> {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let result = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };
    if result.is_null() {
        None
    } else {
        let c_str = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
        c_str.to_str().ok().map(|s| s.to_string())
    }
}
