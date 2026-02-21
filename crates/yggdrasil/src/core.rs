use std::collections::HashSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ironwood::{Addr, Config as IwConfig, EncryptedPacketConn, PacketConn};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::address::{addr_for_key, subnet_for_key, Address, Subnet};
use crate::config::Config;
use crate::ipv6rwc::ReadWriteCloser;
use crate::links::{ActiveLinks, Links, LinkPeerInfo};
use crate::proto::ProtoHandler;
use crate::tls_support;

/// Session type byte prefixed to ironwood payloads.
const TYPE_SESSION_TRAFFIC: u8 = 0x01;
const TYPE_SESSION_PROTO: u8 = 0x02;

/// Shared slot for path_notify callback target.
/// Filled in after Core and RWC are both created.
pub type PathNotifySlot = Arc<std::sync::Mutex<Option<Arc<ReadWriteCloser>>>>;

/// Core wraps an ironwood EncryptedPacketConn with session type handling
/// and TCP link management.
pub struct Core {
    pub(crate) inner: Arc<EncryptedPacketConn>,
    pub(crate) links: Mutex<Links>,
    pub(crate) active_links: ActiveLinks,
    pub(crate) signing_key: SigningKey,
    pub(crate) public_key: [u8; 32],
    pub(crate) address: Address,
    pub(crate) subnet: Subnet,
    pub(crate) allowed_keys: HashSet<[u8; 32]>,
    pub(crate) config: Config,
    pub(crate) path_notify_slot: PathNotifySlot,
    pub(crate) proto_handler: Arc<ProtoHandler>,
    pub(crate) tls_server_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
    pub(crate) tls_client_config: Arc<RwLock<Arc<rustls::ClientConfig>>>,
    pub(crate) tls_cert_expiry: Arc<RwLock<time::OffsetDateTime>>,
    proto_tx: mpsc::Sender<(Addr, Vec<u8>)>,
}

impl Core {
    /// Create a new Core from a signing key and configuration.
    /// Returns the Core and a PathNotifySlot that should be filled with
    /// the ReadWriteCloser after creation (call `set_path_notify`).
    pub fn new(signing_key: SigningKey, config: Config) -> Arc<Self> {
        let public_key = signing_key.verifying_key().to_bytes();
        let address = addr_for_key(&public_key);
        let subnet = subnet_for_key(&public_key);

        let allowed_keys: HashSet<[u8; 32]> = config.allowed_keys().into_iter().collect();

        // Create a shared slot for the path_notify target
        let path_notify_slot: PathNotifySlot = Arc::new(std::sync::Mutex::new(None));
        let slot_clone = path_notify_slot.clone();

        // Create ironwood config with bloom transform and path notify
        let iw_config = IwConfig::default()
            .with_bloom_transform(|key: [u8; 32]| -> [u8; 32] {
                let subnet = subnet_for_key(&key);
                subnet.get_key()
            })
            .with_peer_max_message_size(65535 * 2)
            .with_path_notify(move |key: [u8; 32]| {
                let rwc = {
                    let guard = slot_clone.lock().unwrap();
                    guard.clone()
                };
                if let Some(rwc) = rwc {
                    tokio::spawn(async move {
                        rwc.update_key(key).await;
                    });
                }
            });

        let inner = ironwood::new_encrypted_packet_conn(signing_key.clone(), iw_config);

        let active_links = ActiveLinks::new();

        // Generate self-signed TLS certificate
        let (tls_certs, tls_key, cert_expiry) = tls_support::generate_self_signed_cert(&signing_key)
            .expect("failed to generate TLS certificate");
        let tls_server_config = tls_support::create_server_config(tls_certs, tls_key)
            .expect("failed to create TLS server config");
        let tls_client_config = tls_support::create_client_config()
            .expect("failed to create TLS client config");

        let tls_server_config = Arc::new(RwLock::new(tls_server_config));
        let tls_client_config = Arc::new(RwLock::new(tls_client_config));
        let tls_cert_expiry = Arc::new(RwLock::new(cert_expiry));

        // Create protocol message channel
        let (proto_tx, mut proto_rx) = mpsc::channel::<(Addr, Vec<u8>)>(64);
        let proto_handler = ProtoHandler::new(proto_tx.clone());

        // Spawn proto sender task
        let inner_clone = inner.clone();
        tokio::spawn(async move {
            while let Some((addr, msg)) = proto_rx.recv().await {
                // Prepend TYPE_SESSION_PROTO byte
                let mut full_msg = Vec::with_capacity(1 + msg.len());
                full_msg.push(TYPE_SESSION_PROTO);
                full_msg.extend_from_slice(&msg);
                let _ = inner_clone.write_to(&full_msg, &addr).await;
            }
        });

        let core = Arc::new(Self {
            inner,
            links: Mutex::new(Links::new(active_links.clone())),
            active_links,
            signing_key: signing_key.clone(),
            public_key,
            address,
            subnet,
            allowed_keys,
            config,
            path_notify_slot,
            proto_handler,
            tls_server_config,
            tls_client_config,
            tls_cert_expiry,
            proto_tx,
        });

        // Spawn TLS certificate renewal task
        let core_clone = core.clone();
        tokio::spawn(async move {
            core_clone.tls_renewal_task().await;
        });

        core
    }

    /// Wire up the path_notify callback to deliver to the given ReadWriteCloser.
    /// Must be called after both Core and RWC are created.
    pub fn set_path_notify(&self, rwc: Arc<ReadWriteCloser>) {
        let mut slot = self.path_notify_slot.lock().unwrap();
        *slot = Some(rwc);
    }

    /// Read a traffic packet from ironwood, stripping the session type byte.
    pub async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr), ironwood::Error> {
        loop {
            let mut inner_buf = vec![0u8; buf.len() + 1];
            let (n, addr) = self.inner.read_from(&mut inner_buf).await?;
            tracing::debug!("Core read: {n} bytes with {} from {}", inner_buf[0], &addr);
            if n == 0 {
                continue;
            }
            match inner_buf[0] {
                TYPE_SESSION_TRAFFIC => {
                    let payload_len = n - 1;
                    buf[..payload_len].copy_from_slice(&inner_buf[1..n]);
                    return Ok((payload_len, addr));
                }
                TYPE_SESSION_PROTO => {
                    // Handle protocol message
                    let from_key = addr.0;
                    let payload = &inner_buf[1..n];

                    // Get data needed for proto handlers
                    let routing_entries = self.routing_entries().await;
                    let our_key = self.public_key;
                    let peer_keys = self.get_peer_keys().await;
                    let tree_keys = self.get_tree_keys().await;
                    let nodeinfo_json = self.config.node_info_json();

                    if let Some((target, response)) = self.proto_handler.handle_proto_message(
                        from_key,
                        payload,
                        &our_key,
                        routing_entries,
                        || peer_keys.clone(),
                        || tree_keys.clone(),
                        &nodeinfo_json,
                    ).await {
                        // Send response back through proto channel
                        let _ = self.proto_tx.send((target, response)).await;
                    }

                    // Continue reading, don't return proto messages to caller
                    continue;
                }
                _ => {
                    continue;
                }
            }
        }
    }

    /// Write a traffic packet to ironwood, prepending the session type byte.
    pub async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize, ironwood::Error> {
        let mut payload = Vec::with_capacity(1 + buf.len());
        payload.push(TYPE_SESSION_TRAFFIC);
        payload.extend_from_slice(buf);
        let n = self.inner.write_to(&payload, addr).await?;
        if n > 0 {
            Ok(n - 1)
        } else {
            Ok(0)
        }
    }

    /// Send a key lookup via ironwood.
    pub async fn send_lookup(&self, target: Addr) {
        self.inner.send_lookup(target).await;
    }

    /// Get the MTU (ironwood MTU minus session type overhead, capped at 65535).
    pub fn mtu(&self) -> u64 {
        let m = self.inner.mtu().saturating_sub(1);
        m.min(65535)
    }

    /// Get the local public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Get the local Yggdrasil IPv6 address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the local Yggdrasil /64 subnet.
    pub fn subnet(&self) -> &Subnet {
        &self.subnet
    }

    /// Get the underlying encrypted packet connection.
    ///
    /// This allows integration with higher-level protocols like stream multiplexing
    /// (e.g., ygg_stream) that need direct access to the ironwood PacketConn.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use yggdrasil::core::Core;
    /// use ygg_stream::StreamManager;
    ///
    /// # async fn example(core: std::sync::Arc<Core>) {
    /// let stream_manager = StreamManager::new(core.packet_conn());
    /// # }
    /// ```
    pub fn packet_conn(&self) -> Arc<EncryptedPacketConn> {
        self.inner.clone()
    }

    /// Check if a public key is allowed to connect.
    pub fn is_key_allowed(&self, key: &[u8; 32]) -> bool {
        if self.allowed_keys.is_empty() {
            return true;
        }
        self.allowed_keys.contains(key)
    }

    /// Handle a new peer connection (delegate to ironwood).
    pub async fn handle_conn(
        &self,
        key: [u8; 32],
        conn: Box<dyn ironwood::types::AsyncConn>,
        priority: u8,
    ) -> Result<(), ironwood::Error> {
        self.inner.handle_conn(Addr(key), conn, priority).await
    }

    /// Initialize the links with a reference to this core.
    pub async fn init_links(self: &Arc<Self>) {
        let mut links = self.links.lock().await;
        links.set_core(self.clone());
    }

    /// Close the core and all links.
    pub async fn close(&self) -> Result<(), ironwood::Error> {
        {
            let mut links = self.links.lock().await;
            links.close().await;
        }
        self.inner.close().await
    }

    /// Start listeners and connect to configured peers.
    pub async fn start(self: &Arc<Self>) {
        let config = self.config.clone();

        for addr in &config.listen {
            if let Err(e) = self.listen(addr).await {
                tracing::error!("Failed to listen on {}: {}", addr, e);
            }
        }

        for uri in &config.peers {
            if let Err(e) = self.add_peer(uri).await {
                tracing::error!("Failed to add peer {}: {}", uri, e);
            }
        }
    }

    /// Start listening on the given address.
    pub async fn listen(&self, addr: &str) -> Result<(), String> {
        let mut links = self.links.lock().await;
        links.listen(addr).await
    }

    /// Add a persistent peer.
    pub async fn add_peer(&self, uri: &str) -> Result<(), String> {
        let mut links = self.links.lock().await;
        links.add_peer(uri).await
    }

    /// Remove a peer by URI.
    pub async fn remove_peer(&self, uri: &str) -> Result<(), String> {
        let mut links = self.links.lock().await;
        links.remove_peer(uri).await
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub async fn retry_peers_now(&self) {
        self.links.lock().await.retry_peers_now();
    }

    /// Get link-level peer info merged with ironwood RTT/cost (for admin getPeers).
    pub async fn get_peers(&self) -> Vec<LinkPeerInfo> {
        let mut peers = self.active_links.get_peers().await;
        // Merge latency/cost from ironwood router
        let iw_peers = self.inner.get_peers().await;
        for p in &mut peers {
            if let Some(iw) = iw_peers.iter().find(|ip| ip.key == p.key) {
                p.latency_ms = iw.latency_ms;
                p.cost = iw.cost;
            }
        }
        peers
    }

    /// Get spanning tree entries (from ironwood).
    pub async fn get_tree(&self) -> Vec<ironwood::TreeEntry> {
        self.inner.get_tree().await
    }

    /// Get the number of routing entries.
    pub async fn routing_entries(&self) -> usize {
        self.inner.routing_entries().await
    }

    /// Get our current tree coordinates (path from root).
    pub async fn tree_coordinates(&self) -> Vec<u64> {
        self.inner.tree_coordinates().await
    }

    /// Get all cached paths.
    pub async fn get_paths(&self) -> Vec<ironwood::PathEntry> {
        self.inner.get_paths().await
    }

    /// Get all active encrypted sessions.
    pub async fn get_sessions(&self) -> Vec<ironwood::SessionEntry> {
        self.inner.get_sessions().await
    }

    /// Get a diagnostic snapshot of internal routing state.
    pub async fn get_debug_snapshot(&self) -> ironwood::DebugSnapshot {
        self.inner.get_debug_snapshot().await
    }

    /// Count how many on-tree peers' bloom filters cover the given destination key.
    /// Returns (xformed_key_hex, multicast_count).
    pub async fn count_lookup_targets(&self, dest: [u8; 32]) -> ([u8; 32], usize) {
        self.inner.count_lookup_targets(dest).await
    }

    /// Force a path lookup for the given destination, bypassing the rumor throttle.
    /// Returns the number of peers the lookup was sent to.
    pub async fn force_lookup(&self, dest: [u8; 32]) -> usize {
        self.inner.force_lookup(dest).await
    }

    /// Get TUN adapter status.
    pub fn get_tun_status(&self) -> (bool, String, u64) {
        // TUN is always enabled in current implementation
        // Return (enabled, name, mtu)
        (true, "utun".to_string(), self.mtu())
    }

    /// Get protocol handler (for admin debug commands).
    pub fn proto_handler(&self) -> &Arc<ProtoHandler> {
        &self.proto_handler
    }

    /// Get peer keys for protocol responses (returns routing peer keys).
    pub async fn get_peer_keys(&self) -> Vec<[u8; 32]> {
        self.inner.get_routing_peer_keys().await
    }

    /// Get tree keys for protocol responses.
    pub async fn get_tree_keys(&self) -> Vec<[u8; 32]> {
        let tree = self.get_tree().await;
        tree.iter().map(|t| t.key).collect()
    }

    /// Background task to renew TLS certificate before expiry.
    /// Checks every 12 hours and renews if certificate expires within 10 days.
    async fn tls_renewal_task(self: Arc<Self>) {
        loop {
            // Check every 12 hours
            tokio::time::sleep(std::time::Duration::from_secs(12 * 60 * 60)).await;

            let expiry = *self.tls_cert_expiry.read().await;
            let now = time::OffsetDateTime::now_utc();
            let days_until_expiry = (expiry - now).whole_days();

            if days_until_expiry <= 10 {
                tracing::info!("TLS certificate expires in {} days, renewing...", days_until_expiry);

                // Generate new certificate
                match tls_support::generate_self_signed_cert(&self.signing_key) {
                    Ok((certs, key, new_expiry)) => {
                        match (
                            tls_support::create_server_config(certs, key),
                            tls_support::create_client_config(),
                        ) {
                            (Ok(server_config), Ok(client_config)) => {
                                // Update configs
                                *self.tls_server_config.write().await = server_config;
                                *self.tls_client_config.write().await = client_config;
                                *self.tls_cert_expiry.write().await = new_expiry;

                                tracing::info!("TLS certificate renewed successfully");
                            }
                            (Err(e), _) | (_, Err(e)) => {
                                tracing::error!("Failed to create TLS config during renewal: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to generate new TLS certificate: {}", e);
                    }
                }
            }
        }
    }
}
