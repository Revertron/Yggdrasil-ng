use std::collections::HashSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ironwood::{Addr, Config as IwConfig, EncryptedPacketConn, PacketConn};
use tokio::sync::Mutex;

use crate::address::{addr_for_key, subnet_for_key, Address, Subnet};
use crate::config::Config;
use crate::ipv6rwc::ReadWriteCloser;
use crate::links::{ActiveLinks, Links, LinkPeerInfo};

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

        let core = Arc::new(Self {
            inner,
            links: Mutex::new(Links::new(active_links.clone())),
            active_links,
            signing_key,
            public_key,
            address,
            subnet,
            allowed_keys,
            config,
            path_notify_slot,
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
                    // TODO implement real handling
                    let key = addr; // The Addr contains the public key
                    let payload_len = n - 1;
                    buf[..payload_len].copy_from_slice(&inner_buf[1..n]);
                    return Ok((payload_len, addr));

                    //continue;
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

    /// Get link-level peer info (for admin getPeers).
    pub async fn get_peers(&self) -> Vec<LinkPeerInfo> {
        self.active_links.get_peers().await
    }

    /// Get spanning tree entries (from ironwood).
    pub async fn get_tree(&self) -> Vec<ironwood::TreeEntry> {
        self.inner.get_tree().await
    }

    /// Get the number of routing entries.
    pub async fn routing_entries(&self) -> usize {
        self.inner.routing_entries().await
    }
}
