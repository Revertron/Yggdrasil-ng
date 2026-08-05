//! Encrypted PacketConn wrapper.
//!
//! Wraps a network-level `PacketConnImpl` with end-to-end XSalsa20-Poly1305 encryption
//! (via RustCrypto's `crypto_box` crate), session management, and key ratcheting for forward secrecy.

pub(crate) mod crypto;
pub(crate) mod session;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::core::PacketConnImpl;
use crate::crypto::PublicKey;
use crate::types::{Addr, Error, Result};

use self::crypto::{ed25519_private_to_curve25519, CurvePrivateKey, GroupAuth};
use self::session::{ConcurrentSessionManager, OutAction, SESSION_TRAFFIC_OVERHEAD};

/// Channel capacity for delivering decrypted traffic to readers.
/// Must be large enough to absorb bursts without blocking the decrypt loop,
/// otherwise backpressure propagates to ironwood's delivery queue which drops
/// packets older than 25 ms.
const RECV_CHANNEL_SIZE: usize = 512;

/// LRU of recently used non-direct destination keys for remote keepalive.
/// Most-recently-used entries sit at the back. Capacity 0 disables tracking.
struct RemoteKeepaliveLru {
    capacity: usize,
    order: VecDeque<PublicKey>,
}

impl RemoteKeepaliveLru {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
        }
    }

    /// Record an outbound application write to `key` (MRU at back).
    fn touch(&mut self, key: PublicKey) {
        if self.capacity == 0 {
            return;
        }
        if let Some(pos) = self.order.iter().position(|k| *k == key) {
            self.order.remove(pos);
        }
        self.order.push_back(key);
        while self.order.len() > self.capacity {
            self.order.pop_front();
        }
    }

    /// Snapshot of keys currently in the LRU (oldest first).
    fn keys(&self) -> Vec<PublicKey> {
        self.order.iter().copied().collect()
    }
}

/// Decrypted incoming message.
struct DecryptedMessage {
    source: crate::crypto::PublicKey,
    data: Vec<u8>,
}

/// Public session entry returned by `get_sessions()`.
#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub key: [u8; 32],
    pub uptime_seconds: f64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
}

/// Encrypted PacketConn: wraps a network `PacketConnImpl` with encryption.
pub struct EncryptedPacketConn {
    /// The underlying network-level PacketConn.
    inner: Arc<PacketConnImpl>,
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Session manager with per-session locking (shared with reader task).
    sessions: Arc<ConcurrentSessionManager>,
    /// Channel for delivering decrypted traffic to read_from.
    recv_rx: Mutex<mpsc::Receiver<DecryptedMessage>>,
    recv_tx: mpsc::Sender<DecryptedMessage>,
    /// Whether this conn is closed.
    closed: AtomicBool,
    /// Cancellation for background tasks.
    cancel: CancellationToken,
    /// Reader task handle (wrapped in Mutex so we can await it in close()).
    reader_handle: Mutex<Option<JoinHandle<()>>>,
    /// Session cleanup task handle (wrapped in Mutex so we can await it in close()).
    cleanup_handle: Mutex<Option<JoinHandle<()>>>,
    /// Optional keepalive task handle (direct and/or remote LRU).
    keepalive_handle: Mutex<Option<JoinHandle<()>>>,
    /// LRU of recently used non-direct destinations (shared with keepalive loop).
    remote_lru: Arc<Mutex<RemoteKeepaliveLru>>,
}

impl EncryptedPacketConn {
    /// Create a new EncryptedPacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let curve_priv = ed25519_private_to_curve25519(&secret);
        // Build the group-password gate before `config` is moved into the inner
        // PacketConn. Empty/absent password yields a disabled GroupAuth.
        let group_auth = GroupAuth::new(config.group_password.as_deref().unwrap_or(&[]));
        let session_timeout = config.session_timeout;
        let keepalive_direct = config.keepalive_direct;
        let keepalive_interval = config.keepalive_interval;
        let keepalive_remote_count = config.keepalive_remote_count;
        let inner = Arc::new(PacketConnImpl::new(secret.clone(), config));
        let sessions = Arc::new(ConcurrentSessionManager::new(group_auth, session_timeout));
        let remote_lru = Arc::new(Mutex::new(RemoteKeepaliveLru::new(keepalive_remote_count)));
        let (recv_tx, recv_rx) = mpsc::channel(RECV_CHANNEL_SIZE);
        let cancel = CancellationToken::new();

        // Spawn reader task: reads from inner, decrypts, delivers
        let reader_handle = {
            let inner = inner.clone();
            let sessions = sessions.clone();
            let recv_tx = recv_tx.clone();
            let cancel = cancel.clone();
            let signing_key = secret.clone();
            let curve_priv = curve_priv;
            tokio::spawn(encrypted_reader_loop(
                inner,
                sessions,
                recv_tx,
                cancel,
                signing_key,
                curve_priv,
            ))
        };

        // Spawn session cleanup task: removes expired sessions every 30s
        let cleanup_handle = {
            let sessions = sessions.clone();
            let cancel = cancel.clone();
            tokio::spawn(session_cleanup_loop(sessions, cancel))
        };

        // Optional proactive keepalive: direct peers and/or remote LRU destinations.
        // Independent: either feature can run without the other.
        let keepalive_handle = if keepalive_direct || keepalive_remote_count > 0 {
            let inner = inner.clone();
            let sessions = sessions.clone();
            let cancel = cancel.clone();
            let signing_key = secret.clone();
            let remote_lru = remote_lru.clone();
            Some(tokio::spawn(keepalive_loop(
                inner,
                sessions,
                signing_key,
                keepalive_interval,
                keepalive_direct,
                remote_lru,
                cancel,
            )))
        } else {
            None
        };

        Self {
            inner,
            signing_key: secret,
            sessions,
            recv_rx: Mutex::new(recv_rx),
            recv_tx,
            closed: AtomicBool::new(false),
            cancel,
            reader_handle: Mutex::new(Some(reader_handle)),
            cleanup_handle: Mutex::new(Some(cleanup_handle)),
            keepalive_handle: Mutex::new(keepalive_handle),
            remote_lru,
        }
    }

    /// Get info about all connected peers (delegates to inner).
    pub async fn get_peers(&self) -> Vec<crate::core::PeerInfo> {
        self.inner.get_peers().await
    }

    /// Get spanning tree entries (delegates to inner).
    pub async fn get_tree(&self) -> Vec<crate::core::TreeEntry> {
        self.inner.get_tree().await
    }

    /// Get the number of routing entries.
    pub async fn routing_entries(&self) -> usize {
        self.inner.routing_entries().await
    }

    /// Get our current tree coordinates (path from root).
    pub async fn tree_coordinates(&self) -> Vec<crate::wire::PeerPort> {
        self.inner.tree_coordinates().await
    }

    /// Get all cached paths (delegates to inner).
    pub async fn get_paths(&self) -> Vec<crate::core::PathEntry> {
        self.inner.get_paths().await
    }

    /// Get all active encrypted sessions.
    pub async fn get_sessions(&self) -> Vec<SessionEntry> {
        use std::time::Instant;
        let now = Instant::now();
        let snapshot = self.sessions.get_all_sessions();
        let mut result = Vec::with_capacity(snapshot.len());
        for (key, tx, rx, since) in snapshot {
            result.push(SessionEntry {
                key,
                uptime_seconds: now.duration_since(since).as_secs_f64(),
                bytes_sent: tx,
                bytes_recvd: rx,
            });
        }
        result.sort_by(|a, b| a.key.cmp(&b.key));
        result
    }

    /// Get routing peer keys (direct neighbors in spanning tree).
    pub async fn get_routing_peer_keys(&self) -> Vec<crate::crypto::PublicKey> {
        self.inner.get_routing_peer_keys().await
    }

    /// Get a diagnostic snapshot of internal routing state.
    pub async fn get_debug_snapshot(&self) -> crate::core::DebugSnapshot {
        self.inner.get_debug_snapshot().await
    }

    /// Count how many on-tree peers' bloom filters cover the given destination key.
    /// Returns (xformed_key, multicast_count).
    pub async fn count_lookup_targets(&self, dest: crate::crypto::PublicKey) -> (crate::crypto::PublicKey, usize) {
        self.inner.count_lookup_targets(dest).await
    }

    /// Force a path lookup for the given destination, bypassing the rumor throttle.
    /// Returns the number of peers the lookup was multicast to.
    pub async fn force_lookup(&self, dest: crate::crypto::PublicKey) -> usize {
        self.inner.force_lookup(dest).await
    }

    /// Force an immediate router refresh / re-announce (delegates to inner).
    pub fn force_refresh(&self) {
        self.inner.force_refresh();
    }
}

/// Background reader loop: reads from inner PacketConn, decrypts via sessions, delivers.
/// Background task that periodically cleans up expired sessions and buffers.
/// Runs every 30 seconds to remove sessions/buffers older than SESSION_TIMEOUT (60s).
async fn session_cleanup_loop(sessions: Arc<ConcurrentSessionManager>, cancel: CancellationToken) {
    use std::time::Duration;

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await; // Skip first immediate tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                sessions.cleanup_expired();
            }
        }
    }
}

/// Send empty encrypted traffic to `key` if a session already exists.
/// Does not start Init/handshake for cold destinations.
async fn keepalive_send_if_session(
    inner: &PacketConnImpl,
    sessions: &ConcurrentSessionManager,
    signing_key: &SigningKey,
    key: &PublicKey,
) {
    use crate::types::PacketConn;

    if !sessions.has_session(key) {
        return;
    }
    let actions = sessions.write_to(key, &[], signing_key);
    for action in actions {
        match action {
            OutAction::SendToInner { dest, data } => {
                let _ = inner.write_to(&data, &Addr(dest)).await;
            }
            OutAction::Deliver { .. } => {}
        }
    }
}

/// Background task that periodically sends empty encrypted traffic to:
/// - currently connected direct peers (when `keepalive_direct` is true);
/// - keys in the remote LRU (when capacity > 0), excluding current direct peers.
///
/// Only refreshes sessions that already exist (`has_session`). Path
/// `last_refresh` on the sender is only updated when traffic is received back.
async fn keepalive_loop(
    inner: Arc<PacketConnImpl>,
    sessions: Arc<ConcurrentSessionManager>,
    signing_key: SigningKey,
    interval: std::time::Duration,
    keepalive_direct: bool,
    remote_lru: Arc<Mutex<RemoteKeepaliveLru>>,
    cancel: CancellationToken,
) {
    use std::collections::HashSet;

    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // Skip first immediate tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                let peers = inner.get_peers().await;
                let mut direct_keys = HashSet::new();
                for peer in &peers {
                    direct_keys.insert(peer.key);
                }

                if keepalive_direct {
                    for key in &direct_keys {
                        keepalive_send_if_session(
                            &inner, &sessions, &signing_key, key,
                        ).await;
                    }
                }

                let remote_keys = {
                    let lru = remote_lru.lock().await;
                    lru.keys()
                };
                for key in remote_keys {
                    if direct_keys.contains(&key) {
                        continue;
                    }
                    keepalive_send_if_session(
                        &inner, &sessions, &signing_key, &key,
                    ).await;
                }
            }
        }
    }
}

async fn encrypted_reader_loop(
    inner: Arc<PacketConnImpl>,
    sessions: Arc<ConcurrentSessionManager>,
    recv_tx: mpsc::Sender<DecryptedMessage>,
    cancel: CancellationToken,
    signing_key: SigningKey,
    curve_priv: CurvePrivateKey,
) {
    use crate::types::PacketConn;

    let mut buf = vec![0u8; 128 * 1024]; // 128 KB buffer

    loop {
        tracing::debug!("encrypted_reader_loop");
        let read_result = tokio::select! {
            _ = cancel.cancelled() => break,
            result = inner.read_from(&mut buf) => result,
        };

        let (n, from_addr) = match read_result {
            Ok((n, addr)) => (n, addr),
            Err(_) => break,
        };

        let from_key = from_addr.0;

        // Decrypt via session manager (per-session locking, no global mutex)
        let actions = sessions.handle_data(&from_key, &buf[..n], &curve_priv, &signing_key);

        // Process actions (all locks already released)
        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    tracing::debug!("encrypted_reader: sending {} bytes to inner (session msg)", data.len());
                    let _ = inner.write_to(&data, &Addr(dest)).await;
                }
                OutAction::Deliver { source, data } => {
                    tracing::debug!("encrypted_reader: delivering {} bytes from {:?}", data.len(), hex::encode(&source[..4]));
                    let msg = DecryptedMessage { source, data };
                    if recv_tx.send(msg).await.is_err() {
                        return; // channel closed
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::types::PacketConn for EncryptedPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let mut rx = self.recv_rx.lock().await;
        let cancel = self.cancel.clone();

        let msg = tokio::select! {
            _ = cancel.cancelled() => return Err(Error::Closed),
            msg = rx.recv() => match msg {
                Some(m) => m,
                None => return Err(Error::Closed),
            },
        };

        let n = buf.len().min(msg.data.len());
        buf[..n].copy_from_slice(&msg.data[..n]);
        Ok((n, Addr(msg.source)))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let mtu = self.mtu();
        if buf.len() as u64 > mtu {
            return Err(Error::OversizedMessage);
        }

        let dest = addr.0;

        // Track outbound application traffic for remote keepalive LRU.
        // Empty payloads are keepalive probes and must not refresh the LRU.
        // Keepalive itself calls sessions.write_to directly, not this method.
        if !buf.is_empty() {
            let our_key = self.signing_key.verifying_key().to_bytes();
            if dest != our_key {
                let mut lru = self.remote_lru.lock().await;
                lru.touch(dest);
            }
        }

        let actions = self.sessions.write_to(&dest, buf, &self.signing_key);

        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    self.inner.write_to(&data, &Addr(dest)).await?;
                }
                OutAction::Deliver { source, data } => {
                    let msg = DecryptedMessage { source, data };
                    let _ = self.recv_tx.send(msg).await;
                }
            }
        }

        Ok(buf.len())
    }

    async fn handle_conn(&self, key: Addr, conn: Box<dyn crate::types::AsyncConn>, prio: u8) -> Result<()> {
        self.inner.handle_conn(key, conn, prio).await
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        self.inner.mtu().saturating_sub(SESSION_TRAFFIC_OVERHEAD)
    }

    async fn send_lookup(&self, target: Addr) {
        self.inner.send_lookup(target).await;
    }

    async fn close(&self) -> Result<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Closed);
        }

        // Cancel background tasks
        self.cancel.cancel();

        // Wait for background tasks to finish gracefully
        if let Some(handle) = self.reader_handle.lock().await.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.keepalive_handle.lock().await.take() {
            let _ = handle.await;
        }

        // Close the inner connection
        self.inner.close().await
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }
}

/// Create a new EncryptedPacketConn.
pub fn new_encrypted_packet_conn(secret: SigningKey, config: Config) -> Arc<EncryptedPacketConn> {
    Arc::new(EncryptedPacketConn::new(secret, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn encrypted_create_and_close() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_encrypted_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn encrypted_create_and_close_with_keepalive_direct() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default()
            .with_keepalive_direct(true)
            .with_keepalive_interval(std::time::Duration::from_secs(15));
        let conn = new_encrypted_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn encrypted_create_and_close_with_keepalive_remote_only() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default()
            .with_keepalive_remote_count(8)
            .with_keepalive_interval(std::time::Duration::from_secs(15));
        let conn = new_encrypted_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[test]
    fn remote_lru_evicts_oldest_and_promotes_on_touch() {
        let mut lru = RemoteKeepaliveLru::new(2);
        lru.touch([1u8; 32]);
        lru.touch([2u8; 32]);
        lru.touch([3u8; 32]); // evicts [1]
        let keys = lru.keys();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], [2u8; 32]);
        assert_eq!(keys[1], [3u8; 32]);

        lru.touch([2u8; 32]); // promote [2] to MRU
        let keys = lru.keys();
        assert_eq!(keys[0], [3u8; 32]);
        assert_eq!(keys[1], [2u8; 32]);
    }

    #[test]
    fn remote_lru_capacity_zero_is_noop() {
        let mut lru = RemoteKeepaliveLru::new(0);
        lru.touch([1u8; 32]);
        assert!(lru.keys().is_empty());
    }
    
    #[tokio::test]
    async fn encrypted_mtu_accounts_for_overhead() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = new_encrypted_packet_conn(key.clone(), Config::default());

        use crate::types::PacketConn;
        let inner_conn = crate::core::new_packet_conn(key, Config::default());
        let inner_mtu = inner_conn.mtu();
        let encrypted_mtu = conn.mtu();

        assert!(encrypted_mtu < inner_mtu);
        assert_eq!(encrypted_mtu, inner_mtu - SESSION_TRAFFIC_OVERHEAD);

        conn.close().await.unwrap();
        inner_conn.close().await.unwrap();
    }
}
