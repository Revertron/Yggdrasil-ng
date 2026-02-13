//! Core coordinator: wires Router + Peers together and provides the public
//! `PacketConn` implementation.
//!
//! - `PacketConnImpl` is the concrete implementation of `types::PacketConn`.
//! - Spawns a maintenance loop via `tokio::spawn`.
//! - `handle_conn()` spawns reader/writer tasks per peer.
//! - `read_from()` receives delivered traffic via an mpsc channel.
//! - `write_to()` encodes traffic and routes via the router.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::crypto::{Crypto, PublicKey};
use crate::peers::{
    dispatch_actions, peer_reader, peer_writer, PeerMessage, Peers,
};
use crate::router::Router;
use crate::traffic::{DeliveryQueue, TrafficPacket};
use crate::types::{Addr, AsyncConn, Error, Result};
use crate::wire;

/// Default channel capacity for inbound traffic delivery.
const RECV_CHANNEL_SIZE: usize = 64;

/// Default channel capacity for peer writer.
const PEER_WRITER_CHANNEL_SIZE: usize = 256;

/// The concrete PacketConn implementation.
pub struct PacketConnImpl {
    /// Signing key (identity).
    signing_key: SigningKey,
    /// Our public key.
    pub_key: PublicKey,
    /// Configuration.
    config: Config,
    /// The router (shared with peer tasks).
    router: Arc<Mutex<Router>>,
    /// The peer manager (shared with peer tasks).
    peers: Arc<Mutex<Peers>>,
    /// Delivery queue for receive buffering with backpressure.
    delivery_queue: Arc<DeliveryQueue>,
    /// Inbound traffic channel (reader side).
    traffic_rx: Mutex<mpsc::Receiver<TrafficPacket>>,
    /// Inbound traffic channel (writer side, given to peer readers).
    traffic_tx: mpsc::Sender<TrafficPacket>,
    /// Whether this PacketConn is closed.
    closed: AtomicBool,
    /// Cancellation token for background tasks.
    cancel: CancellationToken,
    /// Maintenance task handle.
    _maintenance_handle: JoinHandle<()>,
}

impl PacketConnImpl {
    /// Create a new PacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let crypto = Crypto::new(secret.clone());
        let pub_key = crypto.public_key;
        let router = Arc::new(Mutex::new(Router::new(crypto, &config)));
        let peers = Arc::new(Mutex::new(Peers::new()));
        let delivery_queue = DeliveryQueue::new();
        let (traffic_tx, traffic_rx) = mpsc::channel(RECV_CHANNEL_SIZE);
        let cancel = CancellationToken::new();

        // Spawn maintenance loop
        let maintenance_handle = {
            let router = router.clone();
            let peers = peers.clone();
            let delivery_queue = delivery_queue.clone();
            let traffic_tx = traffic_tx.clone();
            let cancel = cancel.clone();
            tokio::spawn(maintenance_loop(router, peers, delivery_queue, traffic_tx, cancel))
        };

        Self {
            signing_key: secret,
            pub_key,
            config,
            router,
            peers,
            delivery_queue,
            traffic_rx: Mutex::new(traffic_rx),
            traffic_tx,
            closed: AtomicBool::new(false),
            cancel,
            _maintenance_handle: maintenance_handle,
        }
    }
}

/// Background maintenance loop — runs every 1 second.
async fn maintenance_loop(
    router: Arc<Mutex<Router>>,
    peers: Arc<Mutex<Peers>>,
    delivery_queue: Arc<DeliveryQueue>,
    traffic_tx: mpsc::Sender<TrafficPacket>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {}
        }

        let actions = {
            let mut router = router.lock().await;
            router.expire_infos();
            router.do_maintenance()
        };

        if !actions.is_empty() {
            dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
        }
    }
}

#[async_trait::async_trait]
impl crate::types::PacketConn for PacketConnImpl {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        // First, try to pop from the queue (if packets are already buffered)
        let traffic = if let Some(pkt) = self.delivery_queue.try_pop_or_wait().await {
            // Got a packet from the queue
            pkt
        } else {
            // Queue was empty, recv_ready was incremented, now wait on channel
            let mut rx = self.traffic_rx.lock().await;
            let cancel = self.cancel.clone();

            tokio::select! {
                _ = cancel.cancelled() => return Err(Error::Closed),
                pkt = rx.recv() => match pkt {
                    Some(t) => t,
                    None => return Err(Error::Closed),
                },
            }
        };

        let n = buf.len().min(traffic.payload.len());
        buf[..n].copy_from_slice(&traffic.payload[..n]);
        let addr = Addr(traffic.source);
        Ok((n, addr))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let mtu = self.mtu();
        if buf.len() as u64 > mtu {
            return Err(Error::OversizedMessage);
        }

        let traffic = TrafficPacket::new(self.pub_key, addr.0, buf.to_vec());

        let actions = {
            let mut router = self.router.lock().await;
            router.send_traffic(traffic)
        };

        if !actions.is_empty() {
            dispatch_actions(actions, &self.peers, &self.delivery_queue, &self.traffic_tx).await;
        }

        Ok(buf.len())
    }

    async fn handle_conn(
        &self,
        key: Addr,
        conn: Box<dyn AsyncConn>,
        prio: u8,
    ) -> Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let peer_key = key.0;

        // Don't connect to ourselves
        if peer_key == self.pub_key {
            return Err(Error::BadKey);
        }

        // Split connection into read and write halves
        let (read_half, write_half) = tokio::io::split(conn);

        // Create writer channel and cancellation token for this peer
        let (writer_tx, writer_rx) = mpsc::channel(PEER_WRITER_CHANNEL_SIZE);
        let peer_cancel = CancellationToken::new();

        // Allocate the peer in the peers manager
        let handle = {
            let mut peers = self.peers.lock().await;
            peers.allocate_peer(peer_key, prio, writer_tx.clone(), peer_cancel.clone())
        };

        let peer_id = handle.id;
        let entry = handle.to_entry();
        let traffic_queue = handle.traffic_queue.clone();

        // Register with router and get initial actions
        let actions = {
            let mut router = self.router.lock().await;
            router.add_peer(entry)
        };

        // Send initial actions (sig req, bloom, etc.)
        if !actions.is_empty() {
            dispatch_actions(actions, &self.peers, &self.delivery_queue, &self.traffic_tx).await;
        }

        // Send a keepalive as initial message
        let keepalive_frame = wire::encode_frame(wire::PacketType::KeepAlive, &[]);
        let _ = writer_tx
            .send(PeerMessage::SendFrame(keepalive_frame))
            .await;

        // Spawn writer task
        let writer_cancel = peer_cancel.clone();
        let _writer_handle = tokio::spawn(peer_writer(
            peer_id,
            writer_rx,
            write_half,
            traffic_queue,
            self.config.peer_keepalive_delay,
            writer_cancel,
        ));

        // Run reader task (blocks until peer disconnects)
        peer_reader(
            peer_id,
            peer_key,
            self.pub_key,
            read_half,
            self.router.clone(),
            self.peers.clone(),
            self.delivery_queue.clone(),
            self.traffic_tx.clone(),
            peer_cancel.clone(),
            self.config.peer_max_message_size,
            self.config.peer_timeout,
            self.config.peer_keepalive_delay,
        )
        .await;

        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        // Compute overhead dynamically using Traffic::size()
        // Create a dummy traffic packet with maximum watermark to get worst-case overhead
        let traffic = wire::Traffic {
            path: vec![],
            from: vec![],
            source: [0; 32],
            dest: [0; 32],
            watermark: u64::MAX,  // Maximum watermark for worst-case size
            payload: vec![],
        };
        let overhead = traffic.size() + 1;  // +1 for packet type byte
        self.config.peer_max_message_size.saturating_sub(overhead as u64)
    }

    async fn send_lookup(&self, target: Addr) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }

        let actions = {
            let mut router = self.router.lock().await;
            let dest = target.0;
            let xform = router.blooms.x_key(&dest, &router.bloom_transform);
            router.pathfinder.ensure_rumor(xform);
            router.send_traffic(TrafficPacket::new(self.pub_key, dest, Vec::new()))
        };

        if !actions.is_empty() {
            dispatch_actions(actions, &self.peers, &self.delivery_queue, &self.traffic_tx).await;
        }
    }

    async fn close(&self) -> Result<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Closed);
        }

        // Cancel all background tasks
        self.cancel.cancel();

        // Close all peer connections
        let handles: Vec<(PublicKey, Vec<u64>)> = {
            let peers = self.peers.lock().await;
            peers
                .handles
                .iter()
                .map(|(k, m)| (*k, m.keys().copied().collect()))
                .collect()
        };

        for (_key, peer_ids) in &handles {
            let peers = self.peers.lock().await;
            for &id in peer_ids {
                if let Some(handle) = peers.get_handle(id) {
                    handle.cancel.cancel();
                }
            }
        }

        Ok(())
    }

    fn local_addr(&self) -> Addr {
        Addr(self.pub_key)
    }
}

/// Public peer info returned by `get_peers()`.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub key: [u8; 32],
    pub port: u64,
    pub priority: u8,
    pub latency_ms: f64,
}

/// Public tree entry returned by `get_tree()`.
#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub key: [u8; 32],
    pub parent: [u8; 32],
    pub sequence: u64,
}

impl PacketConnImpl {
    /// Get info about all connected peers.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        let router = self.router.lock().await;
        let mut result = Vec::new();
        for (key, entries) in &router.peers {
            for (_id, entry) in entries {
                let latency_ms = router
                    .lags
                    .get(&entry.id)
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                result.push(PeerInfo {
                    key: *key,
                    port: entry.port,
                    priority: entry.prio,
                    latency_ms,
                });
            }
        }
        result
    }

    /// Get spanning tree entries.
    pub async fn get_tree(&self) -> Vec<TreeEntry> {
        let router = self.router.lock().await;
        let mut result = Vec::new();
        for (key, info) in &router.infos {
            result.push(TreeEntry {
                key: *key,
                parent: info.parent,
                sequence: info.seq,
            });
        }
        result.sort_by(|a, b| a.key.cmp(&b.key));
        result
    }

    /// Get the number of routing entries (tree nodes known).
    pub async fn routing_entries(&self) -> usize {
        let router = self.router.lock().await;
        router.infos.len()
    }
}

/// Create a new PacketConn. This is the primary public constructor.
pub fn new_packet_conn(secret: SigningKey, config: Config) -> Arc<PacketConnImpl> {
    Arc::new(PacketConnImpl::new(secret, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn create_and_close() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_packet_conn(key, config);
        assert!(!conn.is_closed());

        use crate::types::PacketConn;
        conn.close().await.unwrap();
        assert!(conn.is_closed());

        // Double close should error
        assert!(conn.close().await.is_err());
    }

    #[tokio::test]
    async fn mtu_is_reasonable() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_packet_conn(key, config);

        use crate::types::PacketConn;
        let mtu = conn.mtu();
        // With 1MB max message size, MTU should be close to 1MB minus small overhead
        assert!(mtu > 1_000_000 - 100);
        assert!(mtu < 1_048_576);

        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn local_addr_matches_key() {
        let key = SigningKey::generate(&mut OsRng);
        let crypto = Crypto::new(key.clone());
        let expected_addr = Addr(crypto.public_key);
        let config = Config::default();
        let conn = new_packet_conn(key, config);

        use crate::types::PacketConn;
        assert_eq!(conn.local_addr(), expected_addr);

        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn write_to_self_returns_ok() {
        // Writing to self should work (packet gets routed, lookup initiated)
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_packet_conn(key, config);

        use crate::types::PacketConn;
        let addr = conn.local_addr();
        let result = conn.write_to(b"hello", &addr).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5);

        conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn read_from_closed_errors() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_packet_conn(key, config);

        use crate::types::PacketConn;
        conn.close().await.unwrap();

        let mut buf = [0u8; 1024];
        let result = conn.read_from(&mut buf).await;
        assert!(result.is_err());
    }
}
