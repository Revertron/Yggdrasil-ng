//! Core coordinator: wires Router + Peers together and provides the public
//! `PacketConn` implementation.
//!
//! - `PacketConnImpl` is the concrete implementation of `types::PacketConn`.
//! - The Router runs as a dedicated actor task (`router_actor`), processing
//!   messages from an mpsc channel. This eliminates mutex contention that
//!   previously caused cascade disconnects under high peer counts.
//! - `handle_conn()` spawns reader/writer tasks per peer.
//! - `read_from()` receives delivered traffic via an mpsc channel.
//! - `write_to()` sends traffic to the router actor for routing.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::bloom::BloomFilter;
use crate::config::Config;
use crate::crypto::{Crypto, PublicKey};
use crate::peers::{
    dispatch_actions, peer_reader, peer_writer, PeerMessage, Peers, ReadDeadline,
};
use crate::router::{PeerEntry, PeerId, Router, RouterAction, RouterAnnounce};
use crate::traffic::{DeliveryQueue, TrafficPacket};
use crate::types::{Addr, AsyncConn, Error, Result};
use crate::wire;

/// Default channel capacity for inbound traffic delivery.
const RECV_CHANNEL_SIZE: usize = 512;

/// Default channel capacity for peer writer.
const PEER_WRITER_CHANNEL_SIZE: usize = 512;

/// Channel capacity for the router actor message queue.
/// With 50 peers at ~10 msg/sec = 500 msg/sec; 4096 gives ~8s headroom.
const ROUTER_CHANNEL_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Router actor message types
// ---------------------------------------------------------------------------

/// Messages sent to the router actor task.
pub(crate) enum RouterMsg {
    // --- Fire-and-forget mutations (no reply needed) ---
    AddPeer {
        entry: PeerEntry,
        /// Signaled after the peer is registered and initial actions dispatched.
        done: Option<oneshot::Sender<()>>,
    },
    RemovePeer {
        peer_id: PeerId,
        key: PublicKey,
        port: u64,
    },
    HandleRequest {
        peer_id: PeerId,
        peer_key: PublicKey,
        req: wire::SigReq,
    },
    HandleResponse {
        peer_id: PeerId,
        key: PublicKey,
        res: wire::SigRes,
    },
    HandleAnnounce {
        peer_id: PeerId,
        peer_key: PublicKey,
        ann: RouterAnnounce,
    },
    HandleBloom {
        peer_key: PublicKey,
        filter: BloomFilter,
    },
    HandleTraffic {
        traffic: TrafficPacket,
    },
    SendTraffic {
        traffic: TrafficPacket,
    },
    HandleLookup {
        peer_key: PublicKey,
        lookup: wire::PathLookup,
    },
    HandleNotify {
        peer_key: PublicKey,
        notify: wire::PathNotify,
    },
    HandleBroken {
        broken: wire::PathBroken,
    },
    /// Combines ensure_rumor + send_traffic (used by send_lookup).
    SendLookup {
        our_key: PublicKey,
        dest: PublicKey,
    },

    // --- Queries (with oneshot reply) ---
    ForceLookup {
        dest: PublicKey,
        reply: oneshot::Sender<usize>,
    },
    GetPeers {
        reply: oneshot::Sender<Vec<PeerInfo>>,
    },
    GetTree {
        reply: oneshot::Sender<Vec<TreeEntry>>,
    },
    GetPaths {
        reply: oneshot::Sender<Vec<PathEntry>>,
    },
    RoutingEntries {
        reply: oneshot::Sender<usize>,
    },
    TreeCoordinates {
        reply: oneshot::Sender<Vec<wire::PeerPort>>,
    },
    GetDebugSnapshot {
        delivery_queue_bytes: u64,
        reply: oneshot::Sender<DebugSnapshot>,
    },
    GetRoutingPeerKeys {
        reply: oneshot::Sender<Vec<PublicKey>>,
    },
    CountLookupTargets {
        dest: PublicKey,
        reply: oneshot::Sender<(PublicKey, usize)>,
    },
}

// ---------------------------------------------------------------------------
// RouterHandle — cloneable sender for the router actor
// ---------------------------------------------------------------------------

/// A cloneable handle to the router actor. Send messages via `send()` (fire-
/// and-forget) or the `query_*()` async methods (with reply).
#[derive(Clone)]
pub(crate) struct RouterHandle {
    tx: mpsc::Sender<RouterMsg>,
}

impl RouterHandle {
    /// Fire-and-forget: enqueue a message to the router actor.
    /// Never blocks the caller — if the channel is full, spawns a background task.
    pub fn send(&self, msg: RouterMsg) {
        match self.tx.try_send(msg) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(msg)) => {
                let tx = self.tx.clone();
                tokio::spawn(async move {
                    let _ = tx.send(msg).await;
                });
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Blocking send: wait until the message is enqueued.
    /// Used for AddPeer where we must ensure registration completes before
    /// spawning the peer reader.
    pub async fn send_wait(&self, msg: RouterMsg) {
        let _ = self.tx.send(msg).await;
    }

    // --- Query convenience methods ---

    pub async fn query_peers(&self) -> Vec<PeerInfo> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(RouterMsg::GetPeers { reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn query_tree(&self) -> Vec<TreeEntry> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(RouterMsg::GetTree { reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn query_paths(&self) -> Vec<PathEntry> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(RouterMsg::GetPaths { reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn query_routing_entries(&self) -> usize {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(RouterMsg::RoutingEntries { reply: tx }).await;
        rx.await.unwrap_or(0)
    }

    pub async fn query_tree_coordinates(&self) -> Vec<wire::PeerPort> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(RouterMsg::TreeCoordinates { reply: tx }).await;
        rx.await.unwrap_or_default()
    }

    pub async fn query_debug_snapshot(&self, delivery_queue_bytes: u64) -> DebugSnapshot {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RouterMsg::GetDebugSnapshot {
                delivery_queue_bytes,
                reply: tx,
            })
            .await;
        rx.await.unwrap_or(DebugSnapshot {
            tree_node_count: 0,
            routing_peer_count: 0,
            tree_root: [0; 32],
            our_coords: vec![],
            path_cache_count: 0,
            broken_path_count: 0,
            pending_lookups: vec![],
            unresponded_peers: 0,
            peer_latencies_ms: vec![],
            delivery_queue_bytes: 0,
        })
    }

    pub async fn query_routing_peer_keys(&self) -> Vec<PublicKey> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RouterMsg::GetRoutingPeerKeys { reply: tx })
            .await;
        rx.await.unwrap_or_default()
    }

    pub async fn query_count_lookup_targets(&self, dest: PublicKey) -> (PublicKey, usize) {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RouterMsg::CountLookupTargets { dest, reply: tx })
            .await;
        rx.await.unwrap_or(([0; 32], 0))
    }

    pub async fn query_force_lookup(&self, dest: PublicKey) -> usize {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RouterMsg::ForceLookup { dest, reply: tx })
            .await;
        rx.await.unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Router actor task
// ---------------------------------------------------------------------------

/// The router actor: owns the Router exclusively, processes messages from
/// the channel, runs periodic maintenance, and dispatches resulting actions.
/// Replaces both the old `Arc<Mutex<Router>>` and `maintenance_loop`.
async fn router_actor(
    mut router: Router,
    mut rx: mpsc::Receiver<RouterMsg>,
    peers: Arc<Mutex<Peers>>,
    delivery_queue: Arc<DeliveryQueue>,
    traffic_tx: mpsc::Sender<TrafficPacket>,
    path_notify_cb: Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
    cancel: CancellationToken,
) {
    let mut maintenance_interval = tokio::time::interval(Duration::from_secs(1));
    maintenance_interval.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = maintenance_interval.tick() => {
                router.expire_infos();
                let actions = router.do_maintenance();
                if !actions.is_empty() {
                    dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
                }
            }
            msg = rx.recv() => {
                let Some(msg) = msg else { break };
                handle_router_msg(
                    &mut router, msg, &peers, &delivery_queue,
                    &traffic_tx, &path_notify_cb,
                ).await;
            }
        }
    }
}

/// Process a single router message: call the appropriate Router method and
/// dispatch any resulting actions.
async fn handle_router_msg(
    router: &mut Router,
    msg: RouterMsg,
    peers: &Arc<Mutex<Peers>>,
    delivery_queue: &Arc<DeliveryQueue>,
    traffic_tx: &mpsc::Sender<TrafficPacket>,
    path_notify_cb: &Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
) {
    match msg {
        RouterMsg::AddPeer { entry, done } => {
            let actions = router.add_peer(entry);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
            if let Some(tx) = done {
                let _ = tx.send(());
            }
        }
        RouterMsg::RemovePeer { peer_id, key, port } => {
            let actions = router.remove_peer(peer_id, key, port);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::HandleRequest { peer_id, peer_key, req } => {
            // Look up peer entry and compute SigRes response
            if let Some(peers_map) = router.peers.get(&peer_key) {
                if let Some(entry) = peers_map.get(&peer_id) {
                    let action = router.handle_request_with_data(entry, &req);
                    dispatch_actions(vec![action], peers, delivery_queue, traffic_tx, path_notify_cb).await;
                }
            }
        }
        RouterMsg::HandleResponse { peer_id, key, res } => {
            router.handle_response(peer_id, &key, &res);
        }
        RouterMsg::HandleAnnounce { peer_id, peer_key, ann } => {
            let actions = router.handle_announce(peer_id, &peer_key, &ann);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::HandleBloom { peer_key, filter } => {
            router.handle_bloom(&peer_key, filter);
        }
        RouterMsg::HandleTraffic { traffic } => {
            let actions = router.handle_traffic(traffic);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::SendTraffic { traffic } => {
            let actions = router.send_traffic(traffic);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::HandleLookup { peer_key, lookup } => {
            let actions = router.handle_lookup(&peer_key, &lookup);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::HandleNotify { peer_key, notify } => {
            let actions = router.handle_notify(&peer_key, &notify);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::HandleBroken { broken } => {
            let actions = router.handle_broken(&broken);
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::SendLookup { our_key, dest } => {
            let xform = router.blooms.x_key(&dest, &router.bloom_transform);
            router.pathfinder.ensure_rumor(xform);
            let actions = router.send_traffic(TrafficPacket::new(our_key, dest, Vec::new()));
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
        }
        RouterMsg::ForceLookup { dest, reply } => {
            let actions = router.force_lookup(dest);
            let n = actions.iter().filter(|a| matches!(a, RouterAction::SendPathLookup { .. })).count();
            dispatch_actions(actions, peers, delivery_queue, traffic_tx, path_notify_cb).await;
            let _ = reply.send(n);
        }
        RouterMsg::GetPeers { reply } => {
            let mut result = Vec::new();
            for (key, entries) in &router.peers {
                for (_id, entry) in entries {
                    let latency_ms = router
                        .lags
                        .get(&entry.id)
                        .map(|d| d.as_secs_f64() * 1000.0)
                        .unwrap_or(0.0);
                    let cost = router.get_cost(entry.id);
                    result.push(PeerInfo {
                        key: *key,
                        port: entry.port,
                        priority: entry.prio,
                        latency_ms,
                        cost,
                    });
                }
            }
            let _ = reply.send(result);
        }
        RouterMsg::GetTree { reply } => {
            let mut result: Vec<TreeEntry> = router
                .infos
                .iter()
                .map(|(key, info)| TreeEntry {
                    key: *key,
                    parent: info.parent,
                    sequence: info.seq,
                })
                .collect();
            result.sort_by(|a, b| a.key.cmp(&b.key));
            let _ = reply.send(result);
        }
        RouterMsg::GetPaths { reply } => {
            let mut result: Vec<PathEntry> = router
                .pathfinder
                .paths
                .iter()
                .filter(|(_, info)| !info.broken)
                .map(|(key, info)| PathEntry {
                    key: *key,
                    path: info.path.clone(),
                    sequence: info.seq,
                })
                .collect();
            result.sort_by(|a, b| a.key.cmp(&b.key));
            let _ = reply.send(result);
        }
        RouterMsg::RoutingEntries { reply } => {
            let _ = reply.send(router.infos.len());
        }
        RouterMsg::TreeCoordinates { reply } => {
            let self_key = router.crypto.public_key;
            let (_root, path) = router.get_root_and_path(&self_key);
            let _ = reply.send(path);
        }
        RouterMsg::GetDebugSnapshot { delivery_queue_bytes, reply } => {
            use std::time::Instant;
            let now = Instant::now();
            let self_key = router.crypto.public_key;
            let (tree_root, our_coords) = router.get_root_and_path(&self_key);

            let pending_lookups = router
                .pathfinder
                .rumors
                .iter()
                .map(|(xformed_key, rumor)| {
                    let dest_key = rumor.traffic.as_ref().map(|t| t.dest);
                    let age_secs = now.duration_since(rumor.created).as_secs_f64();
                    let multicast_count =
                        router.blooms.count_on_tree_targets_for_xkey(xformed_key);
                    PendingLookup {
                        dest_key,
                        xformed_key: *xformed_key,
                        age_secs,
                        sent: rumor.send_time.is_some(),
                        multicast_count,
                    }
                })
                .collect();

            let total_peer_ids: usize = router.peers.values().map(|m| m.len()).sum();
            let unresponded_peers = total_peer_ids.saturating_sub(router.responded.len());

            let peer_latencies_ms = router
                .peers
                .iter()
                .map(|(key, entries)| {
                    let latency = entries
                        .keys()
                        .find_map(|id| router.lags.get(id))
                        .map(|d| d.as_secs_f64() * 1000.0)
                        .unwrap_or(0.0);
                    (*key, latency)
                })
                .collect();

            let _ = reply.send(DebugSnapshot {
                tree_node_count: router.infos.len(),
                routing_peer_count: router.peers.len(),
                tree_root,
                our_coords,
                path_cache_count: router.pathfinder.paths.len(),
                broken_path_count: router.pathfinder.paths.values().filter(|p| p.broken).count(),
                pending_lookups,
                unresponded_peers,
                peer_latencies_ms,
                delivery_queue_bytes,
            });
        }
        RouterMsg::GetRoutingPeerKeys { reply } => {
            let _ = reply.send(router.peers.keys().copied().collect());
        }
        RouterMsg::CountLookupTargets { dest, reply } => {
            let xform = router.blooms.x_key(&dest, &router.bloom_transform);
            let count = router.blooms.count_on_tree_targets_for_xkey(&xform);
            let _ = reply.send((xform, count));
        }
    }
}

// ---------------------------------------------------------------------------
// PacketConnImpl
// ---------------------------------------------------------------------------

/// The concrete PacketConn implementation.
pub struct PacketConnImpl {
    /// Signing key (identity).
    signing_key: SigningKey,
    /// Our public key.
    pub_key: PublicKey,
    /// Configuration.
    config: Config,
    /// Handle to the router actor (replaces Arc<Mutex<Router>>).
    pub(crate) router_handle: RouterHandle,
    /// The peer manager (shared with peer tasks).
    peers: Arc<Mutex<Peers>>,
    /// Delivery queue for receive buffering with backpressure.
    delivery_queue: Arc<DeliveryQueue>,
    /// Inbound traffic channel (reader side).
    traffic_rx: Mutex<mpsc::Receiver<TrafficPacket>>,
    /// Whether this PacketConn is closed.
    closed: AtomicBool,
    /// Cancellation token for background tasks.
    cancel: CancellationToken,
    /// Router actor task handle.
    _actor_handle: JoinHandle<()>,
}

impl PacketConnImpl {
    /// Create a new PacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let crypto = Crypto::new(secret.clone());
        let pub_key = crypto.public_key;
        let router = Router::new(crypto, &config);
        let peers = Arc::new(Mutex::new(Peers::new()));
        let delivery_queue = DeliveryQueue::new();
        let (traffic_tx, traffic_rx) = mpsc::channel(RECV_CHANNEL_SIZE);
        let cancel = CancellationToken::new();
        let path_notify_cb = config.path_notify.clone();

        // Create router actor channel and spawn actor task
        let (router_tx, router_rx) = mpsc::channel(ROUTER_CHANNEL_SIZE);
        let router_handle = RouterHandle { tx: router_tx };

        let actor_handle = {
            let peers = peers.clone();
            let delivery_queue = delivery_queue.clone();
            let traffic_tx = traffic_tx.clone();
            let cancel = cancel.clone();
            let path_notify_cb = path_notify_cb.clone();
            tokio::spawn(router_actor(
                router, router_rx, peers, delivery_queue, traffic_tx,
                path_notify_cb, cancel,
            ))
        };

        Self {
            signing_key: secret,
            pub_key,
            config,
            router_handle,
            peers,
            delivery_queue,
            traffic_rx: Mutex::new(traffic_rx),
            closed: AtomicBool::new(false),
            cancel,
            _actor_handle: actor_handle,
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
        self.router_handle.send(RouterMsg::SendTraffic { traffic });

        Ok(buf.len())
    }

    async fn handle_conn(&self, key: Addr, conn: Box<dyn AsyncConn>, prio: u8) -> Result<()> {
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
        let _cancel_on_drop = peer_cancel.clone().drop_guard();

        // Allocate the peer in the peers manager
        let handle = {
            let mut peers = self.peers.lock().await;
            peers.allocate_peer(peer_key, prio, writer_tx.clone(), peer_cancel.clone())
        };

        let peer_id = handle.id;
        let entry = handle.to_entry();
        let port = handle.port;
        let traffic_queue = handle.traffic_queue.clone();

        // Register with router actor and wait for completion.
        // This ensures the peer is in the router before the reader starts.
        let (done_tx, done_rx) = oneshot::channel();
        self.router_handle
            .send_wait(RouterMsg::AddPeer {
                entry,
                done: Some(done_tx),
            })
            .await;
        // Wait for the actor to process AddPeer and dispatch initial actions
        let _ = done_rx.await;

        // Send a keepalive as initial message
        let keepalive_frame = wire::encode_frame(wire::PacketType::KeepAlive, &[]);
        let _ = writer_tx
            .send(PeerMessage::SendFrame(keepalive_frame))
            .await;

        // Shared deadline: writer arms it on non-keepalive sends;
        // reader clears it on any receive.
        let read_deadline: ReadDeadline = Arc::new(std::sync::Mutex::new(None));

        // Spawn writer task
        let writer_cancel = peer_cancel.clone();
        let _writer_handle = tokio::spawn(peer_writer(
            peer_id,
            peer_key,
            port,
            writer_rx,
            write_half,
            traffic_queue,
            self.router_handle.clone(),
            self.peers.clone(),
            self.config.peer_keepalive_delay,
            self.config.peer_timeout,
            read_deadline.clone(),
            writer_cancel,
        ));

        // Run reader task (blocks until peer disconnects)
        let result = peer_reader(
            peer_id,
            peer_key,
            self.pub_key,
            read_half,
            self.router_handle.clone(),
            self.peers.clone(),
            writer_tx.clone(),
            peer_cancel.clone(),
            self.config.peer_max_message_size,
            self.config.peer_timeout,
            self.config.peer_keepalive_delay,
            read_deadline,
        )
        .await;

        result
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        let traffic = wire::Traffic {
            path: vec![],
            from: vec![],
            source: [0; 32],
            dest: [0; 32],
            watermark: u64::MAX,
            payload: vec![],
        };
        let overhead = traffic.size() + 1;
        self.config.peer_max_message_size.saturating_sub(overhead as u64)
    }

    async fn send_lookup(&self, target: Addr) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        self.router_handle.send(RouterMsg::SendLookup {
            our_key: self.pub_key,
            dest: target.0,
        });
    }

    async fn close(&self) -> Result<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Closed);
        }

        // Cancel all background tasks (including router actor)
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

// ---------------------------------------------------------------------------
// Public types returned by query methods
// ---------------------------------------------------------------------------

/// One pending path lookup ("rumor") that hasn't resolved yet.
#[derive(Clone, Debug)]
pub struct PendingLookup {
    pub dest_key: Option<[u8; 32]>,
    pub xformed_key: [u8; 32],
    pub age_secs: f64,
    pub sent: bool,
    pub multicast_count: usize,
}

/// Diagnostic snapshot of internal routing state.
#[derive(Clone, Debug)]
pub struct DebugSnapshot {
    pub tree_node_count: usize,
    pub routing_peer_count: usize,
    pub tree_root: [u8; 32],
    pub our_coords: Vec<u64>,
    pub path_cache_count: usize,
    pub broken_path_count: usize,
    pub pending_lookups: Vec<PendingLookup>,
    pub unresponded_peers: usize,
    pub peer_latencies_ms: Vec<([u8; 32], f64)>,
    pub delivery_queue_bytes: u64,
}

/// Public peer info returned by `get_peers()`.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub key: [u8; 32],
    pub port: u64,
    pub priority: u8,
    pub latency_ms: f64,
    pub cost: u64,
}

/// Public tree entry returned by `get_tree()`.
#[derive(Clone, Debug)]
pub struct TreeEntry {
    pub key: [u8; 32],
    pub parent: [u8; 32],
    pub sequence: u64,
}

/// Public path entry returned by `get_paths()`.
#[derive(Clone, Debug)]
pub struct PathEntry {
    pub key: [u8; 32],
    pub path: Vec<wire::PeerPort>,
    pub sequence: u64,
}

impl PacketConnImpl {
    /// Force a path lookup for the given destination, bypassing the rumor throttle.
    /// Returns the number of peers the lookup was multicast to.
    pub async fn force_lookup(&self, dest: PublicKey) -> usize {
        if self.closed.load(Ordering::Relaxed) {
            return 0;
        }
        self.router_handle.query_force_lookup(dest).await
    }

    /// Get info about all connected peers.
    pub async fn get_peers(&self) -> Vec<PeerInfo> {
        self.router_handle.query_peers().await
    }

    /// Get spanning tree entries.
    pub async fn get_tree(&self) -> Vec<TreeEntry> {
        self.router_handle.query_tree().await
    }

    /// Get the number of routing entries (tree nodes known).
    pub async fn routing_entries(&self) -> usize {
        self.router_handle.query_routing_entries().await
    }

    /// Get our current tree coordinates (path from root).
    pub async fn tree_coordinates(&self) -> Vec<wire::PeerPort> {
        self.router_handle.query_tree_coordinates().await
    }

    /// Get all cached paths (from pathfinder).
    pub async fn get_paths(&self) -> Vec<PathEntry> {
        self.router_handle.query_paths().await
    }

    /// Get a diagnostic snapshot of internal routing state.
    pub async fn get_debug_snapshot(&self) -> DebugSnapshot {
        let delivery_queue_bytes = self.delivery_queue.queue_size().await;
        self.router_handle
            .query_debug_snapshot(delivery_queue_bytes)
            .await
    }

    /// Get routing peer keys (direct neighbors in spanning tree).
    pub async fn get_routing_peer_keys(&self) -> Vec<crate::crypto::PublicKey> {
        self.router_handle.query_routing_peer_keys().await
    }

    /// Count how many on-tree peers' bloom filters cover the given destination key.
    pub async fn count_lookup_targets(&self, dest: PublicKey) -> (PublicKey, usize) {
        self.router_handle
            .query_count_lookup_targets(dest)
            .await
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
