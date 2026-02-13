//! Peer connection management.
//!
//! Each peer connection spawns two tokio tasks:
//! - **Reader task**: reads frames from the connection, decodes messages,
//!   dispatches to the router via the shared state mutex.
//! - **Writer task**: receives outbound frames via an mpsc channel,
//!   writes them with buffered I/O, manages keepalive and deadlines.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::bloom::BloomFilter;
use crate::crypto::{Crypto, PublicKey};
use crate::router::{PeerId, PeerEntry, Router, RouterAction, RouterAnnounce};
use crate::traffic::{PacketQueue, TrafficPacket};
use crate::types::Error;
use crate::wire::{self, PeerPort};

/// Messages sent from the system to a peer's writer task.
#[derive(Debug)]
pub(crate) enum PeerMessage {
    /// Raw frame bytes to write (already length-prefixed).
    SendFrame(Vec<u8>),
}

/// Handle to a peer's writer task.
pub(crate) struct PeerHandle {
    pub id: PeerId,
    pub key: PublicKey,
    pub port: PeerPort,
    pub prio: u8,
    pub order: u64,
    pub tx: mpsc::Sender<PeerMessage>,
    pub cancel: CancellationToken,
    /// Queue for outbound traffic when writer is busy.
    pub traffic_queue: Arc<tokio::sync::Mutex<PacketQueue>>,
}

impl PeerHandle {
    pub fn to_entry(&self) -> PeerEntry {
        PeerEntry {
            id: self.id,
            key: self.key,
            port: self.port,
            prio: self.prio,
            order: self.order,
        }
    }
}

/// Manages all peer connections.
pub(crate) struct Peers {
    next_id: PeerId,
    next_port: PeerPort,
    /// Ports allocated to peer keys.
    used_ports: HashMap<PeerPort, PublicKey>,
    /// Active peer handles, grouped by public key.
    pub handles: HashMap<PublicKey, HashMap<PeerId, PeerHandle>>,
    /// Connection order counter.
    order: u64,
}

impl Peers {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_port: 1,
            used_ports: HashMap::new(),
            handles: HashMap::new(),
            order: 0,
        }
    }

    /// Allocate a new peer. Returns the PeerHandle info (id, port, order)
    /// without spawning tasks — the caller is responsible for that.
    pub fn allocate_peer(
        &mut self,
        key: PublicKey,
        prio: u8,
        tx: mpsc::Sender<PeerMessage>,
        cancel: CancellationToken,
    ) -> PeerHandle {
        let id = self.next_id;
        self.next_id += 1;

        // Reuse port if we already have a peer with this key, else allocate new
        let port = if let Some(existing) = self.handles.get(&key) {
            existing.values().next().map(|h| h.port).unwrap_or_else(|| {
                let p = self.next_port;
                self.next_port += 1;
                p
            })
        } else {
            let p = self.next_port;
            self.next_port += 1;
            p
        };

        if !self.handles.contains_key(&key) {
            self.used_ports.insert(port, key);
        }

        let order = self.order;
        self.order += 1;

        let handle = PeerHandle {
            id,
            key,
            port,
            prio,
            order,
            tx,
            cancel,
            traffic_queue: Arc::new(tokio::sync::Mutex::new(PacketQueue::new())),
        };

        self.handles
            .entry(key)
            .or_insert_with(HashMap::new)
            .insert(id, PeerHandle {
                id,
                key,
                port,
                prio,
                order,
                tx: handle.tx.clone(),
                cancel: handle.cancel.clone(),
                traffic_queue: handle.traffic_queue.clone(),
            });

        handle
    }

    /// Remove a peer by ID.
    pub fn remove_peer(&mut self, id: PeerId, key: &PublicKey) -> Option<PeerPort> {
        if let Some(peers) = self.handles.get_mut(key) {
            let port = peers.get(&id).map(|h| h.port);
            peers.remove(&id);
            if peers.is_empty() {
                self.handles.remove(key);
                if let Some(p) = port {
                    self.used_ports.remove(&p);
                }
            }
            port
        } else {
            None
        }
    }

    /// Send a message to a specific peer.
    pub async fn send_to_peer(&self, peer_id: PeerId, msg: PeerMessage) -> bool {
        for peers in self.handles.values() {
            if let Some(handle) = peers.get(&peer_id) {
                // Use try_send to avoid blocking dispatch_actions
                match handle.tx.try_send(msg) {
                    Ok(_) => return true,
                    Err(mpsc::error::TrySendError::Full(msg)) => {
                        // Channel full - spawn background task
                        let tx = handle.tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.send(msg).await;
                        });
                        return true;
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => return false,
                }
            }
        }
        false
    }

    /// Get a reference to a peer handle by ID.
    pub fn get_handle(&self, peer_id: PeerId) -> Option<&PeerHandle> {
        for peers in self.handles.values() {
            if let Some(handle) = peers.get(&peer_id) {
                return Some(handle);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Peer traffic sending with queuing
// ---------------------------------------------------------------------------

/// Send traffic to a peer, queuing if the channel is full.
/// This implements the same backpressure logic as Go's peers.go _push() method.
async fn send_traffic_to_peer(
    peers: &Arc<tokio::sync::Mutex<Peers>>,
    peer_id: PeerId,
    traffic: TrafficPacket,
) {
    let peers_lock = peers.lock().await;

    // Find the peer handle
    let handle = match peers_lock.get_handle(peer_id) {
        Some(h) => h,
        None => {
            drop(peers_lock);
            return;
        }
    };

    // Encode the traffic frame
    let wire_traffic = wire::Traffic {
        path: traffic.path.clone(),
        from: traffic.from.clone(),
        source: traffic.source,
        dest: traffic.dest,
        watermark: traffic.watermark,
        payload: traffic.payload.clone(),
    };
    let mut payload = Vec::new();
    wire_traffic.encode(&mut payload);
    let frame = wire::encode_frame(wire::PacketType::Traffic, &payload);
    let msg = PeerMessage::SendFrame(frame);

    // Try non-blocking send first
    let tx = handle.tx.clone();
    drop(peers_lock);

    match tx.try_send(msg) {
        Ok(_) => {
            // Fast path: sent immediately
        }
        Err(mpsc::error::TrySendError::Full(msg)) => {
            // Channel full - spawn background task to wait for space
            // This prevents blocking dispatch_actions
            tokio::spawn(async move {
                let _ = tx.send(msg).await;
            });
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // Peer disconnected, ignore
        }
    }
}

// ---------------------------------------------------------------------------
// Frame encoding helpers for outbound messages
// ---------------------------------------------------------------------------

/// Encode a RouterAction into a frame and send it to the appropriate peer.
pub(crate) fn encode_action_frame(action: &RouterAction) -> Option<(PeerId, Vec<u8>)> {
    match action {
        RouterAction::SendSigReq { peer_id, req } => {
            tracing::debug!("RouterAction::SendSigReq");
            let mut payload = Vec::new();
            req.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoSigReq, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendSigRes { peer_id, res } => {
            tracing::debug!("RouterAction::SendSigRes");
            let mut payload = Vec::new();
            res.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoSigRes, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendAnnounce { peer_id, ann } => {
            tracing::debug!("RouterAction::SendAnnounce");
            let mut payload = Vec::new();
            ann.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoAnnounce, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendBloom { peer_id, bloom } => {
            tracing::debug!("RouterAction::SendBloom");
            let mut payload = Vec::new();
            wire::encode_bloom(&mut payload, bloom.as_raw());
            let frame = wire::encode_frame(wire::PacketType::ProtoBloomFilter, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendTraffic { peer_id, traffic } => {
            tracing::debug!("RouterAction::SendTraffic");
            let wire_traffic = wire::Traffic {
                path: traffic.path.clone(),
                from: traffic.from.clone(),
                source: traffic.source,
                dest: traffic.dest,
                watermark: traffic.watermark,
                payload: traffic.payload.clone(),
            };
            let mut payload = Vec::new();
            wire_traffic.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::Traffic, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendPathLookup { peer_id, lookup } => {
            tracing::debug!("RouterAction::SendPathLookup");
            let mut payload = Vec::new();
            lookup.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoPathLookup, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendPathNotify { peer_id, notify } => {
            tracing::debug!("RouterAction::SendPathNotify");
            let mut payload = Vec::new();
            notify.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoPathNotify, &payload);
            Some((*peer_id, frame))
        }
        RouterAction::SendPathBroken { peer_id, broken } => {
            tracing::debug!("RouterAction::SendPathBroken");
            let mut payload = Vec::new();
            broken.encode(&mut payload);
            let frame = wire::encode_frame(wire::PacketType::ProtoPathBroken, &payload);
            Some((*peer_id, frame))
        }
        // Non-send actions don't produce frames
        RouterAction::DeliverTraffic { .. } | RouterAction::PathNotifyCallback { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Peer reader: reads from connection, dispatches to router
// ---------------------------------------------------------------------------

/// Read a uvarint from an async reader.
async fn read_uvarint<R: tokio::io::AsyncRead + Unpin>(reader: &mut R) -> Result<u64, Error> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    let mut buf = [0u8; 1];

    loop {
        reader.read_exact(&mut buf).await.map_err(Error::Io)?;
        let byte = buf[0];
        if shift >= 63 && byte > 1 {
            return Err(Error::Decode);
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 70 {
            return Err(Error::Decode);
        }
    }
}

/// The peer reader task. Reads frames from the connection and dispatches
/// messages to the router via the shared mutex.
pub(crate) async fn peer_reader(
    peer_id: PeerId,
    peer_key: PublicKey,
    our_key: PublicKey,
    conn_read: impl tokio::io::AsyncRead + Unpin + Send,
    router: Arc<tokio::sync::Mutex<Router>>,
    peers: Arc<tokio::sync::Mutex<Peers>>,
    delivery_queue: Arc<crate::traffic::DeliveryQueue>,
    traffic_tx: mpsc::Sender<TrafficPacket>,
    cancel: CancellationToken,
    max_message_size: u64,
    _peer_timeout: Duration,
    _keepalive_delay: Duration,
) {
    let mut reader = BufReader::new(conn_read);
    let sig_req_send_time = Instant::now();

    loop {
        // Read frame: length(uvarint) | content
        // No timeout by default - rely on TCP keepalives
        // (Go only sets timeout when expecting a response after sending non-keepalive traffic)
        let frame_result = tokio::select! {
            _ = cancel.cancelled() => { break },
            result = read_uvarint(&mut reader) => result,
        };

        let frame_len = match frame_result {
            Ok(len) => len,
            Err(e) => {
                tracing::info!("Peer {} read_uvarint error: {}, closing connection", peer_id, e);
                break;
            },
        };

        if frame_len > max_message_size {
            break;
        }

        let mut buf = vec![0u8; frame_len as usize];
        let read_result = tokio::select! {
            _ = cancel.cancelled() => { break },
            result = reader.read_exact(&mut buf) => result,
        };

        if let Err(e) = read_result {
            tracing::info!("Peer {} read_exact error: {}, closing connection", peer_id, e);
            break;
        }

        if buf.is_empty() {
            continue; // empty message, skip
        }

        let ptype_byte = buf[0];
        let payload = &buf[1..];

        let ptype = match wire::PacketType::try_from(ptype_byte) {
            Ok(t) => t,
            Err(_) => {
                tracing::warn!(peer_id, "unrecognized packet type: {}", ptype_byte);
                break;
            }
        };

        tracing::debug!("peer_reader[{}]: received {:?} frame, {} bytes payload", peer_id, ptype, payload.len());

        // Dispatch based on message type
        match ptype {
            wire::PacketType::Dummy | wire::PacketType::KeepAlive => {
                // No-op, just resets deadline
            }
            wire::PacketType::ProtoSigReq => {
                let mut r = wire::WireReader::new(payload);
                let req = match wire::SigReq::decode(&mut r) {
                    Ok(req) => req,
                    Err(_) => { break },
                };
                let router = router.lock().await;
                // Find peer entry
                if let Some(peers_map) = router.peers.get(&peer_key) {
                    if let Some(entry) = peers_map.get(&peer_id) {
                        let action = router.handle_request_with_data(entry, &req);
                        drop(router);
                        dispatch_action(action, &peers).await;
                    }
                }
            }
            wire::PacketType::ProtoSigRes => {
                let mut r = wire::WireReader::new(payload);
                let res = match wire::SigRes::decode(&mut r) {
                    Ok(res) => res,
                    Err(_) => break,
                };
                // Verify the signature
                let bs = {
                    let mut out = Vec::new();
                    out.extend_from_slice(&our_key);
                    out.extend_from_slice(&peer_key);
                    wire::encode_uvarint(&mut out, res.seq);
                    wire::encode_uvarint(&mut out, res.nonce);
                    wire::encode_uvarint(&mut out, res.port);
                    out
                };
                if !Crypto::verify(&peer_key, &bs, &res.psig) {
                    tracing::warn!(peer_id, "bad sig res from peer");
                    break;
                }
                let rtt = sig_req_send_time.elapsed();
                let mut router = router.lock().await;
                router.handle_response(peer_id, &peer_key, &res, rtt);
            }
            wire::PacketType::ProtoAnnounce => {
                let ann = match wire::Announce::decode(payload) {
                    Ok(a) => a,
                    Err(_) => { break },
                };
                let router_ann = RouterAnnounce::from_wire(&ann);
                if !router_ann.check() {
                    break;
                }
                let mut router = router.lock().await;
                let actions = router.handle_announce(peer_id, &peer_key, &router_ann);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
            }
            wire::PacketType::ProtoBloomFilter => {
                let raw = match wire::decode_bloom(payload) {
                    Ok(r) => r,
                    Err(_) => {
                        break;
                    },
                };
                let filter = BloomFilter::from_raw(raw);
                let mut router = router.lock().await;
                router.handle_bloom(&peer_key, filter);
            }
            wire::PacketType::ProtoPathLookup => {
                let lookup = match wire::PathLookup::decode(payload) {
                    Ok(l) => l,
                    Err(_) => break,
                };
                let mut router = router.lock().await;
                let actions = router.handle_lookup(&peer_key, &lookup);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
            }
            wire::PacketType::ProtoPathNotify => {
                let notify = match wire::PathNotify::decode(payload) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                let mut router = router.lock().await;
                let actions = router.handle_notify(&peer_key, &notify);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
            }
            wire::PacketType::ProtoPathBroken => {
                let broken = match wire::PathBroken::decode(payload) {
                    Ok(b) => b,
                    Err(_) => break,
                };
                let mut router = router.lock().await;
                let actions = router.handle_broken(&broken);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
            }
            wire::PacketType::Traffic => {
                let tr = match wire::Traffic::decode(payload) {
                    Ok(t) => t,
                    Err(_) => break,
                };
                let traffic = TrafficPacket {
                    path: tr.path,
                    from: tr.from,
                    source: tr.source,
                    dest: tr.dest,
                    watermark: tr.watermark,
                    payload: tr.payload,
                };
                let mut router = router.lock().await;
                let actions = router.handle_traffic(traffic);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
            }
        }
    }

    // Peer disconnected — remove from router and peers
    {
        let peers_lock = peers.lock().await;
        let port = peers_lock
            .handles
            .get(&peer_key)
            .and_then(|m| m.get(&peer_id))
            .map(|h| h.port)
            .unwrap_or(0);
        drop(peers_lock);

        let mut router = router.lock().await;
        let actions = router.remove_peer(peer_id, peer_key, port);
        drop(router);

        let mut peers_lock = peers.lock().await;
        peers_lock.remove_peer(peer_id, &peer_key);
        drop(peers_lock);

        dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx).await;
    }

    cancel.cancel();
}

/// Drain queued traffic packets and send them.
/// This is called by peer_writer after successfully writing a frame.
async fn drain_traffic_queue<W: tokio::io::AsyncWrite + Unpin>(
    peer_id: PeerId,
    queue: &Arc<tokio::sync::Mutex<PacketQueue>>,
    writer: &mut W,
) {
    use tokio::io::AsyncWriteExt;
    loop {
        // Try to pop a packet from the queue
        let traffic = {
            let mut q = queue.lock().await;
            q.pop()
        };

        let traffic = match traffic {
            Some(t) => t,
            None => break, // Queue is empty
        };

        // Encode the traffic frame
        let wire_traffic = wire::Traffic {
            path: traffic.path,
            from: traffic.from,
            source: traffic.source,
            dest: traffic.dest,
            watermark: traffic.watermark,
            payload: traffic.payload,
        };
        let mut payload = Vec::new();
        wire_traffic.encode(&mut payload);
        let frame = wire::encode_frame(wire::PacketType::Traffic, &payload);

        // Write the frame
        if writer.write_all(&frame).await.is_err() {
            tracing::debug!("peer_writer: failed to write queued traffic for peer {}", peer_id);
            break;
        }

        tracing::debug!("peer_writer: sent queued traffic for peer {}", peer_id);
    }
}

/// The peer writer task. Receives frames and writes them to the connection.
/// After writing each frame, it drains queued traffic packets.
pub(crate) async fn peer_writer(
    peer_id: PeerId,
    mut rx: mpsc::Receiver<PeerMessage>,
    mut conn_write: impl tokio::io::AsyncWrite + Unpin + Send,
    traffic_queue: Arc<tokio::sync::Mutex<PacketQueue>>,
    keepalive_delay: Duration,
    cancel: CancellationToken,
) {
    use crate::wire;
    use tokio::io::AsyncWriteExt;

    // Write directly without BufWriter to ensure immediate transmission
    let keepalive_frame = wire::encode_frame(wire::PacketType::KeepAlive, &[]);

    // Use interval for persistent keepalive timer (not sleep which resets each loop)
    let mut keepalive_timer = tokio::time::interval(keepalive_delay);
    keepalive_timer.tick().await; // skip first immediate tick

    loop {
        let msg = tokio::select! {
            _ = cancel.cancelled() => break,
            msg = rx.recv() => match msg {
                Some(m) => Some(m),
                None => break,
            },
            _ = keepalive_timer.tick() => {
                // Timer fired, send keepalive
                tracing::trace!("Peer {} sending keepalive", peer_id);
                if conn_write.write_all(&keepalive_frame).await.is_err() {
                    break;
                }
                if conn_write.flush().await.is_err() {
                    break;
                }
                continue;
            },
        };

        let msg = match msg {
            Some(m) => m,
            None => break,
        };

        match msg {
            PeerMessage::SendFrame(data) => {
                // Log outgoing frame type for diagnostics
                if let Some(ptype) = peek_frame_type(&data) {
                    tracing::debug!("peer_writer: sending {:?} frame, {} bytes", ptype, data.len());
                }
                if conn_write.write_all(&data).await.is_err() {
                    break;
                }

                // After successfully writing, drain queued traffic
                drain_traffic_queue(peer_id, &traffic_queue, &mut conn_write).await;

                // Always flush to ensure data reaches the network immediately
                if conn_write.flush().await.is_err() {
                    break;
                }
            }
        }
    }

    cancel.cancel();
}

/// Peek at the packet type of an encoded frame (uvarint length + type byte).
fn peek_frame_type(data: &[u8]) -> Option<wire::PacketType> {
    // Skip the uvarint length prefix to find the type byte
    let mut offset = 0;
    for &b in data.iter() {
        offset += 1;
        if b & 0x80 == 0 {
            break;
        }
        if offset >= data.len() {
            return None;
        }
    }
    if offset < data.len() {
        wire::PacketType::try_from(data[offset]).ok()
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Action dispatch helpers
// ---------------------------------------------------------------------------

/// Dispatch a single router action.
async fn dispatch_action(
    action: RouterAction,
    peers: &Arc<tokio::sync::Mutex<Peers>>,
) {
    if let Some((peer_id, frame)) = encode_action_frame(&action) {
        let peers = peers.lock().await;
        let _ = peers.send_to_peer(peer_id, PeerMessage::SendFrame(frame)).await;
    }
}

/// Dispatch a batch of router actions.
pub(crate) async fn dispatch_actions(
    actions: Vec<RouterAction>,
    peers: &Arc<tokio::sync::Mutex<Peers>>,
    delivery_queue: &Arc<crate::traffic::DeliveryQueue>,
    traffic_tx: &mpsc::Sender<TrafficPacket>,
) {
    for action in actions {
        match action {
            RouterAction::DeliverTraffic { traffic } => {
                // Use delivery queue for backpressure handling
                if let Some(pkt) = delivery_queue.deliver(traffic).await {
                    // Reader is waiting, send immediately via channel
                    let _ = traffic_tx.send(pkt).await;
                }
                // Otherwise packet was queued (or dropped if too old)
            }
            RouterAction::SendTraffic { peer_id, traffic } => {
                // Use queuing logic for outbound traffic
                send_traffic_to_peer(peers, peer_id, traffic).await;
            }
            RouterAction::PathNotifyCallback { key } => {
                // Path notify callback handled by upper layer
                tracing::trace!("path notify for {:?}", key);
            }
            other => {
                if let Some((peer_id, frame)) = encode_action_frame(&other) {
                    let peers = peers.lock().await;
                    let _ = peers.send_to_peer(peer_id, PeerMessage::SendFrame(frame)).await;
                }
            }
        }
    }
}
