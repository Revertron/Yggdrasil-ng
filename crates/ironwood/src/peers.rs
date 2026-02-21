//! Peer connection management.
//!
//! Each peer connection spawns two tokio tasks:
//! - **Reader task**: reads frames from the connection, decodes messages,
//!   dispatches to the router via the shared state mutex.
//! - **Writer task**: receives outbound frames via an mpsc channel,
//!   writes them with buffered I/O, manages keepalive and deadlines.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, BufReader};
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
    /// Schedule a keepalive to be sent after the delay (unless cancelled by sending other traffic).
    ScheduleKeepalive,
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
    /// Ports allocated to peer keys (port → key).
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

        // Reuse port if we already have a peer with this key.
        // Otherwise scan from 1 for the lowest free port (matches Go's linear search).
        let port = if let Some(existing) = self.handles.get(&key) {
            existing.values().next().map(|h| h.port).unwrap_or_else(|| {
                self.alloc_port()
            })
        } else {
            self.alloc_port()
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

    /// Scan from 1 upward and return the lowest port not currently in use.
    /// Matches Go's linear search behavior: freed ports are reused on reconnection.
    fn alloc_port(&mut self) -> PeerPort {
        let mut p: PeerPort = 1; // skip 0 (reserved for root)
        while self.used_ports.contains_key(&p) {
            p += 1;
        }
        p
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

/// Maximum age for queued packets before applying backpressure (25ms, matches Go).
const MAX_PACKET_AGE_SEND: Duration = Duration::from_millis(25);

/// Send traffic to a peer with backpressure.
/// Implements Go's peers.go _push() method:
/// 1. Try immediate send (if writer is ready)
/// 2. If busy, check queue age - drop oldest from largest flow if >25ms
/// 3. Queue the packet
async fn send_traffic_to_peer(peers: &Arc<tokio::sync::Mutex<Peers>>, peer_id: PeerId, traffic: TrafficPacket) {
    let peers_lock = peers.lock().await;

    // Find the peer handle
    let handle = match peers_lock.get_handle(peer_id) {
        Some(h) => h,
        None => {
            drop(peers_lock);
            return;
        }
    };

    let tx = handle.tx.clone();
    let traffic_queue = handle.traffic_queue.clone();

    // Encode the traffic frame in one allocation (no intermediate buffer, no clones).
    let frame = wire::encode_traffic_frame(
        &traffic.path, &traffic.from,
        &traffic.source, &traffic.dest,
        traffic.watermark, &traffic.payload,
    );
    let msg = PeerMessage::SendFrame(frame);

    // Drop peers_lock before channel operations
    drop(peers_lock);

    // Try non-blocking send first (fast path - writer ready)
    match tx.try_send(msg) {
        Ok(_) => {
            // Fast path: sent immediately, writer is ready
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            // Check if oldest packet in queue is too old (>25ms)
            // If so, drop the oldest packet from the largest flow (backpressure)
            let mut queue = traffic_queue.lock().await;
            if let Some(age) = queue.oldest_age() {
                if age > MAX_PACKET_AGE_SEND {
                    if queue.drop_largest() {
                        tracing::warn!(
                            "send_traffic_to_peer[{}]: dropped oldest packet (age={:?} > 25ms) - backpressure applied",
                            peer_id,
                            age
                        );
                    }
                }
            }

            // Queue the new packet
            queue.push(traffic);
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
            let frame = wire::encode_traffic_frame(
                &traffic.path, &traffic.from,
                &traffic.source, &traffic.dest,
                traffic.watermark, &traffic.payload,
            );
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
/// Returns Ok(()) for clean shutdown, Err with disconnect reason otherwise.
/// Shared peer timeout state between writer and reader.
/// Writer sets the deadline when it sends a non-keepalive frame.
/// Reader clears it when it receives any frame.
pub(crate) type ReadDeadline = Arc<std::sync::Mutex<Option<std::time::Instant>>>;

pub(crate) async fn peer_reader(
    peer_id: PeerId,
    peer_key: PublicKey,
    our_key: PublicKey,
    conn_read: impl tokio::io::AsyncRead + Unpin + Send,
    router: Arc<tokio::sync::Mutex<Router>>,
    peers: Arc<tokio::sync::Mutex<Peers>>,
    delivery_queue: Arc<crate::traffic::DeliveryQueue>,
    traffic_tx: mpsc::Sender<TrafficPacket>,
    writer_tx: mpsc::Sender<PeerMessage>,
    cancel: CancellationToken,
    max_message_size: u64,
    peer_timeout: Duration,
    _keepalive_delay: Duration,
    path_notify_cb: Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
    read_deadline: ReadDeadline,
) -> Result<(), Error> {
    // Use a larger BufReader to reduce syscall count on high-throughput connections.
    let mut reader = BufReader::with_capacity(128 * 1024, conn_read);
    let mut disconnect_reason: Option<Error> = None;

    // Reusable frame buffer: grows to the largest frame seen, then stays.
    // Eliminates one heap allocation per incoming frame.
    let mut buf: Vec<u8> = Vec::with_capacity(16384);

    loop {
        // Read frame: length(uvarint) | content.
        // Wake every 1 second to check whether the writer-set deadline has
        // elapsed (matches Go's SetReadDeadline approach: writer arms 3s
        // deadline on non-keepalive sends; reader clears on any receive).
        let frame_result = tokio::select! {
            _ = cancel.cancelled() => { break },
            result = read_uvarint(&mut reader) => result,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                let deadline = *read_deadline.lock().unwrap();
                if let Some(d) = deadline {
                    if std::time::Instant::now() >= d {
                        tracing::info!("peer_reader[{}]: peer timeout ({}ms, no reply from {:02x?}), disconnecting",
                            peer_id, peer_timeout.as_millis(), &peer_key[..8]);
                        disconnect_reason = Some(Error::Timeout);
                        break;
                    }
                }
                continue;
            }
        };

        // Any received frame clears the deadline (peer is alive).
        *read_deadline.lock().unwrap() = None;

        let frame_len = match frame_result {
            Ok(len) => len,
            Err(e) => {
                disconnect_reason = Some(e.into());
                break;
            },
        };

        if frame_len > max_message_size {
            disconnect_reason = Some(Error::OversizedMessage);
            break;
        }

        buf.resize(frame_len as usize, 0);
        let read_result = tokio::select! {
            _ = cancel.cancelled() => { break },
            result = reader.read_exact(&mut buf) => result,
        };

        if let Err(e) = read_result {
            disconnect_reason = Some(e.into());
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
                tracing::warn!("peer_reader[{}]: unknown packet type {}, skipping", peer_id, ptype_byte);
                continue;
            }
        };

        tracing::debug!("peer_reader[{}]: received {:?} frame, {} bytes payload", peer_id, ptype, payload.len());

        // Track whether we should schedule a keepalive response
        let should_schedule_keepalive = !matches!(ptype, wire::PacketType::Dummy | wire::PacketType::KeepAlive);

        // Dispatch based on message type
        match ptype {
            wire::PacketType::Dummy | wire::PacketType::KeepAlive => {
                // No-op, just resets deadline
            }
            wire::PacketType::ProtoSigReq => {
                let mut r = wire::WireReader::new(payload);
                let req = match wire::SigReq::decode(&mut r) {
                    Ok(req) => req,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
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
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
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
                    disconnect_reason = Some(Error::BadMessage);
                    break;
                }
                let mut router = router.lock().await;
                router.handle_response(peer_id, &peer_key, &res);
            }
            wire::PacketType::ProtoAnnounce => {
                let ann = match wire::Announce::decode(payload) {
                    Ok(a) => a,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
                };
                let router_ann = RouterAnnounce::from_wire(&ann);
                if !router_ann.check() {
                    disconnect_reason = Some(Error::BadMessage);
                    break;
                }
                let mut router = router.lock().await;
                let actions = router.handle_announce(peer_id, &peer_key, &router_ann);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
            }
            wire::PacketType::ProtoBloomFilter => {
                let raw = match wire::decode_bloom(payload) {
                    Ok(r) => r,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
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
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
                };
                let mut router = router.lock().await;
                let actions = router.handle_lookup(&peer_key, &lookup);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
            }
            wire::PacketType::ProtoPathNotify => {
                let notify = match wire::PathNotify::decode(payload) {
                    Ok(n) => n,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
                };
                let mut router = router.lock().await;
                let actions = router.handle_notify(&peer_key, &notify);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
            }
            wire::PacketType::ProtoPathBroken => {
                let broken = match wire::PathBroken::decode(payload) {
                    Ok(b) => b,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
                };
                let mut router = router.lock().await;
                let actions = router.handle_broken(&broken);
                drop(router);
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
            }
            wire::PacketType::Traffic => {
                let tr = match wire::Traffic::decode(payload) {
                    Ok(t) => t,
                    Err(_) => {
                        disconnect_reason = Some(Error::Decode);
                        break;
                    },
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
                dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
            }
        }

        // After processing non-keepalive traffic, schedule a keepalive response.
        // Use try_send (non-blocking): if the writer channel is full the peer is
        // already actively receiving frames, so a keepalive isn't urgent, and we
        // must not stall the reader waiting for channel space.
        if should_schedule_keepalive {
            let _ = writer_tx.try_send(PeerMessage::ScheduleKeepalive);
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

        dispatch_actions(actions, &peers, &delivery_queue, &traffic_tx, &path_notify_cb).await;
    }

    cancel.cancel();

    // Return the disconnect reason (None = clean shutdown)
    match disconnect_reason {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Write timeout for slow peers (10 seconds).
/// If a write takes longer than this, the peer is considered stalled.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of the BufWriter buffer for each peer writer (128 KB).
/// Outbound frames accumulate here; a single flush() drains to the OS per burst.
const WRITE_BUF_SIZE: usize = 128 * 1024;

/// Maximum packets drained from the traffic queue per writer loop iteration.
/// After this many packets the writer yields back to the event loop, allowing
/// other channel messages (routing frames, keepalives, other peers) to be
/// processed before the next drain burst. This limits how long a single heavy
/// stream can monopolize the writer without starving lighter flows.
const MAX_DRAIN_PER_ITER: usize = 96;

/// Drain queued traffic packets and send them with timeout.
/// This is called by peer_writer after successfully writing a frame.
/// Drains at most MAX_DRAIN_PER_ITER packets per call so the writer yields
/// back to the event loop periodically, preventing a heavy stream from
/// blocking other channel messages indefinitely.
/// Returns false if write failed or timed out, true otherwise.
async fn drain_traffic_queue<W: tokio::io::AsyncWrite + Unpin>(
    peer_id: PeerId,
    queue: &Arc<tokio::sync::Mutex<PacketQueue>>,
    writer: &mut W,
    peer_timeout: Duration,
    read_deadline: &ReadDeadline,
) -> bool {
    use tokio::io::AsyncWriteExt;
    for _ in 0..MAX_DRAIN_PER_ITER {
        // Try to pop a packet from the queue
        let traffic = {
            let mut q = queue.lock().await;
            q.pop()
        };

        let traffic = match traffic {
            Some(t) => t,
            None => return true, // Queue is empty, success
        };

        let frame = wire::encode_traffic_frame(
            &traffic.path, &traffic.from,
            &traffic.source, &traffic.dest,
            traffic.watermark, &traffic.payload,
        );

        // Write the frame with timeout
        let write_result = tokio::time::timeout(
            WRITE_TIMEOUT,
            writer.write_all(&frame)
        ).await;

        match write_result {
            Ok(Ok(_)) => {
                tracing::debug!("peer_writer[{}]: sent queued traffic", peer_id);
                // Traffic packets are always non-keepalive — arm read deadline
                *read_deadline.lock().unwrap() = Some(std::time::Instant::now() + peer_timeout);
            }
            Ok(Err(e)) => {
                tracing::debug!("peer_writer[{}]: write error for queued traffic: {}", peer_id, e);
                return false;
            }
            Err(_) => {
                tracing::debug!("peer_writer[{}]: write timeout ({:?}) for queued traffic - slow peer detected", peer_id, WRITE_TIMEOUT);
                return false;
            }
        }
    }
    // Drained MAX_DRAIN_PER_ITER packets; yield back to the event loop.
    true
}

/// The peer writer task. Receives frames and writes them to the connection.
/// After writing each frame, it drains queued traffic packets.
///
/// Keepalive behavior (matches Go implementation):
/// - Only send keepalives AFTER receiving non-keepalive traffic
/// - Schedule keepalive timer when ScheduleKeepalive message is received
/// - Cancel keepalive timer when sending any frame
pub(crate) async fn peer_writer(
    peer_id: PeerId,
    mut rx: mpsc::Receiver<PeerMessage>,
    conn_write: impl tokio::io::AsyncWrite + Unpin + Send,
    traffic_queue: Arc<tokio::sync::Mutex<PacketQueue>>,
    _keepalive_delay: Duration,
    peer_timeout: Duration,
    read_deadline: ReadDeadline,
    cancel: CancellationToken,
) {
    use crate::wire;
    use tokio::io::AsyncWriteExt;

    // Wrap in BufWriter: individual write_all calls go to memory; flush() issues
    // one syscall per burst rather than one per frame.
    let mut conn_write = tokio::io::BufWriter::with_capacity(WRITE_BUF_SIZE, conn_write);

    // Pre-encode keepalive frame
    let keepalive_frame = wire::encode_frame(wire::PacketType::KeepAlive, &[]);

    // Optional keepalive deadline (None = no keepalive scheduled)
    let mut keepalive_deadline: Option<std::pin::Pin<Box<tokio::time::Sleep>>> = None;

    loop {
        let msg = if let Some(ref mut deadline) = keepalive_deadline {
            // Keepalive is scheduled, wait for it or a message
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => msg,
                _ = deadline => {
                    // Keepalive timer fired, send keepalive
                    keepalive_deadline = None; // Clear the deadline

                    // Write keepalive with timeout
                    let write_result = tokio::time::timeout(
                        WRITE_TIMEOUT,
                        conn_write.write_all(&keepalive_frame)
                    ).await;

                    if write_result.is_err() || write_result.unwrap().is_err() {
                        tracing::debug!("peer_writer[{}]: keepalive write failed or timed out", peer_id);
                        break;
                    }

                    // Flush with timeout
                    let flush_result = tokio::time::timeout(
                        WRITE_TIMEOUT,
                        conn_write.flush()
                    ).await;

                    if flush_result.is_err() || flush_result.unwrap().is_err() {
                        tracing::debug!("peer_writer[{}]: keepalive flush failed or timed out", peer_id);
                        break;
                    }
                    continue;
                },
            }
        } else {
            // No keepalive scheduled, just wait for messages
            tokio::select! {
                _ = cancel.cancelled() => break,
                msg = rx.recv() => msg,
            }
        };

        let msg = match msg {
            Some(m) => m,
            None => break,
        };

        match msg {
            PeerMessage::SendFrame(data) => {
                // Cancel any pending keepalive (we're sending traffic)
                keepalive_deadline = None;

                // Log outgoing frame type for diagnostics
                if let Some(ptype) = peek_frame_type(&data) {
                    tracing::debug!("peer_writer[{}]: sending {:?} frame, {} bytes", peer_id, ptype, data.len());
                }

                // Write with timeout to detect slow peers
                let write_result = tokio::time::timeout(
                    WRITE_TIMEOUT,
                    conn_write.write_all(&data)
                ).await;

                match write_result {
                    Ok(Ok(_)) => {
                        // Arm the read deadline for any non-keepalive frame.
                        // Matches Go's SetReadDeadline(now + peerTimeout) on non-keepalive writes.
                        if let Some(ptype) = peek_frame_type(&data) {
                            if !matches!(ptype, wire::PacketType::KeepAlive | wire::PacketType::Dummy) {
                                *read_deadline.lock().unwrap() = Some(std::time::Instant::now() + peer_timeout);
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("peer_writer[{}]: write error: {}", peer_id, e);
                        break;
                    }
                    Err(_) => {
                        tracing::debug!("peer_writer[{}]: write timeout ({:?}) - slow peer detected, disconnecting", peer_id, WRITE_TIMEOUT);
                        break;
                    }
                }

                // After successfully writing, drain queued traffic (with timeout)
                if !drain_traffic_queue(peer_id, &traffic_queue, &mut conn_write, peer_timeout, &read_deadline).await {
                    tracing::debug!("peer_writer[{}]: failed to drain traffic queue, disconnecting", peer_id);
                    break;
                }

                // Flush with timeout
                let flush_result = tokio::time::timeout(
                    WRITE_TIMEOUT,
                    conn_write.flush()
                ).await;

                match flush_result {
                    Ok(Ok(_)) => {
                        // Flush succeeded
                    }
                    Ok(Err(e)) => {
                        tracing::debug!("peer_writer[{}]: flush error: {}", peer_id, e);
                        break;
                    }
                    Err(_) => {
                        tracing::debug!("peer_writer[{}]: flush timeout ({:?}) - slow peer detected, disconnecting", peer_id, WRITE_TIMEOUT);
                        break;
                    }
                }
            }
            PeerMessage::ScheduleKeepalive => {
                // Schedule a keepalive to be sent after keepalive_delay
                // (unless we send other traffic first, which will cancel it)
                if keepalive_deadline.is_none() {
                    keepalive_deadline = Some(Box::pin(tokio::time::sleep(Duration::from_millis(100))));
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
    path_notify_cb: &Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
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
                if let Some(cb) = path_notify_cb {
                    cb(key);
                }
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
