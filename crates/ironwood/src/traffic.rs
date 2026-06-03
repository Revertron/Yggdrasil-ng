//! Traffic packet and Deficit Round Robin (DRR) packet queue.
//!
//! The packet queue groups packets into flows keyed by (source, dest) and
//! schedules them with deficit round robin, giving long-term byte fairness
//! across flows (so many small packets can't starve fewer large ones). The
//! queue is hard-bounded in memory: a global byte cap and a per-flow byte cap,
//! enforced inside `push` by evicting the oldest packet from the largest flow.
//! Ported from Arceliar/ironwood PR #49.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap as HashMap;

use crate::crypto::PublicKey;
use crate::wire::PeerPort;

/// A user traffic packet routed through the network.
#[derive(Debug, Clone)]
pub(crate) struct TrafficPacket {
    pub path: Vec<PeerPort>,
    pub from: Vec<PeerPort>,
    pub source: PublicKey,
    pub dest: PublicKey,
    pub watermark: u64,
    pub payload: Vec<u8>,
}

impl TrafficPacket {
    pub fn new(source: PublicKey, dest: PublicKey, payload: Vec<u8>) -> Self {
        Self {
            path: Vec::new(),
            from: Vec::new(),
            source,
            dest,
            watermark: u64::MAX,
            payload,
        }
    }

    /// Estimated wire size of the packet (used for queue size accounting).
    pub fn wire_size(&self) -> u64 {
        use crate::crypto::PUBLIC_KEY_SIZE;
        use crate::wire::{path_size, uvarint_size};
        (path_size(&self.path)
            + path_size(&self.from)
            + PUBLIC_KEY_SIZE
            + PUBLIC_KEY_SIZE
            + uvarint_size(self.watermark)
            + self.payload.len()) as u64
    }

    /// Copy contents from another traffic packet, reusing existing allocations.
    #[cfg(test)]
    pub fn copy_from(&mut self, other: &TrafficPacket) {
        self.path.clear();
        self.path.extend_from_slice(&other.path);
        self.from.clear();
        self.from.extend_from_slice(&other.from);
        self.source = other.source;
        self.dest = other.dest;
        self.watermark = other.watermark;
        self.payload.clear();
        self.payload.extend_from_slice(&other.payload);
    }
}

// ---------------------------------------------------------------------------
// Packet queue: deficit round robin (DRR) scheduling, byte-bounded
// ---------------------------------------------------------------------------

/// Total queued bytes are capped at `quantum * this`.
const DEFAULT_PACKET_QUEUE_MAX_BYTES_MULTIPLIER: u64 = 16;
/// A single flow's queued bytes are capped at `quantum * this`.
const DEFAULT_PACKET_QUEUE_PER_FLOW_MULTIPLIER: u64 = 4;
/// Fallback quantum when constructed with `0` (matches Go's default message size).
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1024 * 1024;

/// Stable identity of a queued flow: the original sender and intended receiver.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    source: PublicKey,
    dest: PublicKey,
}

/// Info about a single queued packet.
struct PqPacketInfo {
    packet: TrafficPacket,
    size: u64,
    time: Instant,
}

/// A single flow's backlog plus its DRR scheduling state. The flow's identity
/// lives in the `PacketQueue::flows` map key and `active` ring, so it isn't
/// duplicated here.
struct Flow {
    /// FIFO packet backlog for this flow.
    infos: VecDeque<PqPacketInfo>,
    /// Total queued bytes currently held by this flow.
    size: u64,
    /// DRR credit used to decide which flow can send next.
    deficit: u64,
    /// Position in `PacketQueue::active`, or `None` when inactive.
    index: Option<usize>,
}

/// Deficit round robin packet queue.
///
/// Packets are grouped into flows keyed by (source, dest). `pop` serves flows
/// round-robin, granting each visited flow a byte `quantum` of credit and
/// emitting its head packet only when the credit covers it — giving long-term
/// byte fairness. `push` is hard-bounded: it caps total bytes and per-flow
/// bytes, evicting the oldest packet from the largest flow to make room.
pub(crate) struct PacketQueue {
    /// All known flows with a backlog, keyed by source/dest pair.
    flows: HashMap<FlowKey, Flow>,
    /// Flow keys that currently have queued packets (round-robin ring).
    active: Vec<FlowKey>,
    /// Round-robin cursor into `active`, `None` when there are no active flows.
    next: Option<usize>,
    /// Total queued bytes across all flows.
    size: u64,
    /// Hard cap for total queued bytes.
    max_bytes_total: u64,
    /// Hard cap for bytes a single flow may hold.
    max_bytes_per_flow: u64,
    /// DRR byte budget granted to a flow each round.
    quantum: u64,
}

impl PacketQueue {
    /// Create a queue whose DRR quantum (and byte caps) derive from `quantum`
    /// (the peer max message size). A `0` quantum falls back to the default.
    pub fn new(quantum: u64) -> Self {
        let quantum = if quantum == 0 {
            DEFAULT_MAX_MESSAGE_SIZE
        } else {
            quantum
        };
        Self {
            flows: HashMap::default(),
            active: Vec::new(),
            next: None,
            size: 0,
            max_bytes_total: quantum * DEFAULT_PACKET_QUEUE_MAX_BYTES_MULTIPLIER,
            max_bytes_per_flow: quantum * DEFAULT_PACKET_QUEUE_PER_FLOW_MULTIPLIER,
            quantum,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Mark a flow active by appending its key to the round-robin ring.
    fn activate(&mut self, key: FlowKey) {
        let idx = self.active.len();
        self.active.push(key);
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.index = Some(idx);
        }
    }

    /// Remove a flow from the round-robin ring, fixing up the cursor.
    fn deactivate(&mut self, key: FlowKey) {
        let idx = match self.flows.get(&key).and_then(|f| f.index) {
            Some(i) => i,
            None => return,
        };
        let last = self.active.len() - 1;
        if idx > last {
            return;
        }
        if idx != last {
            // Copy the key out before borrowing `flows` mutably.
            let moved = self.active[last];
            self.active[idx] = moved;
            if let Some(mf) = self.flows.get_mut(&moved) {
                mf.index = Some(idx);
            }
        }
        self.active.pop();
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.index = None;
        }
        if self.active.is_empty() {
            self.next = None;
            return;
        }
        if self.next == Some(last) {
            self.next = Some(idx);
        }
        if let Some(n) = self.next {
            if n >= self.active.len() {
                self.next = Some(0);
            }
        }
    }

    /// Get the flow for a packet, creating an inactive one if needed.
    fn flow_for(&mut self, key: FlowKey) -> &mut Flow {
        self.flows.entry(key).or_insert_with(|| Flow {
            infos: VecDeque::new(),
            size: 0,
            deficit: 0,
            index: None,
        })
    }

    /// Delete a flow once it has no backlog left (removing it from the ring).
    fn remove_flow_if_empty(&mut self, key: FlowKey) {
        let (empty, active) = match self.flows.get(&key) {
            Some(f) => (f.infos.is_empty(), f.index.is_some()),
            None => return,
        };
        if !empty {
            return;
        }
        if active {
            self.deactivate(key);
        }
        self.flows.remove(&key);
    }

    /// Remove and return the head packet of a specific flow.
    fn drop_from(&mut self, key: FlowKey) -> Option<PqPacketInfo> {
        // Hoist the deficit clamp before borrowing `flows` mutably.
        let deficit_cap = self.quantum * 4;
        let info = {
            let flow = self.flows.get_mut(&key)?;
            let info = flow.infos.pop_front()?;
            flow.size -= info.size;
            if flow.deficit > deficit_cap {
                flow.deficit = deficit_cap;
            }
            info
        };
        self.size -= info.size;
        self.remove_flow_if_empty(key);
        Some(info)
    }

    /// Find the active flow with the most queued bytes (oldest head breaks ties).
    fn largest_flow(&self) -> Option<FlowKey> {
        self.active
            .iter()
            .copied()
            .filter_map(|k| self.flows.get(&k).map(|f| (k, f)))
            .filter_map(|(k, f)| f.infos.front().map(|head| (k, f.size, head.time)))
            .max_by(|(_, s1, t1), (_, s2, t2)| s1.cmp(s2).then(t2.cmp(t1)))
            .map(|(k, _, _)| k)
    }

    /// Drop the oldest packet from the largest flow (for back-pressure).
    /// Returns true if a packet was dropped.
    pub fn drop_largest(&mut self) -> bool {
        match self.largest_flow() {
            Some(key) => self.drop_from(key).is_some(),
            None => false,
        }
    }

    /// Add a packet to the queue, hard-bounded globally and per flow.
    pub fn push(&mut self, packet: TrafficPacket) {
        let pkt_size = packet.wire_size();
        // Reject packets that could never fit within the caps.
        if pkt_size > self.max_bytes_total || pkt_size > self.max_bytes_per_flow {
            return;
        }
        let key = FlowKey {
            source: packet.source,
            dest: packet.dest,
        };
        let info = PqPacketInfo {
            packet,
            size: pkt_size,
            time: Instant::now(),
        };

        // Ensure the flow exists so we can measure it.
        self.flow_for(key);

        // Per-flow cap: evict this flow's oldest packets until the new one fits.
        loop {
            let (flow_size, flow_count) = match self.flows.get(&key) {
                Some(f) => (f.size, f.infos.len()),
                None => (0, 0),
            };
            if flow_size + pkt_size <= self.max_bytes_per_flow || flow_count == 0 {
                break;
            }
            if self.drop_from(key).is_none() {
                return;
            }
        }

        // Global cap: evict from the largest flow until the new packet fits.
        while self.size + pkt_size > self.max_bytes_total && self.size > 0 {
            if !self.drop_largest() {
                return;
            }
        }

        // The flow may have been deleted while making room; re-acquire it.
        let needs_activate = {
            let flow = self.flow_for(key);
            flow.infos.push_back(info);
            flow.size += pkt_size;
            flow.index.is_none()
        };
        self.size += pkt_size;
        if needs_activate {
            self.activate(key);
        }
    }

    /// Remove and return the next packet using deficit round robin across flows.
    fn pop_info(&mut self) -> Option<PqPacketInfo> {
        if self.is_empty() || self.active.is_empty() {
            self.next = None;
            return None;
        }

        let mut need_credit = false;
        match self.next {
            None => {
                self.next = Some(0);
                need_credit = true;
            }
            Some(n) if n >= self.active.len() => self.next = Some(0),
            Some(_) => {}
        }

        let quantum = self.quantum;
        let mut idx = self.next.unwrap();
        let mut key = self.active[idx];

        if need_credit {
            if let Some(flow) = self.flows.get_mut(&key) {
                flow.deficit += quantum;
            }
        }

        loop {
            let serveable = self
                .flows
                .get(&key)
                .and_then(|f| f.infos.front().map(|head| head.size <= f.deficit))
                .unwrap_or(false);
            if serveable {
                if let Some(info) = self.drop_from(key) {
                    if let Some(flow) = self.flows.get_mut(&key) {
                        flow.deficit -= info.size;
                    }
                    return Some(info);
                }
            }
            idx += 1;
            if idx >= self.active.len() {
                idx = 0;
            }
            self.next = Some(idx);
            key = self.active[idx];
            if let Some(flow) = self.flows.get_mut(&key) {
                flow.deficit += quantum;
            }
        }
    }

    /// Remove and return the next packet (DRR order).
    pub fn pop(&mut self) -> Option<TrafficPacket> {
        self.pop_info().map(|info| info.packet)
    }

    /// Get the total queued bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Get the age of the oldest packet in the queue (oldest head across flows).
    pub fn oldest_age(&self) -> Option<Duration> {
        self.active
            .iter()
            .filter_map(|k| self.flows.get(k))
            .filter_map(|f| f.infos.front())
            .map(|info| info.time)
            .min()
            .map(|time| time.elapsed())
    }
}

/// Maximum age for queued packets before they are dropped (25 milliseconds).
const MAX_PACKET_AGE: Duration = Duration::from_millis(25);

/// DeliveryQueue manages the packet queue with receive-ready counting.
/// Packets are queued when no reader is waiting, and sent directly when a
/// reader is ready. The queue is guarded by a sync mutex because every
/// critical section is short and contains no `.await`.
pub(crate) struct DeliveryQueue {
    /// The underlying packet queue.
    queue: std::sync::Mutex<PacketQueue>,
    /// Number of readers waiting (atomic for lock-free check).
    recv_ready: AtomicUsize,
}

impl DeliveryQueue {
    pub fn new(quantum: u64) -> Arc<Self> {
        Arc::new(Self {
            queue: std::sync::Mutex::new(PacketQueue::new(quantum)),
            recv_ready: AtomicUsize::new(0),
        })
    }

    /// Attempt to deliver a packet. Returns Some(packet) if a reader is waiting
    /// (in which case the caller should send it via channel), or None if the
    /// packet was queued (or dropped due to age).
    pub fn deliver(&self, packet: TrafficPacket) -> Option<TrafficPacket> {
        // Fast path: check if a reader is waiting
        if self.recv_ready.load(Ordering::Acquire) > 0 {
            // Decrement recv_ready and return packet for immediate send
            self.recv_ready.fetch_sub(1, Ordering::AcqRel);
            return Some(packet);
        }

        // Slow path: queue the packet
        let mut queue = self.queue.lock().unwrap();

        // Check if the oldest packet is too old (>25ms), if so drop it
        if let Some(age) = queue.oldest_age() {
            if age > MAX_PACKET_AGE {
                queue.drop_largest();
                tracing::debug!("Dropped oldest packet from queue (age > 25ms)");
            }
        }

        queue.push(packet);
        None
    }

    /// Get the current number of bytes queued (snapshot).
    pub fn queue_size(&self) -> u64 {
        self.queue.lock().unwrap().size()
    }

    /// Called by read_from() before waiting on channel. Returns Some(packet)
    /// if one is already queued, or None if the reader should wait (recv_ready incremented).
    pub fn try_pop_or_wait(&self) -> Option<TrafficPacket> {
        let mut queue = self.queue.lock().unwrap();

        if let Some(packet) = queue.pop() {
            // Packet was queued, return it immediately
            Some(packet)
        } else {
            // No packet queued, increment recv_ready to signal we're waiting
            self.recv_ready.fetch_add(1, Ordering::AcqRel);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(src: u8, dst: u8, payload: &[u8]) -> TrafficPacket {
        TrafficPacket {
            path: Vec::new(),
            from: Vec::new(),
            source: [src; 32],
            dest: [dst; 32],
            watermark: u64::MAX,
            payload: payload.to_vec(),
        }
    }

    /// A queue with a large (1 MB) quantum: byte caps are far out of reach, so
    /// these tests exercise only scheduling, not eviction.
    fn big_queue() -> PacketQueue {
        PacketQueue::new(1024 * 1024)
    }

    #[test]
    fn push_and_pop() {
        let mut q = big_queue();
        q.push(make_packet(1, 2, b"hello"));
        q.push(make_packet(3, 4, b"world"));
        assert!(!q.is_empty());

        let p1 = q.pop().unwrap();
        assert_eq!(p1.payload, b"hello");
        let p2 = q.pop().unwrap();
        assert_eq!(p2.payload, b"world");
        assert!(q.is_empty());
        assert!(q.pop().is_none());
    }

    #[test]
    fn drop_largest_removes_from_biggest_flow() {
        let mut q = big_queue();
        // Flow A->B: 3 packets
        q.push(make_packet(1, 2, &[0; 100]));
        q.push(make_packet(1, 2, &[0; 100]));
        q.push(make_packet(1, 2, &[0; 100]));
        // Flow C->D: 1 packet
        q.push(make_packet(3, 4, &[0; 100]));

        // Should drop from the larger flow (A->B)
        assert!(q.drop_largest());
        // After drop: A->B has 2, C->D has 1 => 3 total
        // Pop all remaining
        let mut count = 0;
        while q.pop().is_some() {
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn same_dest_different_sources() {
        let mut q = big_queue();
        q.push(make_packet(1, 10, b"a"));
        q.push(make_packet(2, 10, b"b"));
        q.push(make_packet(3, 10, b"c"));

        // All go to dest 10, from different sources
        let p1 = q.pop().unwrap();
        assert_eq!(p1.payload, b"a");
        let p2 = q.pop().unwrap();
        assert_eq!(p2.payload, b"b");
        let p3 = q.pop().unwrap();
        assert_eq!(p3.payload, b"c");
    }

    #[test]
    fn copy_from_reuses_allocations() {
        let mut p1 = TrafficPacket::new([1; 32], [2; 32], b"original".to_vec());
        p1.path = vec![10, 20, 30];
        let p2 = TrafficPacket::new([3; 32], [4; 32], b"copy target".to_vec());

        p1.copy_from(&p2);
        assert_eq!(p1.source, [3; 32]);
        assert_eq!(p1.payload, b"copy target");
        assert!(p1.path.is_empty());
    }

    #[test]
    fn drr_round_robin_fairness() {
        // Quantum sized just above one packet means one round of credit serves
        // exactly one packet, so the scheduler must alternate between two flows
        // that both have a backlog (old FIFO would drain one flow fully first).
        let w = make_packet(1, 2, &[0u8; 1000]).wire_size();
        let mut q = PacketQueue::new(w + 1);

        // Flow A (source 1) and flow C (source 3), both to dest 2, 4 packets each.
        for _ in 0..4 {
            q.push(make_packet(1, 2, &[0u8; 1000]));
        }
        for _ in 0..4 {
            q.push(make_packet(3, 2, &[0u8; 1000]));
        }

        let mut sources = Vec::new();
        while let Some(p) = q.pop() {
            sources.push(p.source[0]);
        }

        assert_eq!(sources.len(), 8);
        // Strict alternation, starting with the first-activated flow (source 1).
        for (i, s) in sources.iter().enumerate() {
            let expected = if i % 2 == 0 { 1 } else { 3 };
            assert_eq!(*s, expected, "position {i}: expected source {expected}");
        }
    }

    #[test]
    fn per_flow_byte_cap_eviction() {
        // Small quantum => small per-flow cap; flood ONE flow past it.
        let mut q = PacketQueue::new(1024);
        let cap = q.max_bytes_per_flow;

        // Tag each packet's payload[0] with a sequence number 0..N.
        const N: u8 = 40;
        for i in 0..N {
            let mut payload = vec![0u8; 200];
            payload[0] = i;
            q.push(make_packet(1, 2, &payload));
            // The per-flow cap must hold after every push.
            assert!(q.size() <= cap, "flow exceeded per-flow cap after push {i}");
        }

        // Survivors are the most-recently pushed packets (oldest evicted, FIFO),
        // in order, ending at the last tag (N-1).
        let mut tags = Vec::new();
        while let Some(p) = q.pop() {
            tags.push(p.payload[0]);
        }
        assert!(!tags.is_empty());
        assert_eq!(*tags.last().unwrap(), N - 1, "newest packet must survive");
        assert!(tags[0] > 0, "oldest packets must have been evicted");
        // Contiguous ascending run (no reordering, no gaps among survivors).
        for win in tags.windows(2) {
            assert_eq!(win[1], win[0] + 1, "survivors must stay FIFO-ordered");
        }
    }

    #[test]
    fn total_byte_cap_eviction_drops_largest() {
        // Small quantum => small total cap. A tiny flow plus several big flows
        // that together overflow the total cap; eviction must target the big
        // flows, never the tiny one.
        let mut q = PacketQueue::new(1024);
        let total_cap = q.max_bytes_total;

        // Tiny flow S: source 100 -> dest 200, one small packet.
        q.push(make_packet(100, 200, &[7u8; 10]));

        // Five big flows (sources 1..=5 -> dest 2), enough 500-byte packets to
        // blow past the total cap even after per-flow trimming.
        for src in 1u8..=5 {
            for _ in 0..8 {
                q.push(make_packet(src, 2, &[0u8; 500]));
                assert!(q.size() <= total_cap, "total cap exceeded");
            }
        }

        // The tiny flow's packet must still be present (largest flows dropped).
        let mut saw_small = false;
        while let Some(p) = q.pop() {
            if p.source[0] == 100 {
                saw_small = true;
            }
        }
        assert!(saw_small, "small flow's packet should survive global eviction");
    }

    #[test]
    fn oversized_packet_rejected() {
        // A packet larger than the per-flow cap can never fit and is rejected.
        let mut q = PacketQueue::new(1024); // per-flow cap = 4096
        q.push(make_packet(1, 2, &[0u8; 5000]));
        assert!(q.is_empty());
        assert_eq!(q.size(), 0);
        assert!(q.pop().is_none());
    }
}
