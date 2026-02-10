//! Traffic packet and fair packet queue.
//!
//! The packet queue organizes packets by destination and source,
//! providing fair scheduling across flows. When dropping, it removes
//! the oldest packet from the largest source within the largest destination.

use std::time::Instant;

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
// Packet queue: fair per-destination, per-source scheduling
// ---------------------------------------------------------------------------

/// Info about a single queued packet.
struct PqPacketInfo {
    packet: TrafficPacket,
    size: u64,
    time: Instant,
}

/// Packets from a single source to a single destination.
struct PqSource {
    key: PublicKey,
    infos: Vec<PqPacketInfo>,
    size: u64,
}

/// All packets to a single destination, grouped by source.
struct PqDest {
    key: PublicKey,
    sources: Vec<PqSource>,
    size: u64,
}

/// Fair packet queue: organizes by destination, then source.
///
/// - `push` adds a packet
/// - `pop` removes the oldest packet across all flows (min-time at front)
/// - `drop` removes the oldest packet from the largest flow (back-pressure fairness)
pub(crate) struct PacketQueue {
    dests: Vec<PqDest>,
    size: u64,
}

impl PacketQueue {
    pub fn new() -> Self {
        Self {
            dests: Vec::new(),
            size: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Add a packet to the queue.
    pub fn push(&mut self, packet: TrafficPacket) {
        let s_key = packet.source;
        let d_key = packet.dest;
        let pkt_size = packet.wire_size();
        let info = PqPacketInfo {
            packet,
            size: pkt_size,
            time: Instant::now(),
        };

        // Find or create dest entry
        let d_idx = self
            .dests
            .iter()
            .position(|d| d.key == d_key);

        let dest = if let Some(idx) = d_idx {
            &mut self.dests[idx]
        } else {
            self.dests.push(PqDest {
                key: d_key,
                sources: Vec::new(),
                size: 0,
            });
            self.dests.last_mut().unwrap()
        };

        // Find or create source entry within dest
        let s_idx = dest
            .sources
            .iter()
            .position(|s| s.key == s_key);

        let source = if let Some(idx) = s_idx {
            &mut dest.sources[idx]
        } else {
            dest.sources.push(PqSource {
                key: s_key,
                infos: Vec::new(),
                size: 0,
            });
            dest.sources.last_mut().unwrap()
        };

        source.infos.push(info);
        source.size += pkt_size;
        dest.size += pkt_size;
        self.size += pkt_size;
    }

    /// Remove and return the oldest packet across all flows.
    pub fn pop(&mut self) -> Option<TrafficPacket> {
        if self.is_empty() {
            return None;
        }

        // Find dest with the oldest front packet
        let d_idx = self
            .dests
            .iter()
            .enumerate()
            .min_by_key(|(_, d)| d.sources.iter().map(|s| s.infos[0].time).min().unwrap())
            .map(|(i, _)| i)?;

        let dest = &mut self.dests[d_idx];

        // Find source within that dest with oldest front packet
        let s_idx = dest
            .sources
            .iter()
            .enumerate()
            .min_by_key(|(_, s)| s.infos[0].time)
            .map(|(i, _)| i)
            .unwrap();

        let source = &mut dest.sources[s_idx];
        let info = source.infos.remove(0);
        source.size -= info.size;
        dest.size -= info.size;
        self.size -= info.size;

        // Clean up empty entries
        if source.infos.is_empty() {
            dest.sources.swap_remove(s_idx);
        }
        if dest.sources.is_empty() {
            self.dests.swap_remove(d_idx);
        }

        Some(info.packet)
    }

    /// Drop the oldest packet from the largest flow (for back-pressure).
    /// Returns true if a packet was dropped.
    pub fn drop_largest(&mut self) -> bool {
        if self.is_empty() {
            return false;
        }

        // Find the largest dest
        let d_idx = self
            .dests
            .iter()
            .enumerate()
            .max_by_key(|(_, d)| d.size)
            .map(|(i, _)| i)
            .unwrap();

        let dest = &mut self.dests[d_idx];

        // Find the largest source within that dest
        let s_idx = dest
            .sources
            .iter()
            .enumerate()
            .max_by_key(|(_, s)| s.size)
            .map(|(i, _)| i)
            .unwrap();

        let source = &mut dest.sources[s_idx];
        let info = source.infos.remove(0);
        source.size -= info.size;
        dest.size -= info.size;
        self.size -= info.size;

        if source.infos.is_empty() {
            dest.sources.swap_remove(s_idx);
        }
        if dest.sources.is_empty() {
            self.dests.swap_remove(d_idx);
        }

        true
    }

    /// Peek at the oldest packet without removing it.
    pub fn peek(&self) -> Option<&TrafficPacket> {
        if self.dests.is_empty() {
            return None;
        }
        // Find the oldest across all dests/sources
        self.dests
            .iter()
            .flat_map(|d| d.sources.iter())
            .flat_map(|s| s.infos.first())
            .min_by_key(|info| info.time)
            .map(|info| &info.packet)
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

    #[test]
    fn push_and_pop() {
        let mut q = PacketQueue::new();
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
        let mut q = PacketQueue::new();
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
        let mut q = PacketQueue::new();
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
}
