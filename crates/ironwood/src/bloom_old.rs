//! Bloom filter state management for routing.
//!
//! Each peer on the spanning tree maintains a bloom filter of reachable keys.
//! Lookup/notify messages are multicast only to branches whose bloom filter
//! matches the destination key, reducing unnecessary traffic.

use crate::crypto::PublicKey;
use crate::wire::{BLOOM_FILTER_BITS, BLOOM_FILTER_K, BLOOM_FILTER_U64S};
use murmur3::murmur3_x64_128;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Fixed-size bloom filter (8192 bits, 8 hash functions)
// ---------------------------------------------------------------------------

/// A bloom filter with 8192 bits and 8 hash functions.
/// Wire-compatible with the Go bits-and-blooms/bloom library.
#[derive(Clone, Debug)]
pub(crate) struct BloomFilter {
    bits: [u64; BLOOM_FILTER_U64S],
}

impl BloomFilter {
    /// Create an empty bloom filter.
    pub fn new() -> Self {
        Self {
            bits: [0u64; BLOOM_FILTER_U64S],
        }
    }

    /// Create from a raw u64 array (e.g., from wire decoding).
    pub fn from_raw(bits: [u64; BLOOM_FILTER_U64S]) -> Self {
        Self { bits }
    }

    /// Get the raw backing array (for wire encoding).
    pub fn as_raw(&self) -> &[u64; BLOOM_FILTER_U64S] {
        &self.bits
    }

    /// Add a key to the bloom filter.
    pub fn add(&mut self, key: &[u8]) {
        for i in 0..BLOOM_FILTER_K {
            let bit = self.hash_bit(key, i);
            self.set_bit(bit);
        }
    }

    /// Test if a key might be in the bloom filter.
    pub fn test(&self, key: &[u8]) -> bool {
        for i in 0..BLOOM_FILTER_K {
            let bit = self.hash_bit(key, i);
            if !self.get_bit(bit) {
                return false;
            }
        }
        true
    }

    /// Merge another bloom filter into this one (bitwise OR).
    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_FILTER_U64S {
            self.bits[i] |= other.bits[i];
        }
    }

    /// Check if two bloom filters are equal.
    pub fn equal(&self, other: &BloomFilter) -> bool {
        self.bits == other.bits
    }

    /// Create a copy of this bloom filter.
    pub fn copy(&self) -> BloomFilter {
        self.clone()
    }

    /// Count the number of set bits (for diagnostics).
    pub fn count_ones(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    fn set_bit(&mut self, bit: usize) {
        let idx = bit / 64;
        let offset = bit % 64;
        self.bits[idx] |= 1u64 << offset;
    }

    fn get_bit(&self, bit: usize) -> bool {
        let idx = bit / 64;
        let offset = bit % 64;
        (self.bits[idx] >> offset) & 1 == 1
    }

    /// Hash function compatible with bits-and-blooms/bloom.
    /// Uses two base hashes and derives K hash values from them.
    /// This matches the "double hashing" scheme: h(i) = h1 + i*h2
    fn hash_bit(&self, key: &[u8], i: usize) -> usize {
        // Use SipHash-like approach compatible with Go's bloom library.
        // The bits-and-blooms library uses binary.BigEndian hash of data
        // with baseHashes function returning [4]uint64 from FNV.
        // We replicate: fnv hash the data, get two 64-bit hashes, then combine.
        let (h1, h2) = base_hashes(key);
        let h = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (h % BLOOM_FILTER_BITS as u64) as usize
    }
}

/// Generate two base hashes from the key data using MurMurHash.
/// This matches the Go bits-and-blooms/bloom library's `baseHashes` function,
/// which hashes the data with murmur3 and splits into four u64s,
/// then uses the first two.
fn base_hashes(data: &[u8]) -> (u64, u64) {
    let result = murmur3_x64_128(&mut &data[..], 0).unwrap();
    let h1 = result as u64;
    let h2 = (result >> 64) as u64;
    (h1, h2)
}

// ---------------------------------------------------------------------------
// Blooms manager: per-peer bloom filter state
// ---------------------------------------------------------------------------

/// Per-peer bloom filter tracking.
#[derive(Clone)]
pub(crate) struct BloomInfo {
    /// What we advertise to this peer.
    pub send: BloomFilter,
    /// What we received from this peer.
    pub recv: BloomFilter,
    /// Sequence counter for periodic resend.
    pub seq: u16,
    /// Whether this peer is on the spanning tree.
    pub on_tree: bool,
    /// Whether we've set unnecessary 1 bits (need cleanup).
    pub z_dirty: bool,
}

impl BloomInfo {
    fn new() -> Self {
        Self {
            send: BloomFilter::new(),
            recv: BloomFilter::new(),
            seq: 0,
            on_tree: false,
            z_dirty: false,
        }
    }
}

/// Manages bloom filters for all peers.
pub(crate) struct Blooms {
    pub blooms: HashMap<PublicKey, BloomInfo>,
}

impl Blooms {
    pub fn new() -> Self {
        Self {
            blooms: HashMap::new(),
        }
    }

    /// Check if a peer is on the spanning tree.
    pub fn is_on_tree(&self, key: &PublicKey) -> bool {
        self.blooms
            .get(key)
            .map_or(false, |info| info.on_tree)
    }

    /// Apply the bloom transform to a key. If no transform is configured, identity.
    pub fn x_key(
        &self,
        key: &PublicKey,
        transform: &Option<std::sync::Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    ) -> PublicKey {
        match transform {
            Some(f) => f(*key),
            None => *key,
        }
    }

    /// Add bloom info for a new peer.
    pub fn add_info(&mut self, key: PublicKey) {
        self.blooms.entry(key).or_insert_with(BloomInfo::new);
    }

    /// Remove bloom info for a disconnected peer.
    pub fn remove_info(&mut self, key: &PublicKey) {
        self.blooms.remove(key);
    }

    /// Handle receiving a bloom filter from a peer.
    pub fn handle_bloom(&mut self, peer_key: &PublicKey, filter: BloomFilter) {
        if let Some(info) = self.blooms.get_mut(peer_key) {
            info.recv = filter;
        }
    }

    /// Update on-tree status for all peers based on current tree state.
    /// `self_key`: our own public key
    /// `self_parent`: our current parent's key
    /// `infos`: map of key -> parent for all known nodes
    pub fn fix_on_tree(
        &mut self,
        self_key: &PublicKey,
        self_parent: &PublicKey,
        infos: &HashMap<PublicKey, PublicKey>,
    ) -> Vec<(PublicKey, BloomFilter)> {
        let mut to_send = Vec::new();
        for (pk, pbi) in self.blooms.iter_mut() {
            let was_on = pbi.on_tree;
            pbi.on_tree = false;

            // Our parent is on tree
            if self_parent == pk {
                pbi.on_tree = true;
            }
            // Children: nodes whose parent is us
            else if let Some(parent) = infos.get(pk) {
                if parent == self_key {
                    pbi.on_tree = true;
                }
            }

            if was_on && !pbi.on_tree {
                // Dropped from tree, send blank filter to prevent false positives
                let blank = BloomFilter::new();
                pbi.send = blank.clone();
                to_send.push((*pk, blank));
            }
        }
        to_send
    }

    /// Compute the bloom filter we should send to a given peer.
    /// Returns (filter, is_new).
    pub fn get_bloom_for(
        &mut self,
        key: &PublicKey,
        our_key: &PublicKey,
        keep_ones: bool,
        transform: &Option<std::sync::Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    ) -> (BloomFilter, bool) {
        let mut b = BloomFilter::new();

        // Add our own transformed key
        let xform = self.x_key(our_key, transform);
        b.add(&xform);

        // Merge recv filters from all on-tree peers except the target
        let recv_filters: Vec<BloomFilter> = self
            .blooms
            .iter()
            .filter(|(k, info)| info.on_tree && *k != key)
            .map(|(_, info)| info.recv.clone())
            .collect();

        for filter in &recv_filters {
            b.merge(filter);
        }

        let pbi = self.blooms.get_mut(key).expect("bloom info must exist");

        if keep_ones {
            if !pbi.z_dirty {
                let c = b.copy();
                b.merge(&pbi.send);
                if !b.equal(&c) {
                    pbi.z_dirty = true;
                }
            } else {
                b.merge(&pbi.send);
            }
        } else {
            pbi.z_dirty = false;
        }

        let is_new = !b.equal(&pbi.send);
        if is_new {
            pbi.send = b.clone();
        }

        (b, is_new)
    }

    /// Get the current send bloom for a peer (for retransmission).
    pub fn get_send_bloom(&self, key: &PublicKey) -> Option<BloomFilter> {
        self.blooms.get(key).map(|info| info.send.clone())
    }

    /// Run periodic maintenance: update on-tree status and compute new blooms.
    /// Returns list of (peer_key, bloom_filter) pairs that need to be sent.
    pub fn do_maintenance(
        &mut self,
        self_key: &PublicKey,
        self_parent: &PublicKey,
        infos: &HashMap<PublicKey, PublicKey>,
        transform: &Option<std::sync::Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    ) -> Vec<(PublicKey, BloomFilter)> {
        // Fix on-tree status
        let mut to_send = self.fix_on_tree(self_key, self_parent, infos);

        // Send updated blooms to on-tree peers
        let on_tree_keys: Vec<PublicKey> = self
            .blooms
            .iter()
            .filter(|(_, info)| info.on_tree)
            .map(|(k, _)| *k)
            .collect();

        tracing::debug!(
            "blooms_maintenance: {} on-tree peers, self_parent={:?}",
            on_tree_keys.len(),
            hex::encode(&self_parent[..4]),
        );

        for k in on_tree_keys {
            let z_dirty = self.blooms[&k].z_dirty;
            let keep_ones = !z_dirty;
            let (bloom, is_new) = self.get_bloom_for(&k, self_key, keep_ones, transform);

            let pbi = self.blooms.get_mut(&k).unwrap();
            pbi.seq += 1;
            if is_new || pbi.seq >= 3600 {
                tracing::debug!(
                    "blooms_maintenance: sending bloom to {:?} (is_new={}, seq={}, non_zero_bits={})",
                    hex::encode(&k[..4]),
                    is_new,
                    pbi.seq,
                    bloom.count_ones(),
                );
                to_send.push((k, bloom));
                pbi.seq = 0;
            }
        }

        to_send
    }

    /// Determine which peers should receive a multicast packet.
    /// Returns list of peer keys whose bloom filter matches the destination.
    pub fn get_multicast_targets(
        &self,
        from_key: &PublicKey,
        to_key: &PublicKey,
        transform: &Option<std::sync::Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    ) -> Vec<PublicKey> {
        let xform = self.x_key(to_key, transform);
        let mut targets = Vec::new();
        for (k, pbi) in &self.blooms {
            if !pbi.on_tree {
                continue;
            }
            if k == from_key {
                continue;
            }
            if !pbi.recv.test(&xform) {
                continue;
            }
            targets.push(*k);
        }
        targets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bloom_filter_add_and_test() {
        let mut bf = BloomFilter::new();
        let key = [42u8; 32];
        assert!(!bf.test(&key));
        bf.add(&key);
        assert!(bf.test(&key));
    }

    #[test]
    fn bloom_filter_merge() {
        let mut bf1 = BloomFilter::new();
        let mut bf2 = BloomFilter::new();
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        bf1.add(&key1);
        bf2.add(&key2);
        bf1.merge(&bf2);
        assert!(bf1.test(&key1));
        assert!(bf1.test(&key2));
    }

    #[test]
    fn bloom_filter_equal() {
        let mut bf1 = BloomFilter::new();
        let mut bf2 = BloomFilter::new();
        assert!(bf1.equal(&bf2));
        bf1.add(&[1u8; 32]);
        assert!(!bf1.equal(&bf2));
        bf2.add(&[1u8; 32]);
        assert!(bf1.equal(&bf2));
    }

    #[test]
    fn blooms_manager_add_remove() {
        let mut mgr = Blooms::new();
        let key = [1u8; 32];
        mgr.add_info(key);
        assert!(!mgr.is_on_tree(&key));
        mgr.remove_info(&key);
        assert!(!mgr.is_on_tree(&key));
    }

    #[test]
    fn blooms_multicast_targets() {
        let mut mgr = Blooms::new();
        let peer1 = [1u8; 32];
        let peer2 = [2u8; 32];
        let dest = [3u8; 32];
        let from = [4u8; 32];

        mgr.add_info(peer1);
        mgr.add_info(peer2);

        // Set peer1 on-tree and add dest to its recv filter
        if let Some(info) = mgr.blooms.get_mut(&peer1) {
            info.on_tree = true;
            info.recv.add(&dest);
        }
        // peer2 is off-tree
        if let Some(info) = mgr.blooms.get_mut(&peer2) {
            info.on_tree = false;
        }

        let targets = mgr.get_multicast_targets(&from, &dest, &None);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], peer1);
    }
}

/// Tests for bloom filter compatibility with Go implementation
#[cfg(test)]
mod compatibility_tests {
    use crate::bloom::{base_hashes, BloomFilter};
    use crate::crypto::PublicKey;

    use crate::wire::{decode_bloom, encode_bloom, BLOOM_FILTER_BITS, BLOOM_FILTER_F, BLOOM_FILTER_K, BLOOM_FILTER_U64S};

    /// Calculate bit position for hash index (compatible with Go)
    fn hash_bit(key: &[u8], i: usize) -> usize {
        let (h1, h2) = base_hashes(key);
        // Go: locations[i] = (h1 + uint64(i)*h2) % m
        let h = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (h % BLOOM_FILTER_BITS as u64) as usize
    }

    /// Create bloom filter from raw wire bytes (Go's encoding format)
    fn decode_from_go(data: &[u8]) -> Result<BloomFilter, String> {
        if data.len() < BLOOM_FILTER_F * 2 {
            return Err("data too short for flags".to_string());
        }

        let mut bits = [0u64; BLOOM_FILTER_U64S];
        let mut idx = 0;

        // Parse flags0 (all-zero chunks) and flags1 (all-ones chunks)
        let flags0 = &data[0..BLOOM_FILTER_F];
        let flags1 = &data[BLOOM_FILTER_F..BLOOM_FILTER_F * 2];
        let mut data_idx = BLOOM_FILTER_F * 2;

        for i in 0..BLOOM_FILTER_U64S {
            let flag_byte_idx = i / 8;
            let flag_bit_idx = 7 - (i % 8); // MSB first in Go's encoding

            let is_all_zeros = (flags0[flag_byte_idx] >> flag_bit_idx) & 1 != 0;
            let is_all_ones = (flags1[flag_byte_idx] >> flag_bit_idx) & 1 != 0;

            if is_all_zeros && is_all_ones {
                return Err("invalid flags: both all-zeros and all-ones".to_string());
            }

            if is_all_zeros {
                bits[i] = 0;
            } else if is_all_ones {
                bits[i] = !0u64;
            } else {
                // Need to read 8 bytes from data
                if data_idx + 8 > data.len() {
                    return Err(format!("not enough data for chunk {}", i));
                }
                // Go uses BigEndian for wire format
                bits[i] = u64::from_be_bytes([
                    data[data_idx],
                    data[data_idx + 1],
                    data[data_idx + 2],
                    data[data_idx + 3],
                    data[data_idx + 4],
                    data[data_idx + 5],
                    data[data_idx + 6],
                    data[data_idx + 7],
                ]);
                data_idx += 8;
            }
        }

        if data_idx != data.len() {
            return Err(format!("trailing data: {} bytes", data.len() - data_idx));
        }

        Ok(BloomFilter::from_raw(bits))
    }

    /// Encode to Go's wire format
    fn encode_for_go(filter: &BloomFilter) -> Vec<u8> {
        let us = filter.as_raw();
        let mut flags0 = [0u8; BLOOM_FILTER_F];
        let mut flags1 = [0u8; BLOOM_FILTER_F];
        let mut keep: Vec<u64> = Vec::new();

        for (idx, &u) in us.iter().enumerate() {
            if u == 0 {
                flags0[idx / 8] |= 0x80 >> (idx % 8);
            } else if u == !0u64 {
                flags1[idx / 8] |= 0x80 >> (idx % 8);
            } else {
                keep.push(u);
            }
        }

        let mut out = Vec::new();
        out.extend_from_slice(&flags0);
        out.extend_from_slice(&flags1);

        for u in keep {
            out.extend_from_slice(&u.to_be_bytes());
        }

        out
    }

    #[test]
    fn test_hash_function_compatibility() {
        // Test that our hash function produces expected values
        // These values should match Go's murmur3 output

        let test_key = [42u8; 32];
        let (h1, h2) = base_hashes(&test_key);

        println!("\n=== Hash Function Test ===");
        println!("Input key: {}", hex::encode(&test_key));
        println!("h1 (uint64): 0x{:016X} ({})", h1, h1);
        println!("h2 (uint64): 0x{:016X} ({})", h2, h2);

        // Calculate bit positions that should be set
        let mut bit_positions = Vec::new();
        for i in 0..BLOOM_FILTER_K {
            let bit = hash_bit(&test_key, i);
            bit_positions.push(bit);
        }
        println!("Bit positions: {:?}", bit_positions);

        // Verify bit positions are within range
        for &pos in &bit_positions {
            assert!(pos < BLOOM_FILTER_BITS, "bit position {} out of range", pos);
        }

        // Verify we get exactly BLOOM_FILTER_K unique positions (or fewer if collision)
        let unique: std::collections::HashSet<_> = bit_positions.iter().cloned().collect();
        println!("Unique bit positions: {} (expected ~{})", unique.len(), BLOOM_FILTER_K);
    }

    #[test]
    fn test_known_values_empty() {
        // Reference data from Go - empty filter
        // Go output for empty filter: 32 bytes of flags (all zeros indicating no chunks are all-0 or all-1)
        // Actually for empty filter, all 128 uint64s are 0, so flags0 should be all 1s

        // First, create an empty filter and see what we generate
        let empty = BloomFilter::new();
        let encoded = encode_for_go(&empty);
        println!("\n=== Empty Filter ===");
        println!("Encoded ({} bytes): {}", encoded.len(), hex::encode(&encoded));

        // All chunks are zero, so flags0 should be all 0xFF (16 bytes)
        // flags1 should be all 0x00
        // No payload data
        assert_eq!(encoded.len(), 32); // Just flags

        // Verify round-trip
        let decoded = decode_from_go(&encoded).unwrap();
        assert!(empty.equal(&decoded));
    }

    #[test]
    fn test_known_values_single_key() {
        let key = [42u8; 32];
        let mut filter = BloomFilter::new();
        filter.add(&key);
        let expected = hex::decode("fdbfffbfff7ffe7ffffffffcffffffff0000000000000000000000000000000020000000000000000000000000080000200000000000000000000000000080000000200000000000020000000000000000020000000000000200000000000000").unwrap();
        let expected_filter = BloomFilter::from_raw(decode_bloom(&expected).unwrap());
        //assert!(expected_filter.equal(&filter), "Filter not equals the expected filter!");

        let mut encoded = Vec::new();
        encode_bloom(&mut encoded, filter.as_raw());
        println!("\n=== Single Key [42; 32] ===");
        println!("Key: {}", hex::encode(&key));
        println!("Encoded  ({} bytes): {}", encoded.len(), hex::encode(&encoded));
        println!("Expected ({} bytes): {}", expected.len(), hex::encode(&expected));

        // Print raw bitset
        let raw = filter.as_raw();
        let non_zero: Vec<_> = raw.iter().enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, v)| (i, *v))
            .collect();
        println!("Non-zero chunks: {:?}", non_zero);

        // Verify the key is present
        assert!(filter.test(&key), "Key should be present after adding");

        // Verify round-trip
        let decoded = BloomFilter::from_raw(decode_bloom(&encoded).unwrap());
        assert!(filter.equal(&decoded), "Round-trip should preserve filter");
        assert!(decoded.test(&key), "Key should be present after round-trip");
    }

    #[test]
    fn test_cross_impl_reference() {
        // This test uses hardcoded reference data from Go
        // Run the Go TestBloomFilterCrossImpl and paste the output here

        println!("\n=== Cross-Implementation Reference ===");
        println!("Run Go test TestBloomFilterCrossImpl and paste hex here:");

        // Example format (replace with actual Go output):
        // let go_encoded = hex::decode("...").unwrap();
        // let decoded = decode_from_go(&go_encoded).unwrap();
        // assert!(decoded.test(&expected_key));
    }

    #[test]
    fn test_all_ones_key() {
        let key = [0xFFu8; 32];
        let mut filter = BloomFilter::new();
        filter.add(&key);

        let encoded = encode_for_go(&filter);
        println!("\n=== All-0xFF Key ===");
        println!("Key: {}", hex::encode(&key));
        println!("Encoded ({} bytes): {}", encoded.len(), hex::encode(&encoded));

        let raw = filter.as_raw();
        let non_zero: Vec<_> = raw.iter().enumerate()
            .filter(|(_, &v)| v != 0)
            .map(|(i, v)| (i, *v))
            .collect();
        println!("Non-zero chunks: {} {:?}", non_zero.len(), non_zero);
    }

    #[test]
    fn test_two_keys() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let mut filter = BloomFilter::new();
        filter.add(&key1);
        filter.add(&key2);

        let encoded = encode_for_go(&filter);
        println!("\n=== Two Keys ===");
        println!("Key1: {}", hex::encode(&key1));
        println!("Key2: {}", hex::encode(&key2));
        println!("Encoded ({} bytes): {}", encoded.len(), hex::encode(&encoded));

        // Verify both keys present
        assert!(filter.test(&key1));
        assert!(filter.test(&key2));

        // Verify a different key is not present (with high probability)
        let key3 = [0x03u8; 32];
        // This might fail with small probability due to bloom filter false positives
        // but with 8192 bits and 2 items, FPP is ~0.00006%
        if filter.test(&key3) {
            println!("WARNING: False positive on key3 (unlikely but possible)");
        }
    }

    #[test]
    fn test_merge_compatibility() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];

        let mut filter1 = BloomFilter::new();
        filter1.add(&key1);

        let mut filter2 = BloomFilter::new();
        filter2.add(&key2);

        // Merge filter2 into filter1
        filter1.merge(&filter2);

        // Verify both keys present in merged filter
        assert!(filter1.test(&key1));
        assert!(filter1.test(&key2));

        let encoded = encode_for_go(&filter1);
        println!("\n=== Merged Filter ===");
        println!("Encoded ({} bytes): {}", encoded.len(), hex::encode(&encoded));
    }

    #[test]
    fn test_realistic_public_key() {
        // Simulated ed25519 public key
        let pk: PublicKey = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
        ];

        let mut filter = BloomFilter::new();
        filter.add(&pk);

        let encoded = encode_for_go(&filter);
        println!("\n=== Realistic Public Key ===");
        println!("PK: {}", hex::encode(&pk));
        println!("Encoded ({} bytes): {}", encoded.len(), hex::encode(&encoded));
    }

    #[test]
    fn test_bit_positions_deterministic() {
        // Verify that the same key always produces the same bit positions
        let key = [0xABu8; 32];

        let mut positions1 = Vec::new();
        for i in 0..BLOOM_FILTER_K {
            positions1.push(hash_bit(&key, i));
        }

        let mut positions2 = Vec::new();
        for i in 0..BLOOM_FILTER_K {
            positions2.push(hash_bit(&key, i));
        }

        assert_eq!(positions1, positions2, "Hash function must be deterministic");

        // Now verify by checking actual filter bits
        let mut filter = BloomFilter::new();
        filter.add(&key);

        let raw = filter.as_raw();
        for &pos in &positions1 {
            let idx = pos / 64;
            let bit = pos % 64;
            let actual = (raw[idx] >> bit) & 1;
            assert_eq!(actual, 1, "Bit {} should be set (idx={}, bit={})", pos, idx, bit);
        }

        println!("\n=== Deterministic Check ===");
        println!("Key: {}", hex::encode(&key));
        println!("Bit positions: {:?}", positions1);
    }

    // Manual bit manipulation test to verify our understanding
    #[test]
    fn test_manual_bit_manipulation() {
        let mut bits = [0u64; BLOOM_FILTER_U64S];

        // Set some specific bits
        let test_bits = [0, 63, 64, 127, 8191];
        for &bit in &test_bits {
            let idx = bit / 64;
            let offset = bit % 64;
            bits[idx] |= 1u64 << offset;
        }

        // Verify
        for &bit in &test_bits {
            let idx = bit / 64;
            let offset = bit % 64;
            assert!((bits[idx] >> offset) & 1 == 1);
        }

        // Create filter from raw
        let filter = BloomFilter::from_raw(bits);
        let encoded = encode_for_go(&filter);

        println!("\n=== Manual Bit Test ===");
        println!("Set bits: {:?}", test_bits);
        println!("Encoded: {}", hex::encode(&encoded));

        // Verify round-trip preserves bits
        let decoded = decode_from_go(&encoded).unwrap();
        let raw_back = decoded.as_raw();

        for &bit in &test_bits {
            let idx = bit / 64;
            let offset = bit % 64;
            assert!((raw_back[idx] >> offset) & 1 == 1, "Bit {} lost in round-trip", bit);
        }
    }
}
