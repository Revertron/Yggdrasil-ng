//! Bloom filter implementation compatible with Go's bits-and-blooms/bloom library.
//!
//! This implementation uses the same hashing scheme as the Go library:
//! - Murmur3 128-bit hash to generate 4 base hash values
//! - Location formula: h[i%2] + i*h[2+(((i+(i%2))%4)/2)]
//!
//! Wire format: [16 bytes: zero flags][16 bytes: ones flags][remaining u64s in big-endian]

use std::collections::HashMap;
use murmur3::murmur3_x64_128;
use crate::crypto::PublicKey;

// Configuration constants - must match Go library
pub const BLOOM_FILTER_BITS: usize = 8192;
pub const BLOOM_FILTER_K: usize = 8;
pub const BLOOM_FILTER_U64S: usize = BLOOM_FILTER_BITS / 64; // 128
pub const BLOOM_FILTER_FLAGS: usize = BLOOM_FILTER_U64S / 8; // 16

/// A Bloom filter with fixed 8192 bits and 8 hash functions.
/// Wire-compatible with the Go bits-and-blooms/bloom library.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BloomFilter {
    bits: [u64; BLOOM_FILTER_U64S],
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
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

    /// Get the raw backing array (for wire encoding or inspection).
    pub fn as_raw(&self) -> &[u64; BLOOM_FILTER_U64S] {
        &self.bits
    }

    /// Add a key to the bloom filter.
    pub fn add(&mut self, key: &[u8]) {
        let h = base_hashes(key);
        for i in 0..BLOOM_FILTER_K {
            let bit = location(&h, i, BLOOM_FILTER_BITS);
            self.set_bit(bit);
        }
    }

    /// Test if a key might be in the bloom filter.
    /// Returns true if the key might be present (could be false positive).
    /// Returns false if the key is definitely not present.
    pub fn test(&self, key: &[u8]) -> bool {
        let h = base_hashes(key);
        for i in 0..BLOOM_FILTER_K {
            let bit = location(&h, i, BLOOM_FILTER_BITS);
            if !self.get_bit(bit) {
                return false;
            }
        }
        true
    }

    /// Merge another bloom filter into this one (bitwise OR).
    /// Both filters must have the same configuration.
    pub fn merge(&mut self, other: &BloomFilter) {
        for i in 0..BLOOM_FILTER_U64S {
            self.bits[i] |= other.bits[i];
        }
    }

    /// Count the number of set bits (for diagnostics).
    pub fn count_ones(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Clear all bits from the filter.
    pub fn clear(&mut self) {
        self.bits = [0u64; BLOOM_FILTER_U64S];
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

    pub(crate) fn equal(&self, other: &BloomFilter) -> bool {
        self == other
    }
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
                let c = b.clone();
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

/// Generate four base hash values from key data using Murmur3.
///
/// This replicates the Go library's `sum256` function exactly:
/// 1. Hash data with murmur3 → h1, h2
/// 2. Hash data || [1] with murmur3 → h3, h4
fn base_hashes(data: &[u8]) -> [u64; 4] {
    // First hash: data with seed 0
    let result1 = murmur3_x64_128(&mut &data[..], 0).unwrap_or(0);
    let h1 = result1 as u64;
    let h2 = (result1 >> 64) as u64;

    // Second hash: data || [1] with seed 0
    // This matches Go's behavior of "virtually" appending 1
    let mut data_with_one: Vec<u8> = Vec::with_capacity(data.len() + 1);
    data_with_one.extend_from_slice(data);
    data_with_one.push(1);

    let result2 = murmur3_x64_128(&mut &data_with_one[..], 0).unwrap_or(0);
    let h3 = result2 as u64;
    let h4 = (result2 >> 64) as u64;

    [h1, h2, h3, h4]
}

/// Calculate the ith hash location using the four base hash values.
///
/// This replicates the Go library's `location` function exactly:
/// location(h, i) = h[i%2] + i*h[2+(((i+(i%2))%4)/2)]
///
/// The formula rotates between h[2] and h[3] as the multiplicative hash,
/// while alternating between h[0] and h[1] as the additive base.
fn location(h: &[u64; 4], i: usize, m: usize) -> usize {
    let ii = i as u64;
    // h[i%2] + i*h[2+(((i+(i%2))%4)/2)]
    let base = h[i % 2];
    let inner = (i + (i % 2)) % 4;
    let hash_idx = 2 + (inner / 2);
    let mult = h[hash_idx];
    let loc = base.wrapping_add(ii.wrapping_mul(mult));
    (loc % m as u64) as usize
}

/// Encode a bloom filter's backing u64 array with compression.
///
/// Format:
/// - [16 bytes: flags0 - marks all-zero chunks]
/// - [16 bytes: flags1 - marks all-ones chunks]
/// - [remaining u64s in big-endian]
///
/// This is compatible with the Go library's wire format.
pub fn encode_bloom(data: &[u64; BLOOM_FILTER_U64S]) -> Vec<u8> {
    let mut flags0 = [0u8; BLOOM_FILTER_FLAGS];
    let mut flags1 = [0u8; BLOOM_FILTER_FLAGS];
    let mut keep = Vec::new();

    for (idx, &u) in data.iter().enumerate() {
        if u == 0 {
            flags0[idx / 8] |= 0x80 >> (idx % 8);
        } else if u == u64::MAX {
            flags1[idx / 8] |= 0x80 >> (idx % 8);
        } else {
            keep.push(u);
        }
    }

    let mut out = Vec::with_capacity(BLOOM_FILTER_FLAGS * 2 + keep.len() * 8);
    out.extend_from_slice(&flags0);
    out.extend_from_slice(&flags1);
    for u in keep {
        out.extend_from_slice(&u.to_be_bytes());
    }
    out
}

/// Decode a bloom filter from wire format.
///
/// Returns the decoded u64 array or an error if the format is invalid.
pub fn decode_bloom(data: &[u8]) -> Result<[u64; BLOOM_FILTER_U64S], BloomError> {
    if data.len() < BLOOM_FILTER_FLAGS * 2 {
        return Err(BloomError::Decode("Input too short"));
    }

    let (flags0, rest) = data.split_at(BLOOM_FILTER_FLAGS);
    let (flags1, rest) = rest.split_at(BLOOM_FILTER_FLAGS);

    let flags0: [u8; BLOOM_FILTER_FLAGS] = flags0.try_into().map_err(|_| BloomError::Decode("Invalid flags0"))?;
    let flags1: [u8; BLOOM_FILTER_FLAGS] = flags1.try_into().map_err(|_| BloomError::Decode("Invalid flags1"))?;

    let mut result = [0u64; BLOOM_FILTER_U64S];
    let mut byte_idx = 0;

    for idx in 0..BLOOM_FILTER_U64S {
        let f0 = flags0[idx / 8] & (0x80 >> (idx % 8));
        let f1 = flags1[idx / 8] & (0x80 >> (idx % 8));

        if f0 != 0 && f1 != 0 {
            return Err(BloomError::Decode("Chunk marked as both zero and all-ones"));
        } else if f0 != 0 {
            result[idx] = 0;
        } else if f1 != 0 {
            result[idx] = u64::MAX;
        } else {
            if byte_idx + 8 > rest.len() {
                return Err(BloomError::Decode("Not enough data for non-compressed chunk"));
            }
            let bytes: [u8; 8] = rest[byte_idx..byte_idx + 8].try_into().unwrap();
            result[idx] = u64::from_be_bytes(bytes);
            byte_idx += 8;
        }
    }

    if byte_idx != rest.len() {
        return Err(BloomError::Decode("Extra data after decoding"));
    }

    Ok(result)
}

/// Error type for bloom filter operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BloomError {
    Decode(&'static str),
}

impl std::fmt::Display for BloomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BloomError::Decode(msg) => write!(f, "Decode error: {}", msg),
        }
    }
}

impl std::error::Error for BloomError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_add_test() {
        let mut filter = BloomFilter::new();
        let key = b"hello world";

        assert!(!filter.test(key));
        filter.add(key);
        assert!(filter.test(key));
    }

    #[test]
    fn test_false_positive_rate() {
        let mut filter = BloomFilter::new();

        // Add 1000 keys
        for i in 0..1000u32 {
            let key = i.to_be_bytes();
            filter.add(&key);
        }

        // Test that all added keys are found
        for i in 0..1000u32 {
            let key = i.to_be_bytes();
            assert!(filter.test(&key), "Key {} should be found", i);
        }

        // Check false positive rate on non-existent keys (should be low)
        let mut false_positives = 0;
        for i in 1000..2000u32 {
            let key = i.to_be_bytes();
            if filter.test(&key) {
                false_positives += 1;
            }
        }

        let fp_rate = false_positives as f64 / 1000.0;
        println!("False positive rate: {}", fp_rate);
        // With m=8192, k=8, n=1000, expected FP rate is about 0.008
        assert!(fp_rate < 0.05, "False positive rate {} too high", fp_rate);
    }

    #[test]
    fn test_merge() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();

        filter1.add(b"key1");
        filter2.add(b"key2");

        filter1.merge(&filter2);

        assert!(filter1.test(b"key1"));
        assert!(filter1.test(b"key2"));
    }

    #[test]
    fn test_encode_decode() {
        let mut filter = BloomFilter::new();
        filter.add(b"test key");
        filter.add(b"another key");

        let encoded = encode_bloom(filter.as_raw());
        let decoded = decode_bloom(&encoded).unwrap();

        assert_eq!(filter.as_raw(), &decoded);

        let restored = BloomFilter::from_raw(decoded);
        assert!(restored.test(b"test key"));
        assert!(restored.test(b"another key"));
    }

    #[test]
    fn test_empty_filter_encode() {
        let filter = BloomFilter::new();
        let encoded = encode_bloom(filter.as_raw());
        let decoded = decode_bloom(&encoded).unwrap();
        assert_eq!(filter.as_raw(), &decoded);
    }

    #[test]
    fn test_full_filter_encode() {
        let filter = BloomFilter {
            bits: [u64::MAX; BLOOM_FILTER_U64S],
        };
        let encoded = encode_bloom(filter.as_raw());
        let decoded = decode_bloom(&encoded).unwrap();
        assert_eq!(filter.as_raw(), &decoded);
    }

    #[test]
    fn test_count_ones() {
        let mut filter = BloomFilter::new();
        assert_eq!(filter.count_ones(), 0);

        filter.add(b"test");
        assert!(filter.count_ones() > 0);
        assert!(filter.count_ones() <= (BLOOM_FILTER_K as u32));
    }

    #[test]
    fn test_known_values_single_key() {
        let key = [42u8; 32];
        let mut filter = BloomFilter::new();
        filter.add(&key);
        let expected = hex::decode("fdbfffbfff7ffe7ffffffffcffffffff0000000000000000000000000000000020000000000000000000000000080000200000000000000000000000000080000000200000000000020000000000000000020000000000000200000000000000").unwrap();
        let expected_filter = BloomFilter::from_raw(decode_bloom(&expected).unwrap());

        let encoded = encode_bloom(filter.as_raw());
        println!("\n=== Single Key [42; 32] ===");
        println!("Key: {}", hex::encode(&key));
        println!("Encoded  ({} bytes): {}", encoded.len(), hex::encode(&encoded));
        println!("Expected ({} bytes): {}", expected.len(), hex::encode(&expected));
        assert!(expected_filter.equal(&filter), "Filter not equals the expected filter!");

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
}