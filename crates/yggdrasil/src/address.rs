use std::fmt;

/// Yggdrasil IPv6 address (16 bytes, prefix 0x02).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Address(pub [u8; 16]);

/// Yggdrasil /64 subnet (8 bytes, prefix 0x03).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Subnet(pub [u8; 8]);

const ADDRESS_PREFIX: u8 = 0x02;
const SUBNET_PREFIX: u8 = 0x03;

impl Address {
    /// Check if this is a valid Yggdrasil address (starts with 0x02).
    pub fn is_valid(&self) -> bool {
        self.0[0] == ADDRESS_PREFIX
    }

    /// Reconstruct a partial ed25519 public key from this address.
    /// Used for DHT lookups. Exact port of Go's GetKey().
    pub fn get_key(&self) -> [u8; 32] {
        let ones = self.0[1] as usize;
        let mut key = [0u8; 32];
        // Set the first `ones` bits to 1
        for idx in 0..ones {
            if idx / 8 >= 32 {
                break;
            }
            key[idx / 8] |= 0x80 >> (idx % 8);
        }
        // Skip the next bit (the 0 separator), copy remaining from addr[2..]
        let key_offset = ones + 1; // bits into key
        for idx in 0..(8 * 14) {
            let addr_byte = 2 + idx / 8;
            if addr_byte >= 16 {
                break;
            }
            let bit = (self.0[addr_byte] >> (7 - (idx % 8))) & 1;
            let key_bit_pos = key_offset + idx;
            if key_bit_pos / 8 >= 32 {
                break;
            }
            key[key_bit_pos / 8] |= bit << (7 - (key_bit_pos % 8));
        }
        // Bitwise invert
        for byte in &mut key {
            *byte = !*byte;
        }
        key
    }
}

impl Subnet {
    /// Check if this is a valid Yggdrasil subnet (starts with 0x03).
    pub fn is_valid(&self) -> bool {
        self.0[0] == SUBNET_PREFIX
    }

    /// Reconstruct a partial ed25519 public key from this subnet.
    pub fn get_key(&self) -> [u8; 32] {
        // Subnet is addr[0..8] with bit 0 set, so undo that first
        let mut addr_bytes = [0u8; 16];
        addr_bytes[..8].copy_from_slice(&self.0);
        addr_bytes[0] &= !0x01; // clear the subnet marker bit
        let addr = Address(addr_bytes);
        addr.get_key()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format as IPv6 address
        let a = &self.0;
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
            u16::from_be_bytes([a[0], a[1]]),
            u16::from_be_bytes([a[2], a[3]]),
            u16::from_be_bytes([a[4], a[5]]),
            u16::from_be_bytes([a[6], a[7]]),
            u16::from_be_bytes([a[8], a[9]]),
            u16::from_be_bytes([a[10], a[11]]),
            u16::from_be_bytes([a[12], a[13]]),
            u16::from_be_bytes([a[14], a[15]]),
        )
    }
}

impl fmt::Display for Subnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(
            f,
            "{:x}:{:x}:{:x}:{:x}::/64",
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u16::from_be_bytes([s[4], s[5]]),
            u16::from_be_bytes([s[6], s[7]]),
        )
    }
}

/// Derive a Yggdrasil IPv6 address from an ed25519 public key.
/// Exact port of Go's `AddrForKey`.
pub fn addr_for_key(public_key: &[u8; 32]) -> Address {
    // Bitwise invert the key
    let mut buf = *public_key;
    for byte in &mut buf {
        *byte = !*byte;
    }

    // Count leading 1-bits in inverted key, collect remaining bits
    // Use usize to avoid overflow (all-zeros key → 256 leading ones in inverted)
    let mut ones: usize = 0;
    let mut done = false;
    let mut temp = Vec::new();
    let mut bits: u8 = 0;
    let mut n_bits: u8 = 0;

    for idx in 0..(8 * 32) {
        let bit = (buf[idx / 8] & (0x80 >> (idx % 8))) >> (7 - (idx % 8));
        if !done && bit != 0 {
            ones += 1;
            continue;
        }
        if !done && bit == 0 {
            done = true;
            continue; // skip the first 0 bit
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            temp.push(bits);
            bits = 0;
            n_bits = 0;
        }
    }

    let mut addr = [0u8; 16];
    addr[0] = ADDRESS_PREFIX;
    // ones can exceed 255 for degenerate keys; clamp to u8 range
    addr[1] = ones.min(255) as u8;
    let copy_len = temp.len().min(14);
    addr[2..2 + copy_len].copy_from_slice(&temp[..copy_len]);
    Address(addr)
}

/// Derive a Yggdrasil /64 subnet from an ed25519 public key.
/// Exact port of Go's `SubnetForKey`.
pub fn subnet_for_key(public_key: &[u8; 32]) -> Subnet {
    let addr = addr_for_key(public_key);
    let mut subnet = [0u8; 8];
    subnet.copy_from_slice(&addr.0[..8]);
    subnet[0] |= 0x01; // set subnet marker bit
    Subnet(subnet)
}

/// Check if an IPv6 address (16 bytes) is a valid Yggdrasil address.
pub fn is_valid_address(addr: &[u8; 16]) -> bool {
    addr[0] == ADDRESS_PREFIX
}

/// Check if an IPv6 /64 prefix (first 8 bytes) is a valid Yggdrasil subnet.
pub fn is_valid_subnet(prefix: &[u8; 8]) -> bool {
    prefix[0] == SUBNET_PREFIX
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addr_for_key_basic() {
        // Zero key should produce a valid address with prefix 0x02
        let key = [0u8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert!(addr.is_valid());
    }

    #[test]
    fn test_subnet_for_key_basic() {
        let key = [0u8; 32];
        let subnet = subnet_for_key(&key);
        assert!(subnet.is_valid());
        assert_eq!(subnet.0[0] & 0x01, 0x01); // subnet bit set
    }

    #[test]
    fn test_addr_roundtrip() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];
        let addr = addr_for_key(&key);
        assert!(addr.is_valid());

        let subnet = subnet_for_key(&key);
        assert!(subnet.is_valid());
    }

    #[test]
    fn test_address_display() {
        let addr = Address([
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]);
        let s = format!("{}", addr);
        assert!(s.starts_with("200:"));
    }

    #[test]
    fn test_subnet_display() {
        let subnet = Subnet([0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        let s = format!("{}", subnet);
        assert!(s.contains("::/64"));
    }

    #[test]
    fn test_get_key_produces_same_address() {
        // For various keys, addr_for_key(get_key(addr_for_key(k))) should equal addr_for_key(k)
        for seed in 0u8..20 {
            let mut key = [0u8; 32];
            key[0] = seed;
            key[31] = seed.wrapping_mul(7);
            let addr = addr_for_key(&key);
            let recovered = addr.get_key();
            let addr2 = addr_for_key(&recovered);
            assert_eq!(addr, addr2, "roundtrip failed for seed {}", seed);
        }
    }

    #[test]
    fn test_all_zeros_key() {
        // Edge case: all-zeros key inverts to all-ones, 256 leading 1-bits
        let key = [0u8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        // ones count clamped to 255
        assert_eq!(addr.0[1], 255);
    }

    #[test]
    fn test_all_ones_key() {
        // All-ones key inverts to all-zeros, 0 leading 1-bits
        let key = [0xFFu8; 32];
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert_eq!(addr.0[1], 0); // zero leading ones
    }

    #[test]
    fn test_known_key() {
        // A key with a known number of leading zeros (which become leading ones when inverted)
        // Key starts with 0x00 0x01 = first 15 bits are 0, bit 16 is 1
        // Inverted: first 15 bits are 1, bit 16 is 0 → ones = 15
        let mut key = [0u8; 32];
        key[1] = 0x01;
        key[2] = 0xFF; // fill rest
        let addr = addr_for_key(&key);
        assert_eq!(addr.0[0], 0x02);
        assert_eq!(addr.0[1], 15);
    }

    #[test]
    fn test_bloom_transform_equivalence() {
        // The bloom transform is: subnet_for_key(k).get_key()
        // When ipv6rwc sends a lookup, it uses Address.get_key() (partial key).
        // The receiver does: subnet_for_key(partial_key).get_key() == subnet_for_key(full_key).get_key()
        // This test verifies they match for various keys.
        use rand::rngs::OsRng;
        use rand::RngCore;

        for _ in 0..100 {
            let mut full_key = [0u8; 32];
            OsRng.fill_bytes(&mut full_key);

            let addr = addr_for_key(&full_key);
            let partial_key = addr.get_key();

            let bloom_full = subnet_for_key(&full_key).get_key();
            let bloom_partial = subnet_for_key(&partial_key).get_key();

            assert_eq!(
                bloom_full, bloom_partial,
                "bloom transform mismatch for key {:02x?} (ones={})",
                &full_key[..4], addr.0[1]
            );
        }
    }

    #[test]
    fn test_bloom_transform_via_subnet() {
        // Also test via subnet path: Subnet.get_key() → subnet_for_key → get_key
        use rand::rngs::OsRng;
        use rand::RngCore;

        for _ in 0..100 {
            let mut full_key = [0u8; 32];
            OsRng.fill_bytes(&mut full_key);

            let subnet = subnet_for_key(&full_key);
            let partial_key_from_subnet = subnet.get_key();

            let bloom_full = subnet_for_key(&full_key).get_key();
            let bloom_partial = subnet_for_key(&partial_key_from_subnet).get_key();

            assert_eq!(
                bloom_full, bloom_partial,
                "subnet bloom transform mismatch for key {:02x?}",
                &full_key[..4]
            );
        }
    }
}
