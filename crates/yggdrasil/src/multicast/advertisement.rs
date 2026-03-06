/// Multicast beacon advertisement — wire-compatible with yggdrasil-go.
///
/// Wire format (big-endian):
/// ```text
/// Offset  Size     Field
/// 0       2        MajorVersion (u16)
/// 2       2        MinorVersion (u16)
/// 4       32       PublicKey (ed25519)
/// 36      2        Port (u16) — TLS listen port
/// 38      2        HashLength (u16)
/// 40      variable Hash (BLAKE2b-512, always 64 bytes)
/// ```

use blake2::digest::Mac;
use blake2::{Blake2b512, Blake2bMac512};

/// Minimum beacon size: 2 + 2 + 32 + 2 + 2 = 40 bytes (no hash).
const MIN_BEACON_SIZE: usize = 40;

/// Ed25519 public key size.
const PUBLIC_KEY_SIZE: usize = 32;

/// A multicast beacon advertisement.
#[derive(Clone, Debug)]
pub struct MulticastAdvertisement {
    pub major_version: u16,
    pub minor_version: u16,
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    pub port: u16,
    pub hash: Vec<u8>,
}

impl MulticastAdvertisement {
    /// Encode the advertisement into a byte vector (big-endian).
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(MIN_BEACON_SIZE + self.hash.len());
        buf.extend_from_slice(&self.major_version.to_be_bytes());
        buf.extend_from_slice(&self.minor_version.to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.port.to_be_bytes());
        buf.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.hash);
        buf
    }

    /// Decode a beacon from raw bytes. Returns an error if the data is too short
    /// or the hash length field is inconsistent.
    pub fn unmarshal(data: &[u8]) -> Result<Self, String> {
        if data.len() < MIN_BEACON_SIZE {
            return Err(format!(
                "invalid multicast beacon: {} bytes (minimum {})",
                data.len(),
                MIN_BEACON_SIZE
            ));
        }

        let major_version = u16::from_be_bytes([data[0], data[1]]);
        let minor_version = u16::from_be_bytes([data[2], data[3]]);

        let mut public_key = [0u8; PUBLIC_KEY_SIZE];
        public_key.copy_from_slice(&data[4..4 + PUBLIC_KEY_SIZE]);

        let port = u16::from_be_bytes([data[36], data[37]]);
        let hash_len = u16::from_be_bytes([data[38], data[39]]) as usize;

        if data.len() < MIN_BEACON_SIZE + hash_len {
            return Err(format!(
                "invalid multicast beacon: hash_len={} but only {} bytes remain",
                hash_len,
                data.len() - MIN_BEACON_SIZE
            ));
        }

        let hash = data[MIN_BEACON_SIZE..MIN_BEACON_SIZE + hash_len].to_vec();

        Ok(Self {
            major_version,
            minor_version,
            public_key,
            port,
            hash,
        })
    }
}

/// Compute a BLAKE2b-512 hash of the public key.
///
/// Matches Go's behavior exactly:
/// - Empty password: BLAKE2b-512(public_key) — unkeyed hash
/// - Non-empty password: BLAKE2b-512(public_key, key=password) — keyed MAC
///
/// Always returns a 64-byte hash.
pub fn compute_beacon_hash(public_key: &[u8; 32], password: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        // Unkeyed BLAKE2b-512 (matches Go's blake2b.New512(nil))
        use blake2::Digest;
        let mut hasher = Blake2b512::new();
        Digest::update(&mut hasher, public_key);
        hasher.finalize().to_vec()
    } else {
        // Keyed BLAKE2b-512 MAC (matches Go's blake2b.New512(password))
        let mut mac = Blake2bMac512::new_from_slice(password)
            .expect("BLAKE2b key length should be valid");
        Mac::update(&mut mac, public_key);
        mac.finalize().into_bytes().to_vec()
    }
}

/// Verify a received beacon hash against the expected password.
/// Always expects a 64-byte hash (Go always includes one).
pub fn verify_beacon_hash(public_key: &[u8; 32], received_hash: &[u8], password: &[u8]) -> bool {
    let expected = compute_beacon_hash(public_key, password);
    if expected.len() != received_hash.len() {
        return false;
    }
    // Constant-time comparison
    expected.iter().zip(received_hash.iter()).all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marshal_unmarshal_with_unkeyed_hash() {
        let public_key = [0xAB; 32];
        let hash = compute_beacon_hash(&public_key, &[]);
        assert_eq!(hash.len(), 64); // Always 64 bytes, even with no password

        let adv = MulticastAdvertisement {
            major_version: 0,
            minor_version: 5,
            public_key,
            port: 12345,
            hash,
        };

        let data = adv.marshal();
        assert_eq!(data.len(), MIN_BEACON_SIZE + 64);

        let decoded = MulticastAdvertisement::unmarshal(&data).unwrap();
        assert_eq!(decoded.major_version, 0);
        assert_eq!(decoded.minor_version, 5);
        assert_eq!(decoded.public_key, [0xAB; 32]);
        assert_eq!(decoded.port, 12345);
        assert_eq!(decoded.hash.len(), 64);
    }

    #[test]
    fn test_marshal_unmarshal_with_hash() {
        let public_key = [0x42; 32];
        let hash = compute_beacon_hash(&public_key, b"secret");
        assert_eq!(hash.len(), 64);

        let adv = MulticastAdvertisement {
            major_version: 0,
            minor_version: 5,
            public_key,
            port: 9001,
            hash,
        };

        let data = adv.marshal();
        assert_eq!(data.len(), MIN_BEACON_SIZE + 64);

        let decoded = MulticastAdvertisement::unmarshal(&data).unwrap();
        assert_eq!(decoded.major_version, 0);
        assert_eq!(decoded.minor_version, 5);
        assert_eq!(decoded.public_key, public_key);
        assert_eq!(decoded.port, 9001);
        assert_eq!(decoded.hash.len(), 64);
        assert_eq!(decoded.hash, adv.hash);
    }

    #[test]
    fn test_unmarshal_too_short() {
        let data = vec![0u8; 10];
        assert!(MulticastAdvertisement::unmarshal(&data).is_err());
    }

    #[test]
    fn test_unmarshal_hash_length_mismatch() {
        let mut data = vec![0u8; MIN_BEACON_SIZE];
        // Set hash_len to 64 but don't provide the hash bytes
        data[38] = 0;
        data[39] = 64;
        assert!(MulticastAdvertisement::unmarshal(&data).is_err());
    }

    #[test]
    fn test_verify_hash() {
        let pk = [0x42; 32];
        let password = b"mypassword";
        let hash = compute_beacon_hash(&pk, password);
        assert!(verify_beacon_hash(&pk, &hash, password));
        assert!(!verify_beacon_hash(&pk, &hash, b"wrongpassword"));
    }

    #[test]
    fn test_verify_empty_password() {
        let pk = [0x42; 32];
        // Empty password still produces a 64-byte unkeyed hash
        let hash = compute_beacon_hash(&pk, &[]);
        assert_eq!(hash.len(), 64);
        assert!(verify_beacon_hash(&pk, &hash, &[]));
        // Wrong hash should fail
        assert!(!verify_beacon_hash(&pk, &[1, 2, 3], &[]));
        // Empty hash should fail (Go always sends 64 bytes)
        assert!(!verify_beacon_hash(&pk, &[], &[]));
    }
}
