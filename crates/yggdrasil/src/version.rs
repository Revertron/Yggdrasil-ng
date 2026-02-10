use blake2::digest::Mac;
use blake2::Blake2bMac512;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::io::Read;
use thiserror::Error;

pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

const PREAMBLE: &[u8; 4] = b"meta";
const SIGNATURE_SIZE: usize = 64;

#[derive(Error, Debug)]
pub enum VersionError {
    #[error("invalid preamble")]
    InvalidPreamble,
    #[error("metadata too short")]
    TooShort,
    #[error("incorrect password or invalid signature")]
    BadSignature,
    #[error("incompatible version {0}.{1}")]
    IncompatibleVersion(u16, u16),
    #[error("invalid public key length")]
    InvalidKey,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handshake metadata exchanged between peers.
#[derive(Clone, Debug)]
pub struct Metadata {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub public_key: [u8; 32],
    pub priority: u8,
}

impl Default for Metadata {
    fn default() -> Self {
        Self {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key: [0u8; 32],
            priority: 0,
        }
    }
}

impl Metadata {
    /// Create metadata for the local node.
    pub fn new(public_key: [u8; 32], priority: u8) -> Self {
        Self {
            major_ver: PROTOCOL_VERSION_MAJOR,
            minor_ver: PROTOCOL_VERSION_MINOR,
            public_key,
            priority,
        }
    }

    /// Check if the version is compatible.
    pub fn check(&self) -> bool {
        self.major_ver == PROTOCOL_VERSION_MAJOR
            && self.minor_ver == PROTOCOL_VERSION_MINOR
            && self.public_key.len() == 32
    }

    /// Encode metadata to wire format, signed with the given key.
    /// Wire format:
    ///   "meta" (4 bytes) + length (u16 BE) + TLV fields + ed25519 signature (64 bytes)
    /// The signature is over BLAKE2b-512(public_key, key=password).
    pub fn encode(&self, signing_key: &SigningKey, password: &[u8]) -> Vec<u8> {
        let mut bs = Vec::with_capacity(128);
        bs.extend_from_slice(PREAMBLE);
        bs.extend_from_slice(&[0, 0]); // length placeholder

        // Major version
        bs.extend_from_slice(&META_VERSION_MAJOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.major_ver.to_be_bytes());

        // Minor version
        bs.extend_from_slice(&META_VERSION_MINOR.to_be_bytes());
        bs.extend_from_slice(&2u16.to_be_bytes());
        bs.extend_from_slice(&self.minor_ver.to_be_bytes());

        // Public key
        bs.extend_from_slice(&META_PUBLIC_KEY.to_be_bytes());
        bs.extend_from_slice(&32u16.to_be_bytes());
        bs.extend_from_slice(&self.public_key);

        // Priority
        bs.extend_from_slice(&META_PRIORITY.to_be_bytes());
        bs.extend_from_slice(&1u16.to_be_bytes());
        bs.push(self.priority);

        // BLAKE2b-512 hash of public key (keyed with password if non-empty)
        let hash = blake2b_hash(&self.public_key, password);
        let sig = signing_key.sign(&hash);
        bs.extend_from_slice(&sig.to_bytes());

        // Fill in length (excludes the 6-byte header)
        let length = (bs.len() - 6) as u16;
        bs[4..6].copy_from_slice(&length.to_be_bytes());

        bs
    }

    /// Decode metadata from a reader. Verifies the signature.
    pub fn decode<R: Read>(reader: &mut R, password: &[u8]) -> Result<Self, VersionError> {
        // Read 6-byte header
        let mut header = [0u8; 6];
        reader.read_exact(&mut header)?;

        if &header[..4] != PREAMBLE {
            return Err(VersionError::InvalidPreamble);
        }

        let length = u16::from_be_bytes([header[4], header[5]]) as usize;
        if length < SIGNATURE_SIZE {
            return Err(VersionError::TooShort);
        }

        let mut body = vec![0u8; length];
        reader.read_exact(&mut body)?;

        let sig_bytes = &body[length - SIGNATURE_SIZE..];
        let fields = &body[..length - SIGNATURE_SIZE];

        // Parse TLV fields
        let mut meta = Metadata::default();
        let mut pos = 0;
        while pos + 4 <= fields.len() {
            let field_id = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
            let field_len = u16::from_be_bytes([fields[pos + 2], fields[pos + 3]]) as usize;
            pos += 4;
            if pos + field_len > fields.len() {
                break;
            }
            match field_id {
                META_VERSION_MAJOR if field_len >= 2 => {
                    meta.major_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_VERSION_MINOR if field_len >= 2 => {
                    meta.minor_ver = u16::from_be_bytes([fields[pos], fields[pos + 1]]);
                }
                META_PUBLIC_KEY if field_len == 32 => {
                    meta.public_key.copy_from_slice(&fields[pos..pos + 32]);
                }
                META_PRIORITY if field_len >= 1 => {
                    meta.priority = fields[pos];
                }
                _ => {} // skip unknown fields
            }
            pos += field_len;
        }

        // Verify signature
        let hash = blake2b_hash(&meta.public_key, password);
        let signature =
            Signature::from_bytes(sig_bytes.try_into().map_err(|_| VersionError::BadSignature)?);
        let verifying_key = VerifyingKey::from_bytes(&meta.public_key)
            .map_err(|_| VersionError::InvalidKey)?;
        verifying_key
            .verify(&hash, &signature)
            .map_err(|_| VersionError::BadSignature)?;

        Ok(meta)
    }
}

/// Compute BLAKE2b-512 hash of data, optionally keyed with password.
fn blake2b_hash(data: &[u8], password: &[u8]) -> [u8; 64] {
    if password.is_empty() {
        // Unkeyed: Go's blake2b.New512(nil) → use as a keyed MAC with empty key?
        // Actually, Go's blake2b.New512(nil) creates an unkeyed hash.
        // blake2 crate: use Blake2b512 (unkeyed) for this case.
        use blake2::Digest;
        use blake2::Blake2b512;
        let mut hasher = Blake2b512::new();
        hasher.update(data);
        hasher.finalize().into()
    } else {
        // Keyed: Go's blake2b.New512(password)
        let mut mac = Blake2bMac512::new_from_slice(password)
            .expect("BLAKE2b key length should be valid");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_encode_decode_no_password() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 0);
        let encoded = meta.encode(&signing_key, b"");

        // Verify header
        assert_eq!(&encoded[..4], b"meta");

        // Decode
        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Metadata::decode(&mut cursor, b"").unwrap();
        assert_eq!(decoded.major_ver, PROTOCOL_VERSION_MAJOR);
        assert_eq!(decoded.minor_ver, PROTOCOL_VERSION_MINOR);
        assert_eq!(decoded.public_key, public_key);
        assert_eq!(decoded.priority, 0);
        assert!(decoded.check());
    }

    #[test]
    fn test_encode_decode_with_password() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 5);
        let password = b"test-password";
        let encoded = meta.encode(&signing_key, password);

        let mut cursor = std::io::Cursor::new(&encoded);
        let decoded = Metadata::decode(&mut cursor, password).unwrap();
        assert_eq!(decoded.priority, 5);
        assert_eq!(decoded.public_key, public_key);
    }

    #[test]
    fn test_decode_wrong_password_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key: [u8; 32] = signing_key.verifying_key().to_bytes();

        let meta = Metadata::new(public_key, 0);
        let encoded = meta.encode(&signing_key, b"correct");

        let mut cursor = std::io::Cursor::new(&encoded);
        let result = Metadata::decode(&mut cursor, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_valid() {
        let meta = Metadata::new([1u8; 32], 0);
        assert!(meta.check());
    }

    #[test]
    fn test_check_invalid_version() {
        let mut meta = Metadata::new([1u8; 32], 0);
        meta.major_ver = 1;
        assert!(!meta.check());
    }
}
