//! Cryptographic primitives for the encrypted layer.
//!
//! - Ed25519 ↔ Curve25519 key conversion using `curve25519-dalek`
//! - XSalsa20-Poly1305 authenticated encryption (NaCl box construction) using `crypto_box` crate
//! - Nonce construction from u64 counters

use crypto_box::aead::Aead;
use crypto_box::aead::generic_array::GenericArray;
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, SalsaBox};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};

/// XSalsa20-Poly1305 overhead (Poly1305 authentication tag).
pub(crate) const BOX_OVERHEAD: usize = 16;

/// XSalsa20-Poly1305 nonce size (24 bytes).
pub(crate) const BOX_NONCE_SIZE: usize = 24;

/// Curve25519 public key (32 bytes).
pub(crate) type CurvePublicKey = [u8; 32];

/// Curve25519 private key (32 bytes).
pub(crate) type CurvePrivateKey = [u8; 32];

// ---------------------------------------------------------------------------
// Ed25519 → Curve25519 conversion
// ---------------------------------------------------------------------------

/// Convert an Ed25519 private key (seed) to a Curve25519 private key.
///
/// This hashes the seed with SHA-512 and takes the first 32 bytes,
/// matching Go's `e2c.Ed25519PrivateKeyToCurve25519`.
pub(crate) fn ed25519_private_to_curve25519(signing_key: &SigningKey) -> CurvePrivateKey {
    let seed = signing_key.to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(seed);
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash[..32]);
    // Clamp (x25519-dalek does this internally, but we match Go's raw output)
    out
}

/// Convert an Ed25519 public key to a Curve25519 (Montgomery) public key.
///
/// Uses the bilinear map: u = (1 + y) / (1 - y) mod p
/// where y is the Edwards y-coordinate.
///
/// Matches Go's `e2c.Ed25519PublicKeyToCurve25519`.
pub(crate) fn ed25519_public_to_curve25519(
    ed_pub: &crate::crypto::PublicKey,
) -> Result<CurvePublicKey, ()> {
    use curve25519_dalek::edwards::CompressedEdwardsY;

    // Parse the Ed25519 public key as a compressed Edwards point
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards_point = compressed.decompress().ok_or(())?;

    // Convert to Montgomery u-coordinate using the built-in conversion
    // This uses optimized field arithmetic, much faster than custom bigint
    let montgomery = edwards_point.to_montgomery();

    Ok(montgomery.0)
}

// ---------------------------------------------------------------------------
// XSalsa20-Poly1305 encryption (crypto_box crate)
// ---------------------------------------------------------------------------

/// Generate a new random Curve25519 keypair.
pub(crate) fn new_box_keys() -> (CurvePublicKey, CurvePrivateKey) {
    let secret = BoxSecretKey::generate(&mut rand::rngs::OsRng);
    let public = secret.public_key();
    let mut pub_bytes = [0u8; 32];
    let mut priv_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(public.as_bytes());
    priv_bytes.copy_from_slice(&secret.to_bytes());
    (pub_bytes, priv_bytes)
}

/// Encrypt a message using XSalsa20-Poly1305 (via crypto_box crate).
///
/// Returns ciphertext (plaintext.len() + 16 bytes overhead).
pub(crate) fn box_seal(
    msg: &[u8],
    nonce: u64,
    their_pub: &CurvePublicKey,
    our_priv: &CurvePrivateKey,
) -> Result<Vec<u8>, ()> {
    let salsa_box = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.encrypt(nonce_ga, msg).map_err(|_| ())
}

/// Decrypt a message using XSalsa20-Poly1305 (via crypto_box crate).
///
/// Returns plaintext (ciphertext.len() - 16 bytes).
pub(crate) fn box_open(
    ciphertext: &[u8],
    nonce: u64,
    their_pub: &CurvePublicKey,
    our_priv: &CurvePrivateKey,
) -> Result<Vec<u8>, ()> {
    let salsa_box = make_salsa_box(their_pub, our_priv);
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.decrypt(nonce_ga, ciphertext).map_err(|_| ())
}

/// Encrypt with a precomputed shared secret (SalsaBox already contains it).
pub(crate) fn box_seal_precomputed(
    msg: &[u8],
    nonce: u64,
    salsa_box: &SalsaBox,
) -> Result<Vec<u8>, ()> {
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.encrypt(nonce_ga, msg).map_err(|_| ())
}

/// Decrypt with a precomputed shared secret (SalsaBox already contains it).
pub(crate) fn box_open_precomputed(
    ciphertext: &[u8],
    nonce: u64,
    salsa_box: &SalsaBox,
) -> Result<Vec<u8>, ()> {
    let nonce_bytes = nonce_for_u64(nonce);
    let nonce_ga = GenericArray::from_slice(&nonce_bytes);
    salsa_box.decrypt(nonce_ga, ciphertext).map_err(|_| ())
}

/// Create a SalsaBox (precomputed shared secret) from keys.
pub(crate) fn make_salsa_box(
    their_pub: &CurvePublicKey,
    our_priv: &CurvePrivateKey,
) -> SalsaBox {
    let pk = BoxPublicKey::from(*their_pub);
    let sk = BoxSecretKey::from(*our_priv);
    SalsaBox::new(&pk, &sk)
}

/// Convert a u64 counter to a 24-byte XSalsa20 nonce.
///
/// Format: 16 zero bytes followed by 8 bytes big-endian u64.
/// Matches Go's `nonceForUint64`.
pub(crate) fn nonce_for_u64(value: u64) -> [u8; BOX_NONCE_SIZE] {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    nonce[16..24].copy_from_slice(&value.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn nonce_for_u64_format() {
        let n = nonce_for_u64(0);
        assert_eq!(n, [0u8; 24]);

        let n = nonce_for_u64(1);
        let mut expected = [0u8; 24];
        expected[23] = 1;
        assert_eq!(n, expected);

        let n = nonce_for_u64(256);
        let mut expected = [0u8; 24];
        expected[22] = 1;
        assert_eq!(n, expected);
    }

    #[test]
    fn box_seal_and_open() {
        let (pub_a, priv_a) = new_box_keys();
        let (pub_b, priv_b) = new_box_keys();

        let msg = b"hello world";
        let ciphertext = box_seal(msg, 42, &pub_b, &priv_a).unwrap();
        assert_ne!(&ciphertext[..], msg);
        assert_eq!(ciphertext.len(), msg.len() + BOX_OVERHEAD);

        let plaintext = box_open(&ciphertext, 42, &pub_a, &priv_b).unwrap();
        assert_eq!(&plaintext[..], msg);
    }

    #[test]
    fn box_wrong_nonce_fails() {
        let (pub_a, priv_a) = new_box_keys();
        let (pub_b, priv_b) = new_box_keys();

        let msg = b"secret";
        let ciphertext = box_seal(msg, 1, &pub_b, &priv_a).unwrap();
        let result = box_open(&ciphertext, 2, &pub_a, &priv_b);
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_to_curve25519_roundtrip() {
        // Generate Ed25519 keypair, convert to Curve25519, verify shared secret matches
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);

        let curve_priv_a = ed25519_private_to_curve25519(&key_a);
        let curve_priv_b = ed25519_private_to_curve25519(&key_b);

        let pub_a_ed: crate::crypto::PublicKey = key_a.verifying_key().to_bytes();
        let pub_b_ed: crate::crypto::PublicKey = key_b.verifying_key().to_bytes();

        let curve_pub_a = ed25519_public_to_curve25519(&pub_a_ed).unwrap();
        let curve_pub_b = ed25519_public_to_curve25519(&pub_b_ed).unwrap();

        // Both sides should compute the same shared secret
        let msg = b"test message for encryption";
        let ct = box_seal(msg, 0, &curve_pub_b, &curve_priv_a).unwrap();
        let pt = box_open(&ct, 0, &curve_pub_a, &curve_priv_b).unwrap();
        assert_eq!(&pt[..], msg);
    }

    #[test]
    fn new_box_keys_are_valid() {
        let (pub_key, priv_key) = new_box_keys();
        // Verify the public key matches the private key
        let sk = BoxSecretKey::from(priv_key);
        let expected_pub = sk.public_key();
        assert_eq!(pub_key, *expected_pub.as_bytes());
    }

    #[test]
    fn precomputed_box_matches_direct() {
        let (pub_a, priv_a) = new_box_keys();
        let (pub_b, priv_b) = new_box_keys();

        let msg = b"precomputed test";

        // Direct
        let ct1 = box_seal(msg, 5, &pub_b, &priv_a).unwrap();

        // Precomputed
        let salsa = make_salsa_box(&pub_b, &priv_a);
        let ct2 = box_seal_precomputed(msg, 5, &salsa).unwrap();

        // Both should produce same ciphertext (SalsaBox is deterministic for same nonce)
        assert_eq!(ct1, ct2);

        // Both should decrypt with the other side
        let pt1 = box_open(&ct1, 5, &pub_a, &priv_b).unwrap();
        let salsa2 = make_salsa_box(&pub_a, &priv_b);
        let pt2 = box_open_precomputed(&ct2, 5, &salsa2).unwrap();
        assert_eq!(&pt1[..], msg);
        assert_eq!(&pt2[..], msg);
    }
}
