//! Cryptographic primitives for the encrypted layer.
//!
//! - Ed25519 ↔ Curve25519 key conversion
//! - NaCl box encryption/decryption with precomputed shared secrets
//! - Nonce construction from u64 counters

use crypto_box::aead::Aead;
use crypto_box::aead::generic_array::GenericArray;
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, SalsaBox};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};

/// NaCl box overhead (Poly1305 tag).
pub(crate) const BOX_OVERHEAD: usize = 16;

/// NaCl box nonce size.
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
    // The Curve25519 field prime
    // p = 2^255 - 19
    let p = {
        let mut bytes = [0u8; 32];
        // p in little-endian
        bytes[0] = 0xed; // 2^255 - 19 in little-endian
        bytes[1] = 0xff;
        for b in bytes.iter_mut().skip(2).take(29) {
            *b = 0xff;
        }
        bytes[31] = 0x7f;
        bytes
    };

    // ed25519 public key is little-endian y with sign bit in top bit of last byte
    let mut y_le = *ed_pub;
    y_le[31] &= 0x7f; // clear sign bit

    // Compute u = (1 + y) / (1 - y) mod p using big-integer arithmetic
    // We'll use a simple modular arithmetic implementation

    let y = le_bytes_to_bigint(&y_le);
    let p_big = le_bytes_to_bigint(&p);
    let one = [1u8; 1];
    let one_big = le_bytes_to_bigint(&one);

    // numerator = 1 + y
    let num = bigint_add_mod(&one_big, &y, &p_big);
    // denominator = 1 - y (= p + 1 - y since we work mod p)
    let denom = bigint_sub_mod(&one_big, &y, &p_big);
    // denom_inv = denom^(p-2) mod p (Fermat's little theorem)
    let denom_inv = bigint_pow_mod(&denom, &bigint_sub(&p_big, &[2]), &p_big);
    // u = num * denom_inv mod p
    let u = bigint_mul_mod(&num, &denom_inv, &p_big);

    let mut out = [0u8; 32];
    bigint_to_le_bytes(&u, &mut out);
    Ok(out)
}

// ---------------------------------------------------------------------------
// NaCl box operations
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

/// Encrypt a message with a precomputed NaCl box (XSalsa20-Poly1305).
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

/// Decrypt a message with a precomputed NaCl box (XSalsa20-Poly1305).
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

/// Convert a u64 counter to a 24-byte NaCl nonce.
///
/// Format: 16 zero bytes followed by 8 bytes big-endian u64.
/// Matches Go's `nonceForUint64`.
pub(crate) fn nonce_for_u64(value: u64) -> [u8; BOX_NONCE_SIZE] {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    nonce[16..24].copy_from_slice(&value.to_be_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// Simple big-integer arithmetic (for Ed25519→Curve25519 conversion)
//
// Numbers are represented as Vec<u8> in big-endian format.
// This is only used during key conversion, not in the hot path.
// ---------------------------------------------------------------------------

fn le_bytes_to_bigint(le: &[u8]) -> Vec<u8> {
    let mut be: Vec<u8> = le.iter().rev().copied().collect();
    // Remove leading zeros
    while be.len() > 1 && be[0] == 0 {
        be.remove(0);
    }
    be
}

fn bigint_to_le_bytes(be: &[u8], out: &mut [u8; 32]) {
    out.fill(0);
    let len = be.len().min(32);
    for i in 0..len {
        out[i] = be[be.len() - 1 - i];
    }
}

fn bigint_add_mod(a: &[u8], b: &[u8], m: &[u8]) -> Vec<u8> {
    let sum = bigint_add(a, b);
    bigint_mod(&sum, m)
}

fn bigint_sub_mod(a: &[u8], b: &[u8], m: &[u8]) -> Vec<u8> {
    // (a - b) mod m = (a + m - b) mod m
    let a_plus_m = bigint_add(a, m);
    let diff = bigint_sub(&a_plus_m, b);
    bigint_mod(&diff, m)
}

fn bigint_mul_mod(a: &[u8], b: &[u8], m: &[u8]) -> Vec<u8> {
    let prod = bigint_mul(a, b);
    bigint_mod(&prod, m)
}

fn bigint_pow_mod(base: &[u8], exp: &[u8], m: &[u8]) -> Vec<u8> {
    if exp.is_empty() || (exp.len() == 1 && exp[0] == 0) {
        return vec![1];
    }

    let mut result = vec![1u8];
    let base = bigint_mod(base, m);

    // Convert exponent to bits
    let mut bits = Vec::new();
    for &byte in exp {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }
    // Remove leading zeros
    let start = bits.iter().position(|&b| b == 1).unwrap_or(bits.len());

    for &bit in &bits[start..] {
        result = bigint_mul_mod(&result, &result, m);
        if bit == 1 {
            result = bigint_mul_mod(&result, &base, m);
        }
    }

    result
}

fn bigint_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = a.len().max(b.len());
    let mut result = vec![0u8; max_len + 1];
    let mut carry: u16 = 0;

    for i in 0..max_len {
        let ai = if i < a.len() { a[a.len() - 1 - i] as u16 } else { 0 };
        let bi = if i < b.len() { b[b.len() - 1 - i] as u16 } else { 0 };
        let sum = ai + bi + carry;
        result[max_len - i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    result[0] = carry as u8;

    // Remove leading zeros
    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    result
}

fn bigint_sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    // Assumes a >= b
    let mut result = vec![0u8; a.len()];
    let mut borrow: i16 = 0;

    for i in 0..a.len() {
        let ai = a[a.len() - 1 - i] as i16;
        let bi = if i < b.len() { b[b.len() - 1 - i] as i16 } else { 0 };
        let mut diff = ai - bi - borrow;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result[a.len() - 1 - i] = diff as u8;
    }

    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    result
}

fn bigint_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; a.len() + b.len()];

    let rlen = result.len();
    for i in 0..a.len() {
        let mut carry: u32 = 0;
        for j in 0..b.len() {
            let idx = rlen - 1 - i - j;
            let prod = (a[a.len() - 1 - i] as u32) * (b[b.len() - 1 - j] as u32)
                + result[idx] as u32
                + carry;
            result[idx] = (prod & 0xFF) as u8;
            carry = prod >> 8;
        }
        result[rlen - 1 - i - b.len()] += carry as u8;
    }

    while result.len() > 1 && result[0] == 0 {
        result.remove(0);
    }
    result
}

fn bigint_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    // Strip leading zeros
    let a_start = a.iter().position(|&x| x != 0).unwrap_or(a.len());
    let b_start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    let a = &a[a_start..];
    let b = &b[b_start..];

    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    a.cmp(b)
}

fn bigint_mod(a: &[u8], m: &[u8]) -> Vec<u8> {
    bigint_divmod(a, m).1
}

fn bigint_divmod(a: &[u8], m: &[u8]) -> (Vec<u8>, Vec<u8>) {
    if bigint_cmp(a, m) == std::cmp::Ordering::Less {
        return (vec![0], a.to_vec());
    }

    // Simple long division
    let mut remainder = Vec::new();
    let mut quotient = Vec::new();

    for &byte in a {
        remainder.push(byte);
        // Remove leading zeros from remainder
        while remainder.len() > 1 && remainder[0] == 0 {
            remainder.remove(0);
        }

        let mut q_byte = 0u8;
        while bigint_cmp(&remainder, m) != std::cmp::Ordering::Less {
            remainder = bigint_sub(&remainder, m);
            q_byte += 1;
        }
        quotient.push(q_byte);
    }

    while quotient.len() > 1 && quotient[0] == 0 {
        quotient.remove(0);
    }
    while remainder.len() > 1 && remainder[0] == 0 {
        remainder.remove(0);
    }

    (quotient, remainder)
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
