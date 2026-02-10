use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fmt::Debug;

use crate::types::Addr;

pub(crate) const PUBLIC_KEY_SIZE: usize = 32;
pub(crate) const SIGNATURE_SIZE: usize = 64;

/// Fixed-size public key for internal use.
pub(crate) type PublicKey = [u8; PUBLIC_KEY_SIZE];

/// Fixed-size signature for internal use.
pub(crate) type Sig = [u8; SIGNATURE_SIZE];

/// Cryptographic identity: holds signing key and derived public key.
pub(crate) struct Crypto {
    pub signing_key: SigningKey,
    pub public_key: PublicKey,
}

impl Crypto {
    pub fn new(signing_key: SigningKey) -> Self {
        let public_key: PublicKey = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Sign a message with our private key.
    pub fn sign(&self, message: &[u8]) -> Sig {
        let sig = self.signing_key.sign(message);
        sig.to_bytes()
    }

    /// Verify a signature from the given public key.
    pub fn verify(key: &PublicKey, message: &[u8], sig: &Sig) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(key) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(sig) else {
            return false;
        };
        verifying_key.verify(message, &signature).is_ok()
    }

    /// Sign a message with an arbitrary signing key.
    pub fn sign_with_key(key: &SigningKey, message: &[u8]) -> Sig {
        let sig = key.sign(message);
        sig.to_bytes()
    }

    /// Get our public key as an Addr.
    pub fn addr(&self) -> Addr {
        Addr(self.public_key)
    }
}

/// Compare two public keys (for root election: smallest key wins).
pub(crate) fn key_less(a: &PublicKey, b: &PublicKey) -> bool {
    a < b
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let crypto = Crypto::new(signing_key);
        let message = b"hello ironwood";
        let sig = crypto.sign(message);
        assert!(Crypto::verify(&crypto.public_key, message, &sig));
    }

    #[test]
    fn verify_wrong_message_fails() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let crypto = Crypto::new(signing_key);
        let sig = crypto.sign(b"correct");
        assert!(!Crypto::verify(&crypto.public_key, b"wrong", &sig));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let crypto1 = Crypto::new(key1);
        let crypto2 = Crypto::new(key2);
        let sig = crypto1.sign(b"test");
        assert!(!Crypto::verify(&crypto2.public_key, b"test", &sig));
    }
}
