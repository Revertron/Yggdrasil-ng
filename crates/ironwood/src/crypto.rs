use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

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
    ///
    /// Low-order and non-canonical keys are rejected outright: signatures for
    /// them can be forged without a private key, which would e.g. let anyone
    /// relay a tree announcement claiming the all-zero (lowest, so root) key.
    /// Go only checks direct peers and session inits; checking every signature
    /// here also covers relayed announcements, without changing the wire format.
    pub fn verify(key: &PublicKey, message: &[u8], sig: &Sig) -> bool {
        if !crate::types::is_public_key_valid(key) {
            return false;
        }
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

    /// Identity-point key with R = identity and s = 0 satisfies the
    /// (cofactorless) verification equation for *any* message.
    #[test]
    fn forged_signature_for_low_order_key_rejected() {
        let mut key = [0u8; 32];
        key[0] = 1; // compressed identity point
        let mut sig = [0u8; 64];
        sig[0] = 1; // R = identity, s = 0
        let message = b"anything at all";

        // Plain ed25519 verification accepts the forgery...
        let vk = VerifyingKey::from_bytes(&key).expect("identity decodes");
        assert!(vk.verify(message, &Signature::from_bytes(&sig)).is_ok());
        // ...Crypto::verify must not.
        assert!(!Crypto::verify(&key, message, &sig));
    }
}
