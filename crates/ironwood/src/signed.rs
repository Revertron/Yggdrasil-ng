//! Signed PacketConn wrapper.
//!
//! Wraps a network-level `PacketConnImpl` with Ed25519 signature authentication.
//! Each packet is prepended with a 64-byte signature on send and verified on read.
//! No encryption is provided — this is for restricted networks (e.g. amateur radio)
//! where encryption is prohibited but authentication is desired.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::core::PacketConnImpl;
use crate::crypto::{Crypto, PublicKey, SIGNATURE_SIZE};
use crate::types::{Addr, Error, Result};

/// Channel capacity for delivering verified traffic to readers.
const RECV_CHANNEL_SIZE: usize = 64;

/// Verified incoming message.
struct VerifiedMessage {
    source: PublicKey,
    data: Vec<u8>,
}

/// Signed PacketConn: wraps a network `PacketConnImpl` with Ed25519 signatures.
pub struct SignedPacketConn {
    /// The underlying network-level PacketConn.
    inner: Arc<PacketConnImpl>,
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Channel for delivering verified traffic to read_from.
    recv_rx: Mutex<mpsc::Receiver<VerifiedMessage>>,
    /// Whether this conn is closed.
    closed: AtomicBool,
    /// Cancellation for background tasks.
    cancel: CancellationToken,
    /// Reader task handle.
    _reader_handle: JoinHandle<()>,
}

impl SignedPacketConn {
    /// Create a new SignedPacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let pub_key = secret.verifying_key().to_bytes();
        let inner = Arc::new(PacketConnImpl::new(secret.clone(), config));
        let (recv_tx, recv_rx) = mpsc::channel(RECV_CHANNEL_SIZE);
        let cancel = CancellationToken::new();

        let reader_handle = {
            let inner = inner.clone();
            let recv_tx = recv_tx.clone();
            let cancel = cancel.clone();
            let our_pub = pub_key;
            tokio::spawn(signed_reader_loop(inner, recv_tx, cancel, our_pub))
        };

        Self {
            inner,
            signing_key: secret,
            recv_rx: Mutex::new(recv_rx),
            closed: AtomicBool::new(false),
            cancel,
            _reader_handle: reader_handle,
        }
    }

    /// Sign a message for a specific recipient.
    ///
    /// Signs `[toKey || msg]` and returns `[signature(64) || msg]`.
    fn sign(&self, to_key: &PublicKey, msg: &[u8]) -> Vec<u8> {
        let mut sig_bytes = Vec::with_capacity(32 + msg.len());
        sig_bytes.extend_from_slice(to_key);
        sig_bytes.extend_from_slice(msg);

        let sig = Crypto::sign_with_key(&self.signing_key, &sig_bytes);

        let mut out = Vec::with_capacity(SIGNATURE_SIZE + msg.len());
        out.extend_from_slice(&sig);
        out.extend_from_slice(msg);
        out
    }

    /// Verify and unpack a signed message.
    ///
    /// Verifies signature over `[ourPubKey || msg]` from sender's key.
    fn unpack(our_pub: &PublicKey, bs: &[u8], from_key: &PublicKey) -> Option<Vec<u8>> {
        if bs.len() < SIGNATURE_SIZE {
            return None;
        }

        let mut sig = [0u8; SIGNATURE_SIZE];
        sig.copy_from_slice(&bs[..SIGNATURE_SIZE]);
        let msg = &bs[SIGNATURE_SIZE..];

        let mut sig_bytes = Vec::with_capacity(32 + msg.len());
        sig_bytes.extend_from_slice(our_pub);
        sig_bytes.extend_from_slice(msg);

        if Crypto::verify(from_key, &sig_bytes, &sig) {
            Some(msg.to_vec())
        } else {
            None
        }
    }
}

/// Background reader loop: reads from inner PacketConn, verifies signatures, delivers.
async fn signed_reader_loop(
    inner: Arc<PacketConnImpl>,
    recv_tx: mpsc::Sender<VerifiedMessage>,
    cancel: CancellationToken,
    our_pub: PublicKey,
) {
    use crate::types::PacketConn;

    let mut buf = vec![0u8; 128 * 1024];

    loop {
        let read_result = tokio::select! {
            _ = cancel.cancelled() => break,
            result = inner.read_from(&mut buf) => result,
        };

        let (n, from_addr) = match read_result {
            Ok((n, addr)) => (n, addr),
            Err(_) => break,
        };

        let from_key = from_addr.0;
        let data = &buf[..n];

        if let Some(msg) = SignedPacketConn::unpack(&our_pub, data, &from_key) {
            let verified = VerifiedMessage {
                source: from_key,
                data: msg,
            };
            if recv_tx.send(verified).await.is_err() {
                return;
            }
        }
        // Invalid signatures are silently dropped (matching Go behavior)
    }
}

#[async_trait::async_trait]
impl crate::types::PacketConn for SignedPacketConn {
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let mut rx = self.recv_rx.lock().await;
        let cancel = self.cancel.clone();

        let msg = tokio::select! {
            _ = cancel.cancelled() => return Err(Error::Closed),
            msg = rx.recv() => match msg {
                Some(m) => m,
                None => return Err(Error::Closed),
            },
        };

        let n = buf.len().min(msg.data.len());
        buf[..n].copy_from_slice(&msg.data[..n]);
        Ok((n, Addr(msg.source)))
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let mtu = self.mtu();
        if buf.len() as u64 > mtu {
            return Err(Error::OversizedMessage);
        }

        let dest = addr.0;
        let signed_msg = self.sign(&dest, buf);

        let _ = self.inner.write_to(&signed_msg, addr).await?;

        Ok(buf.len())
    }

    async fn handle_conn(
        &self,
        key: Addr,
        conn: Box<dyn crate::types::AsyncConn>,
        prio: u8,
    ) -> Result<()> {
        self.inner.handle_conn(key, conn, prio).await
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        self.inner.mtu().saturating_sub(SIGNATURE_SIZE as u64)
    }

    async fn send_lookup(&self, target: Addr) {
        self.inner.send_lookup(target).await;
    }

    async fn close(&self) -> Result<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Closed);
        }

        self.cancel.cancel();
        self.inner.close().await
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }
}

/// Create a new SignedPacketConn.
pub fn new_signed_packet_conn(secret: SigningKey, config: Config) -> Arc<SignedPacketConn> {
    Arc::new(SignedPacketConn::new(secret, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn signed_create_and_close() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_signed_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn signed_mtu_accounts_for_overhead() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = new_signed_packet_conn(key.clone(), Config::default());

        use crate::types::PacketConn;
        let inner_conn = crate::core::new_packet_conn(key, Config::default());
        let inner_mtu = inner_conn.mtu();
        let signed_mtu = conn.mtu();

        assert!(signed_mtu < inner_mtu);
        assert_eq!(signed_mtu, inner_mtu - SIGNATURE_SIZE as u64);

        conn.close().await.unwrap();
        inner_conn.close().await.unwrap();
    }

    #[tokio::test]
    async fn sign_and_unpack() {
        let key_a = SigningKey::generate(&mut OsRng);
        let pub_a = key_a.verifying_key().to_bytes();
        let key_b = SigningKey::generate(&mut OsRng);
        let pub_b = key_b.verifying_key().to_bytes();

        let conn_a = SignedPacketConn {
            inner: Arc::new(PacketConnImpl::new(key_a.clone(), Config::default())),
            signing_key: key_a,
            recv_rx: Mutex::new(mpsc::channel(1).1),
            closed: AtomicBool::new(false),
            cancel: CancellationToken::new(),
            _reader_handle: tokio::spawn(async {}),
        };

        let msg = b"hello world";
        let signed = conn_a.sign(&pub_b, msg);

        assert_eq!(signed.len(), SIGNATURE_SIZE + msg.len());

        // B can unpack it (verifying against B's own pub key)
        let unpacked = SignedPacketConn::unpack(&pub_b, &signed, &pub_a);
        assert!(unpacked.is_some());
        assert_eq!(unpacked.unwrap(), msg);

        // Wrong key fails
        let wrong = SignedPacketConn::unpack(&pub_a, &signed, &pub_a);
        assert!(wrong.is_none());
    }
}
