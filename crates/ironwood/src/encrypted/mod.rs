//! Encrypted PacketConn wrapper.
//!
//! Wraps a network-level `PacketConnImpl` with end-to-end NaCl box encryption,
//! session management, and key ratcheting for forward secrecy.

pub(crate) mod crypto;
pub(crate) mod session;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::core::PacketConnImpl;
use crate::types::{Addr, Error, Result};

use self::crypto::{ed25519_private_to_curve25519, CurvePrivateKey};
use self::session::{OutAction, SessionManager, SESSION_TRAFFIC_OVERHEAD};

/// Channel capacity for delivering decrypted traffic to readers.
const RECV_CHANNEL_SIZE: usize = 64;

/// Decrypted incoming message.
struct DecryptedMessage {
    source: crate::crypto::PublicKey,
    data: Vec<u8>,
}

/// Encrypted PacketConn: wraps a network `PacketConnImpl` with encryption.
pub struct EncryptedPacketConn {
    /// The underlying network-level PacketConn.
    inner: Arc<PacketConnImpl>,
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Our Curve25519 private key (derived from Ed25519).
    curve_priv: CurvePrivateKey,
    /// Session manager (shared with reader task).
    sessions: Arc<Mutex<SessionManager>>,
    /// Channel for delivering decrypted traffic to read_from.
    recv_rx: Mutex<mpsc::Receiver<DecryptedMessage>>,
    recv_tx: mpsc::Sender<DecryptedMessage>,
    /// Whether this conn is closed.
    closed: AtomicBool,
    /// Cancellation for background tasks.
    cancel: CancellationToken,
    /// Reader task handle.
    _reader_handle: JoinHandle<()>,
}

impl EncryptedPacketConn {
    /// Create a new EncryptedPacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let curve_priv = ed25519_private_to_curve25519(&secret);
        let inner = Arc::new(PacketConnImpl::new(secret.clone(), config));
        let sessions = Arc::new(Mutex::new(SessionManager::new()));
        let (recv_tx, recv_rx) = mpsc::channel(RECV_CHANNEL_SIZE);
        let cancel = CancellationToken::new();

        // Spawn reader task: reads from inner, decrypts, delivers
        let reader_handle = {
            let inner = inner.clone();
            let sessions = sessions.clone();
            let recv_tx = recv_tx.clone();
            let cancel = cancel.clone();
            let signing_key = secret.clone();
            let curve_priv = curve_priv;
            tokio::spawn(encrypted_reader_loop(
                inner,
                sessions,
                recv_tx,
                cancel,
                signing_key,
                curve_priv,
            ))
        };

        Self {
            inner,
            signing_key: secret,
            curve_priv,
            sessions,
            recv_rx: Mutex::new(recv_rx),
            recv_tx,
            closed: AtomicBool::new(false),
            cancel,
            _reader_handle: reader_handle,
        }
    }

    /// Get info about all connected peers (delegates to inner).
    pub async fn get_peers(&self) -> Vec<crate::core::PeerInfo> {
        self.inner.get_peers().await
    }

    /// Get spanning tree entries (delegates to inner).
    pub async fn get_tree(&self) -> Vec<crate::core::TreeEntry> {
        self.inner.get_tree().await
    }

    /// Get the number of routing entries.
    pub async fn routing_entries(&self) -> usize {
        self.inner.routing_entries().await
    }
}

/// Background reader loop: reads from inner PacketConn, decrypts via sessions, delivers.
async fn encrypted_reader_loop(
    inner: Arc<PacketConnImpl>,
    sessions: Arc<Mutex<SessionManager>>,
    recv_tx: mpsc::Sender<DecryptedMessage>,
    cancel: CancellationToken,
    signing_key: SigningKey,
    curve_priv: CurvePrivateKey,
) {
    use crate::types::PacketConn;

    let mut buf = vec![0u8; 128 * 1024]; // 128 KB buffer

    loop {
        tracing::debug!("encrypted_reader_loop");
        let read_result = tokio::select! {
            _ = cancel.cancelled() => break,
            result = inner.read_from(&mut buf) => result,
        };

        let (n, from_addr) = match read_result {
            Ok((n, addr)) => (n, addr),
            Err(_) => break,
        };

        let from_key = from_addr.0;
        let data = buf[..n].to_vec();

        // Decrypt via session manager
        let actions = {
            let mut mgr = sessions.lock().await;
            mgr.handle_data(&from_key, &data, &curve_priv, &signing_key)
        };

        // Process actions
        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    tracing::debug!("encrypted_reader: sending {} bytes to inner (session msg)", data.len());
                    let _ = inner.write_to(&data, &Addr(dest)).await;
                }
                OutAction::Deliver { source, data } => {
                    tracing::debug!("encrypted_reader: delivering {} bytes from {:?}", data.len(), hex::encode(&source[..4]));
                    let msg = DecryptedMessage { source, data };
                    if recv_tx.send(msg).await.is_err() {
                        return; // channel closed
                    }
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::types::PacketConn for EncryptedPacketConn {
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

        let actions = {
            let mut mgr = self.sessions.lock().await;
            mgr.write_to(&dest, buf, &self.signing_key)
        };

        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    let _ = self.inner.write_to(&data, &Addr(dest)).await;
                }
                OutAction::Deliver { source, data } => {
                    let msg = DecryptedMessage { source, data };
                    let _ = self.recv_tx.send(msg).await;
                }
            }
        }

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
        self.inner.mtu().saturating_sub(SESSION_TRAFFIC_OVERHEAD)
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

/// Create a new EncryptedPacketConn.
pub fn new_encrypted_packet_conn(secret: SigningKey, config: Config) -> Arc<EncryptedPacketConn> {
    Arc::new(EncryptedPacketConn::new(secret, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn encrypted_create_and_close() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_encrypted_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn encrypted_mtu_accounts_for_overhead() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = new_encrypted_packet_conn(key.clone(), Config::default());

        use crate::types::PacketConn;
        let inner_conn = crate::core::new_packet_conn(key, Config::default());
        let inner_mtu = inner_conn.mtu();
        let encrypted_mtu = conn.mtu();

        assert!(encrypted_mtu < inner_mtu);
        assert_eq!(encrypted_mtu, inner_mtu - SESSION_TRAFFIC_OVERHEAD);

        conn.close().await.unwrap();
        inner_conn.close().await.unwrap();
    }
}
