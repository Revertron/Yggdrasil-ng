//! UniFFI export layer for ygg_stream.
//!
//! Provides `FfiMessenger` and `FfiConn` — thin wrappers around [`Messenger`]
//! and [`Conn`] that are annotated for UniFFI so Kotlin/Swift bindings can be
//! generated automatically.
//!
//! Key design difference from the native Rust API:
//! - `read_with_timeout` returns `Vec<u8>` instead of filling a mutable buffer
//!   (UniFFI cannot express in-place mutation of a byte array).
//!   The Kotlin wrapper copies the returned bytes into the caller's buffer.

use std::sync::Arc;

use crate::messenger::{Conn, Messenger};

// ── Error type ────────────────────────────────────────────────────────────────

/// Error returned by the UniFFI-exposed API.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum YggError {
    #[error("{0}")]
    Generic(String),
}

impl From<String> for YggError {
    fn from(s: String) -> Self {
        YggError::Generic(s)
    }
}

// ── FfiMessenger ──────────────────────────────────────────────────────────────

/// UniFFI-exported Yggdrasil messenger node.
///
/// Wraps [`Messenger`] so that the blocking API is accessible from Kotlin/Swift
/// via the generated UniFFI bindings.
#[derive(uniffi::Object)]
pub struct FfiMessenger(Messenger);

#[uniffi::export]
impl FfiMessenger {
    /// Create a node with a random key and connect to one initial peer.
    ///
    /// Pass an empty string to start without any initial peers.
    #[uniffi::constructor]
    pub fn new_(peer_addr: String) -> Result<Arc<FfiMessenger>, YggError> {
        Messenger::new(&peer_addr)
            .map(|m| Arc::new(FfiMessenger(m)))
            .map_err(YggError::Generic)
    }

    /// Create a node with a specific 32-byte signing key and a list of peers.
    #[uniffi::constructor]
    pub fn new_with_key(
        key_bytes: Vec<u8>,
        peers: Vec<String>,
    ) -> Result<Arc<FfiMessenger>, YggError> {
        Messenger::new_with_key(&key_bytes, peers)
            .map(|m| Arc::new(FfiMessenger(m)))
            .map_err(YggError::Generic)
    }

    /// Local node's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }

    /// Open a stream to the peer identified by its 32-byte public key.
    pub fn connect(&self, public_key: Vec<u8>) -> Result<Arc<FfiConn>, YggError> {
        self.0
            .connect(&public_key)
            .map(|c| Arc::new(FfiConn(c)))
            .map_err(YggError::Generic)
    }

    /// Block until an incoming stream arrives.
    pub fn accept(&self) -> Result<Arc<FfiConn>, YggError> {
        self.0
            .accept()
            .map(|c| Arc::new(FfiConn(c)))
            .map_err(YggError::Generic)
    }

    /// Add a peer by URI (e.g. `"tcp://1.2.3.4:1234"` or `"tls://…"`).
    pub fn add_peer(&self, addr: String) -> Result<(), YggError> {
        self.0.add_peer(&addr).map_err(YggError::Generic)
    }

    /// Remove a peer by URI.
    pub fn remove_peer(&self, addr: String) -> Result<(), YggError> {
        self.0.remove_peer(&addr).map_err(YggError::Generic)
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.0.retry_peers_now();
    }

    /// Force-close the cached stream connection to the peer with the given public key.
    pub fn close_connection(&self, public_key: Vec<u8>) {
        self.0.close_connection(&public_key);
    }

    /// Peer list as a JSON array.
    pub fn get_peers_json(&self) -> String {
        self.0.get_peers_json()
    }

    /// Cached routing paths as a JSON array.
    pub fn get_paths_json(&self) -> String {
        self.0.get_paths_json()
    }

    /// Spanning-tree entries as a JSON array.
    pub fn get_tree_json(&self) -> String {
        self.0.get_tree_json()
    }

}

// Closing the Messenger is triggered by UniFFI's Disposable.close() → destroy()
// → Rust drop, so we implement Drop rather than exporting a `close()` method
// (which would conflict with the Disposable-generated `fun close()` in Kotlin).
impl Drop for FfiMessenger {
    fn drop(&mut self) {
        self.0.close();
    }
}

// ── FfiConn ───────────────────────────────────────────────────────────────────

/// UniFFI-exported bidirectional stream to a remote Yggdrasil peer.
#[derive(uniffi::Object)]
pub struct FfiConn(Conn);

#[uniffi::export]
impl FfiConn {
    /// Remote peer's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public_key()
    }

    /// Returns `true` while the stream is open.
    pub fn is_alive(&self) -> bool {
        self.0.is_alive()
    }

    /// Read up to `max_bytes` from the stream and return them.
    ///
    /// The Kotlin wrapper copies the returned bytes into the caller's buffer
    /// (UniFFI cannot express mutable byte-array arguments for in-place fills).
    ///
    /// `timeout_ms ≤ 0` means no timeout.
    pub fn read_with_timeout(
        &self,
        max_bytes: u64,
        timeout_ms: i64,
    ) -> Result<Vec<u8>, YggError> {
        let mut buf = vec![0u8; max_bytes as usize];
        let n = if timeout_ms <= 0 {
            self.0.read(&mut buf).map_err(YggError::Generic)?
        } else {
            self.0
                .read_with_timeout(&mut buf, timeout_ms)
                .map_err(YggError::Generic)?
        };
        buf.truncate(n);
        Ok(buf)
    }

    /// Write `data` to the stream with an optional timeout.
    ///
    /// Returns the number of bytes written. `timeout_ms ≤ 0` means no timeout.
    pub fn write_with_timeout(
        &self,
        data: Vec<u8>,
        timeout_ms: i64,
    ) -> Result<u64, YggError> {
        self.0
            .write_with_timeout(&data, timeout_ms)
            .map(|n| n as u64)
            .map_err(YggError::Generic)
    }

    /// Write `data` to the stream (no timeout).
    pub fn write(&self, data: Vec<u8>) -> Result<u64, YggError> {
        self.0
            .write(&data)
            .map(|n| n as u64)
            .map_err(YggError::Generic)
    }

}

// Same pattern as FfiMessenger: close on drop rather than exporting close().
impl Drop for FfiConn {
    fn drop(&mut self) {
        self.0.close();
    }
}
