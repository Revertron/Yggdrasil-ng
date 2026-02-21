//! High-level Messenger API for Yggdrasil stream connections.
//!
//! Mirrors the API of yggquic-new's `Messenger` (messenger.go) so Android apps
//! can use an identical mental model regardless of which transport they pick.
//!
//! # Design
//!
//! ```text
//!  App thread (blocking)
//!       │
//!  Messenger::connect() / accept()
//!       │  rt.block_on(...)
//!       ▼
//!  tokio Runtime (owned by Messenger)
//!       ├── ConnectHandle (Arc-cloned, &self connect)
//!       └── Background accept task
//!             owns mpsc::Receiver<Arc<Connection>>  ← no lock, no contention
//!             spawns per-connection stream-accept tasks
//!             pushes (Stream, pubkey) to Messenger::incoming_rx
//! ```
//!
//! The connect side and accept side are fully decoupled:
//! - Connect: cloneable `ConnectHandle` with `&self` — no blocking mutex.
//! - Accept: exclusive ownership of the incoming-connection receiver — no lock needed.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing::warn;

use yggdrasil::config::Config;
use yggdrasil::core::Core;

use crate::manager::ConnectHandle;
use crate::stream::Stream;
use crate::StreamManager;

// ── Conn ─────────────────────────────────────────────────────────────────────

/// A single bidirectional stream to a remote Yggdrasil peer.
///
/// All I/O methods are **blocking** (suitable for calling from Java/Kotlin on Android).
/// Timeout variants accept milliseconds (`i64`; ≤ 0 means no timeout).
pub struct Conn {
    stream: Arc<TokioMutex<Stream>>,
    /// Remote peer's 32-byte ed25519 public key.
    public_key: Vec<u8>,
    rt: Arc<Runtime>,
}

impl Conn {
    /// Remote peer's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Returns `true` while the stream is open.
    pub fn is_alive(&self) -> bool {
        self.rt.block_on(async {
            let s = self.stream.lock().await;
            matches!(s.state().await, crate::StreamState::Open | crate::StreamState::Opening)
        })
    }

    /// Blocking read. Fills `buf` and returns the number of bytes read.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, String> {
        let stream = self.stream.clone();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            AsyncReadExt::read(&mut *s, buf)
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking read with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn read_with_timeout(&self, buf: &mut [u8], timeout_ms: i64) -> Result<usize, String> {
        let stream = self.stream.clone();
        if timeout_ms <= 0 {
            return self.read(buf);
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            tokio::time::timeout(dur, AsyncReadExt::read(&mut *s, buf))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking write. Returns the number of bytes written.
    pub fn write(&self, buf: &[u8]) -> Result<usize, String> {
        let stream = self.stream.clone();
        let data = buf.to_vec();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            AsyncWriteExt::write(&mut *s, &data)
                .await
                .map_err(|e| e.to_string())
        })
    }

    /// Blocking write with timeout (milliseconds). Returns `Err("timeout")` on expiry.
    pub fn write_with_timeout(&self, buf: &[u8], timeout_ms: i64) -> Result<usize, String> {
        let stream = self.stream.clone();
        let data = buf.to_vec();
        if timeout_ms <= 0 {
            return self.write(buf);
        }
        let dur = Duration::from_millis(timeout_ms as u64);
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            tokio::time::timeout(dur, AsyncWriteExt::write(&mut *s, &data))
                .await
                .map_err(|_| "timeout".to_string())?
                .map_err(|e| e.to_string())
        })
    }

    /// Close the stream gracefully.
    pub fn close(&self) {
        let stream = self.stream.clone();
        self.rt.block_on(async move {
            let mut s = stream.lock().await;
            let _ = s.shutdown().await;
        });
    }
}

// ── Messenger ─────────────────────────────────────────────────────────────────

/// High-level Yggdrasil messenger — manages a full node and provides
/// simple connect / accept / peer-management operations.
///
/// Mirrors yggquic-new's `Messenger` API for easy Android integration.
///
/// All methods are **blocking** (backed by an internal `tokio::Runtime`),
/// so they can be called directly from Java/Kotlin without any async plumbing.
pub struct Messenger {
    core: Arc<Core>,
    /// Connect-only handle (Arc-cloned, lock-free).
    handle: ConnectHandle,
    /// Incoming (Stream, pubkey) pairs produced by the background accept loop.
    incoming_rx: TokioMutex<mpsc::Receiver<(Stream, Vec<u8>)>>,
    rt: Arc<Runtime>,
}

impl Messenger {
    // ── constructors ──────────────────────────────────────────────────────

    /// Create a new node with a randomly generated key and connect to `peer_addr`.
    ///
    /// `peer_addr` uses Yggdrasil URI syntax, e.g. `"tcp://1.2.3.4:1234"`.
    /// Pass an empty string to start a node without any initial peers.
    pub fn new(peer_addr: &str) -> Result<Self, String> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut config = Config::default();
        if !peer_addr.is_empty() {
            config.peers = vec![peer_addr.to_string()];
        }
        Self::from_key_and_config(signing_key, config)
    }

    /// Create a node with a specific 32-byte signing key and a list of peers.
    pub fn new_with_key(signing_key_bytes: &[u8], peers: Vec<String>) -> Result<Self, String> {
        let bytes: [u8; 32] = signing_key_bytes
            .try_into()
            .map_err(|_| "signing key must be exactly 32 bytes".to_string())?;
        let signing_key = SigningKey::from_bytes(&bytes);
        let mut config = Config::default();
        config.peers = peers;
        Self::from_key_and_config(signing_key, config)
    }

    fn from_key_and_config(signing_key: SigningKey, config: Config) -> Result<Self, String> {
        let rt = Arc::new(Runtime::new().map_err(|e| e.to_string())?);

        // All async setup runs inside the runtime so tokio::spawn works correctly.
        let (core, handle, incoming_rx) = rt.block_on(async {
            let core = Core::new(signing_key, config);
            core.init_links().await;
            core.start().await;

            // Brief pause so TCP handshakes with bootstrap peers can begin.
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Create the stream manager and split it immediately:
            //   handle      → connect side (Arc-cloneable, &self)
            //   incoming_rx → accept side  (exclusive ownership, no lock)
            let manager = StreamManager::new(core.packet_conn());
            let (handle, conn_rx) = manager.split();

            // Channel that the background task will push (Stream, pubkey) pairs into.
            let (stream_tx, stream_rx) =
                mpsc::channel::<(Stream, Vec<u8>)>(64);

            // Background accept loop — owns conn_rx exclusively (no lock contention).
            let handle_clone = handle.clone();
            tokio::spawn(accept_loop(conn_rx, stream_tx, handle_clone));

            (core, handle, stream_rx)
        });

        Ok(Self {
            core,
            handle,
            incoming_rx: TokioMutex::new(incoming_rx),
            rt,
        })
    }

    // ── identity ──────────────────────────────────────────────────────────

    /// Local node's 32-byte ed25519 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.core.public_key().to_vec()
    }

    // ── connection API ────────────────────────────────────────────────────

    /// Open a stream to the remote peer identified by its 32-byte public key.
    ///
    /// Reuses an existing ironwood session if one exists; otherwise establishes
    /// a new one. Blocks until the stream handshake completes (≤ 30 s default).
    pub fn connect(&self, public_key: &[u8]) -> Result<Conn, String> {
        if public_key.len() != 32 {
            return Err("public_key must be exactly 32 bytes".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        let handle = self.handle.clone();
        let rt = self.rt.clone();

        let stream = rt.block_on(async move {
            let connection = handle.connect(addr).await.map_err(|e| e.to_string())?;
            connection.open_stream().await.map_err(|e| e.to_string())
        })?;

        Ok(Conn {
            stream: Arc::new(TokioMutex::new(stream)),
            public_key: public_key.to_vec(),
            rt: self.rt.clone(),
        })
    }

    /// Block until an incoming stream arrives and return it as a [`Conn`].
    pub fn accept(&self) -> Result<Conn, String> {
        let (stream, public_key) = self.rt.block_on(async {
            let mut rx = self.incoming_rx.lock().await;
            rx.recv().await.ok_or_else(|| "messenger closed".to_string())
        })?;

        Ok(Conn {
            stream: Arc::new(TokioMutex::new(stream)),
            public_key,
            rt: self.rt.clone(),
        })
    }

    // ── peer management ───────────────────────────────────────────────────

    /// Add a peer by URI (e.g. `"tcp://1.2.3.4:1234"` or `"tls://…"`).
    pub fn add_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.core.add_peer(addr))
    }

    /// Remove a peer by URI.
    pub fn remove_peer(&self, addr: &str) -> Result<(), String> {
        self.rt.block_on(self.core.remove_peer(addr))
    }

    /// Wake all sleeping peer reconnect loops so they retry immediately.
    pub fn retry_peers_now(&self) {
        self.rt.block_on(self.core.retry_peers_now());
    }

    /// Force-close and remove a cached stream connection to the peer with the given 32-byte public key.
    pub fn close_connection(&self, public_key: &[u8]) {
        if public_key.len() != 32 {
            return;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(public_key);
        let addr = ironwood::Addr::from(key);
        let handle = self.handle.clone();
        self.rt.block_on(async move { handle.close_connection(addr).await });
    }

    // ── network introspection ─────────────────────────────────────────────

    /// Peer list as a JSON array.
    ///
    /// Each element contains `key`, `address`, `uri`, `up`, `inbound`,
    /// `priority`, `rx_bytes`, `tx_bytes`, `rx_rate`, `tx_rate`, `uptime`.
    pub fn get_peers_json(&self) -> String {
        let peers = self.rt.block_on(self.core.get_peers());
        let arr: Vec<serde_json::Value> = peers
            .iter()
            .map(|p| {
                let address = yggdrasil::address::addr_for_key(&p.key);
                serde_json::json!({
                    "key":      hex::encode(p.key),
                    "address":  address.to_string(),
                    "uri":      p.uri,
                    "up":       p.up,
                    "inbound":  p.inbound,
                    "priority": p.priority,
                    "latency":  p.latency_ms,
                    "cost":     p.cost,
                    "rx_bytes": p.rx_bytes,
                    "tx_bytes": p.tx_bytes,
                    "rx_rate":  p.rx_rate,
                    "tx_rate":  p.tx_rate,
                    "uptime":   p.uptime_secs,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    /// Cached routing paths as a JSON array.
    ///
    /// Each element contains `key`, `address`, `path` (port sequence), `sequence`.
    pub fn get_paths_json(&self) -> String {
        let paths = self.rt.block_on(self.core.get_paths());
        let arr: Vec<serde_json::Value> = paths
            .iter()
            .map(|p| {
                let address = yggdrasil::address::addr_for_key(&p.key);
                serde_json::json!({
                    "key":      hex::encode(p.key),
                    "address":  address.to_string(),
                    "path":     p.path,
                    "sequence": p.sequence,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    /// Spanning-tree entries as a JSON array.
    ///
    /// Each element contains `key`, `address`, `parent`, `sequence`.
    pub fn get_tree_json(&self) -> String {
        let tree = self.rt.block_on(self.core.get_tree());
        let arr: Vec<serde_json::Value> = tree
            .iter()
            .map(|t| {
                let address = yggdrasil::address::addr_for_key(&t.key);
                serde_json::json!({
                    "key":      hex::encode(t.key),
                    "address":  address.to_string(),
                    "parent":   hex::encode(t.parent),
                    "sequence": t.sequence,
                })
            })
            .collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    }

    // ── lifecycle ─────────────────────────────────────────────────────────

    /// Shut down the node and all background tasks.
    pub fn close(&self) {
        self.rt.block_on(async {
            let _ = self.core.close().await;
        });
    }
}

// ── Background accept loop ────────────────────────────────────────────────────

/// Continuously accepts connections from the exclusive receiver, then accepts
/// streams from each connection and pushes them into `stream_tx`.
///
/// Owns `conn_rx` exclusively — no mutex, no lock contention with connect side.
async fn accept_loop(
    mut conn_rx: mpsc::Receiver<Arc<crate::Connection>>,
    stream_tx: mpsc::Sender<(Stream, Vec<u8>)>,
    _handle: ConnectHandle, // kept alive so the writer tasks can run
) {
    while let Some(connection) = conn_rx.recv().await {
        let public_key = connection.peer_addr().0.to_vec();
        let tx = stream_tx.clone();

        // Spawn a per-connection task that accepts all streams from this peer.
        tokio::spawn(async move {
            loop {
                match connection.accept_stream().await {
                    Ok(stream) => {
                        if tx.send((stream, public_key.clone())).await.is_err() {
                            break; // Messenger dropped
                        }
                    }
                    Err(_) => break, // connection closed
                }
            }
        });
    }
    warn!("accept_loop: incoming connection receiver closed");
}