use std::fmt;

use ed25519_dalek::SigningKey;

/// Ed25519 public key used as a network address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Addr(pub [u8; 32]);

impl Addr {
    pub fn network(&self) -> &'static str {
        "ed25519"
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Addr({})", self)
    }
}

impl From<[u8; 32]> for Addr {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Addr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Errors returned by ironwood operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("encode error")]
    Encode,
    #[error("decode error")]
    Decode,
    #[error("connection closed")]
    Closed,
    #[error("operation timed out")]
    Timeout,
    #[error("bad message")]
    BadMessage,
    #[error("empty message")]
    EmptyMessage,
    #[error("oversized message")]
    OversizedMessage,
    #[error("unrecognized message type")]
    UnrecognizedMessage,
    #[error("peer not found")]
    PeerNotFound,
    #[error("bad address")]
    BadAddress,
    #[error("bad key")]
    BadKey,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Trait for transport connections used by peers.
/// Any async bidirectional byte stream (TCP, TLS, WebSocket, etc.).
pub trait AsyncConn: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}

// Blanket implementation: anything that satisfies the bounds is an AsyncConn.
impl<T> AsyncConn for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static
{}

/// The main packet connection trait.
#[async_trait::async_trait]
pub trait PacketConn: Send + Sync {
    /// Receive a packet. Returns (bytes_read, source_address).
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)>;

    /// Send a packet to the given address.
    async fn write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize>;

    /// Accept a peer connection with the given public key and priority.
    async fn handle_conn(
        &self,
        key: Addr,
        conn: Box<dyn AsyncConn>,
        prio: u8,
    ) -> Result<()>;

    /// Check if the connection is closed.
    fn is_closed(&self) -> bool;

    /// Get the local signing key.
    fn private_key(&self) -> &SigningKey;

    /// Maximum transmission unit (largest safe payload size).
    fn mtu(&self) -> u64;

    /// Initiate a path lookup for the given target address.
    async fn send_lookup(&self, target: Addr);

    /// Close the connection.
    async fn close(&self) -> Result<()>;

    /// Get the local address (our public key).
    fn local_addr(&self) -> Addr;
}
