use thiserror::Error;

/// Errors that can occur in stream operations
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Ironwood error
    #[error("Ironwood error: {0}")]
    Ironwood(#[from] ironwood::Error),

    /// Protocol error (malformed packet, invalid state transition, etc.)
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Stream closed by remote peer
    #[error("Stream closed by peer")]
    StreamClosed,

    /// Stream was reset (aborted)
    #[error("Stream reset")]
    StreamReset,

    /// Connection closed
    #[error("Connection closed")]
    ConnectionClosed,

    /// Invalid stream ID
    #[error("Invalid stream ID: {0}")]
    InvalidStreamId(u32),

    /// Stream already exists
    #[error("Stream already exists: {0}")]
    StreamExists(u32),

    /// Packet too large
    #[error("Packet too large: {0} bytes (max {1})")]
    PacketTooLarge(usize, usize),

    /// Timeout waiting for operation
    #[error("Operation timed out")]
    Timeout,

    /// Flow control violation
    #[error("Flow control violation: attempted to send {0} bytes but window is {1}")]
    FlowControl(usize, usize),
}

pub type Result<T> = std::result::Result<T, Error>;
