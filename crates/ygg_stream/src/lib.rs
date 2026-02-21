//! Stream multiplexing library for Yggdrasil mesh network
//!
//! This crate provides QUIC-like stream multiplexing on top of ironwood's
//! `EncryptedPacketConn`. It allows applications to:
//!
//! - Open multiple concurrent streams per peer connection
//! - Use standard Rust async I/O traits (AsyncRead, AsyncWrite)
//! - Avoid MTU concerns - streams provide continuous byte streams
//! - Leverage Yggdrasil's existing encryption (no additional overhead)
//!
//! # Architecture
//!
//! ```text
//! Application
//!     ↓
//! ygg_stream (stream multiplexing)
//!     ↓
//! ironwood (encrypted PacketConn)
//! ```
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use ygg_stream::StreamManager;
//! use ironwood::new_encrypted_packet_conn;
//! use ed25519_dalek::SigningKey;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create ironwood node
//!     let signing_key = SigningKey::generate(&mut rand::thread_rng());
//!     let conn = new_encrypted_packet_conn(signing_key, Default::default());
//!
//!     // Create stream manager
//!     let manager = StreamManager::new(conn);
//!
//!     // Accept incoming connection
//!     let connection = manager.accept().await?;
//!
//!     // Accept incoming stream
//!     let mut stream = connection.accept_stream().await?;
//!
//!     // Use standard async I/O
//!     let mut buf = vec![0u8; 1024];
//!     let n = stream.read(&mut buf).await?;
//!     stream.write_all(&buf[..n]).await?;
//!
//!     Ok(())
//! }
//! ```

// UniFFI scaffolding — must be in the crate root.
uniffi::setup_scaffolding!("ygg_stream");

pub mod connection;
pub mod error;
pub mod ffi;
pub mod manager;
pub mod messenger;
pub mod protocol;
pub mod stream;

// Re-export main types
pub use connection::Connection;
pub use error::{Error, Result};
pub use manager::{ConnectHandle, StreamManager};
pub use messenger::{Conn, Messenger};
pub use protocol::{Packet, DEFAULT_WINDOW_SIZE, MAX_PACKET_SIZE};
pub use stream::{Stream, StreamState};
