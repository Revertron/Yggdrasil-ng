use std::net::SocketAddr;

use async_trait::async_trait;
use ironwood::types::AsyncConn;
use url::Url;

use crate::links::LinkOptions;

pub mod tcp;
pub mod tls;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod ws;
#[cfg(feature = "websocket")]
pub mod wss;

/// A connected transport stream with its remote address.
pub struct TransportStream {
    pub stream: Box<dyn AsyncConn>,
    pub remote_addr: SocketAddr,
}

/// Trait for transport protocols (TCP, TLS, QUIC, WebSocket, etc.).
///
/// Mirrors yggdrasil-go's `linkProtocol` interface.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Dial a remote peer.
    async fn dial(
        &self,
        url: &Url,
        options: &LinkOptions,
    ) -> Result<TransportStream, String>;

    /// Start listening for incoming connections.
    async fn listen(
        &self,
        url: &Url,
    ) -> Result<Box<dyn TransportListener>, String>;

    /// URL scheme(s) this transport handles (e.g., "tcp", "tls", "quic").
    fn scheme(&self) -> &str;
}

/// Extract the bare hostname from a URL, stripping IPv6 brackets.
///
/// `url::Url::host_str()` returns `[::1]` for IPv6 addresses (with brackets),
/// which is correct for socket address formatting but breaks TLS/QUIC server
/// name parsing. This helper strips the brackets.
pub(crate) fn bare_host(url: &Url) -> Result<String, String> {
    let host = url.host_str().ok_or("missing host")?;
    Ok(host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_string())
}

/// Listener that accepts incoming transport connections.
#[async_trait]
pub trait TransportListener: Send + Sync {
    /// Accept a new incoming connection.
    async fn accept(&self) -> Result<TransportStream, String>;

    /// Get the local address we're listening on.
    fn local_addr(&self) -> Result<SocketAddr, String>;

    /// Close the listener.
    async fn close(&self);
}
