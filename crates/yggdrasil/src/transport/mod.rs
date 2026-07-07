// Transport layer module.
// Groups TLS configuration, certificate generation and related code
// (moved from the former tls_support.rs at crate root).
// This structure allows future transport implementations (e.g. QUIC and WebSocket)
// to live under the same namespace without polluting the crate root.
// QUIC and WebSocket are optional and compiled only when the "transport-quic-ws"
// feature is enabled.
pub mod tls;

#[cfg(feature = "transport-quic-ws")]
pub(crate) mod quic;

#[cfg(feature = "transport-quic-ws")]
pub(crate) mod ws;