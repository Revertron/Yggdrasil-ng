// Transport layer module.
// Groups TLS configuration, certificate generation and related code
// (moved from the former tls_support.rs at crate root).
// This structure allows future transport implementations (e.g. QUIC)
// to live under the same namespace without polluting the crate root.
pub mod tls;