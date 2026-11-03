//! Bridges between the host's sockets and the Yggdrasil network: a SOCKS5
//! server and TCP/UDP port forwarding. Lets any application use Yggdrasil
//! without a TUN adapter or bindings.

mod forward;
mod socks5;

pub use forward::{
    forward_local_tcp, forward_local_udp, forward_remote_tcp, forward_remote_udp, serve_remote_tcp,
    serve_remote_udp,
};
pub use socks5::Socks5Server;

use std::time::Duration;

/// UDP forwarding sessions without traffic for this long are dropped.
pub const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(120);
