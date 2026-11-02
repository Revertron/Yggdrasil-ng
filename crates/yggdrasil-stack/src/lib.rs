//! Userspace TCP/UDP/ICMPv6 over an embedded Yggdrasil node, without a TUN
//! adapter or elevated privileges.
//!
//! The node's IPv6 packets are fed through a [smoltcp] interface that owns the
//! node's address. Applications get tokio-style sockets that interoperate with
//! regular Yggdrasil hosts using the kernel stack.
//!
//! ```no_run
//! # async fn demo() -> std::io::Result<()> {
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use yggdrasil::config::Config;
//! use yggdrasil::node::NodeBuilder;
//! use yggdrasil_stack::YggStack;
//!
//! let mut config = Config::default();
//! config.peers.push("tls://peer.example.org:443".into());
//! let node = NodeBuilder::new(config).embedded().start().await.map_err(std::io::Error::other)?;
//! let stack = YggStack::new(&node)?;
//!
//! let mut stream = stack.tcp_connect("[200:1234::1]:80".parse().unwrap()).await?;
//! stream.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;
//! let mut reply = Vec::new();
//! stream.read_to_end(&mut reply).await?;
//! # Ok(())
//! # }
//! ```
//!
//! Limitations: IPv6 only (no CKR/IPv4), no IPv6 fragmentation, and one
//! address (the node's own; its /64 subnet is not served).

mod device;
mod icmp;
mod stack;
mod tcp;
mod udp;

pub use stack::{StackConfig, YggStack};
pub use tcp::{TcpListener, TcpStream};
pub use udp::UdpSocket;
