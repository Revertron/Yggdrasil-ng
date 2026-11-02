# Library Mode

Yggdrasil-ng can be embedded in an application instead of running as a daemon
with a TUN adapter. Traffic goes through a userspace TCP/IP stack
([smoltcp](https://github.com/smoltcp-rs/smoltcp)) inside the process, so no
TUN driver, root or administrator rights are needed. Peers on the network see
an ordinary Yggdrasil node and talk to it with their kernel stacks.

## Crates

| Crate | Purpose |
|---|---|
| `yggdrasil` | The node. `node::NodeBuilder` starts it; `.embedded()` disables TUN and the admin socket. |
| `yggdrasil-stack` | `YggStack`: TCP streams/listeners, UDP sockets and ICMPv6 ping over an embedded node. |

## Rust example

```rust
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yggdrasil::config::Config;
use yggdrasil::node::NodeBuilder;
use yggdrasil_stack::YggStack;

let mut config = Config::default();
config.peers.push("tls://peer.example.org:443".into());
config.private_key = "...".into(); // optional; otherwise an ephemeral key

let node = NodeBuilder::new(config).embedded().start().await?;
let stack = YggStack::new(&node)?;
println!("our address: {}", stack.address());

// Client
let mut s = stack.tcp_connect("[200:1234::1]:80".parse()?).await?;
s.write_all(b"GET / HTTP/1.0\r\n\r\n").await?;

// Dial by public key (skips the address-to-key lookup)
let s = stack.tcp_connect_key(&peer_key, 8080).await?;

// Server
let listener = stack.tcp_listen(8080)?;
let (stream, peer) = listener.accept().await?;

// UDP
let sock = stack.udp_bind(0)?;
sock.send_to(b"hi", "[200:1234::1]:5353".parse()?).await?;

// ICMPv6 echo
let rtt = stack.ping("200:1234::1".parse()?, Duration::from_secs(5)).await?;

stack.close();
node.close().await;
```

`TcpStream` implements tokio's `AsyncRead`/`AsyncWrite`, so it works with
`tokio::io` utilities, `tokio-rustls`, hyper, etc.

## Tuning

`YggStack::with_config(&node, StackConfig { .. })`:

| Field | Default | Notes |
|---|---|---|
| `mtu` | node MTU (≤ 65535) | Interface MTU; TCP MSS follows it. |
| `tcp_rx_buffer` / `tcp_tx_buffer` | 1 MiB | Per connection. The receive buffer caps the window, so throughput ≲ buffer / RTT. Memory is committed only as data flows. |
| `tcp_backlog` | 128 | Connections handshaking or waiting for `accept`, per port. Excess SYNs are dropped and retried by the client. |
| `connect_timeout` | 30 s | |
| `udp_rx_buffer` / `udp_tx_buffer` / `udp_queue` | 256 KiB / 256 KiB / 128 | Per socket. |

## Limitations

- IPv6 only; crypto-key routing (IPv4 / foreign prefixes) is not available.
- Only the node's own address is served, not its /64 subnet.
- No IPv6 fragmentation: UDP datagrams must fit `UdpSocket::max_datagram_size()`.
- The stack owns the node's packet stream: one stack per node, and the node must
  not run a TUN adapter.
- The first packets to a node not contacted before are delayed while the
  encrypted session is set up; TCP retransmits the SYN after about 1 s.

## Roadmap

- C ABI (`cdylib`/`staticlib`) where each connection is a real OS socket
  (socketpair), usable from C/C++ event loops, Python `asyncio`, etc.
- Python and Kotlin bindings on top of it.
- SOCKS5 proxy and port forwarding.
