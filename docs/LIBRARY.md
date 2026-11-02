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
| `yggdrasil-stack` | `YggStack`: TCP streams/listeners, UDP sockets and ICMPv6 ping over an embedded node. Feature `proxy` (default): SOCKS5 server and port forwarding. Feature `cli`: the `yggdrasil-proxy` tool. |

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

Hosts can be given as addresses or public keys: `Host`/`Target` parse
`[200:1234::1]:80`, `<hex key>:80` and `<hex key>.pk.ygg:80`, and
`stack.tcp_connect_target(&target)` dials either.

## SOCKS5 and port forwarding

Module `yggdrasil_stack::proxy` (feature `proxy`, on by default):

```rust
use yggdrasil_stack::proxy::*;

// SOCKS5 (CONNECT only). Destinations: IPv6 in 200::/7 or `<key>.pk.ygg`;
// other names can be mapped with `.with_resolver(..)`.
let listener = tokio::net::TcpListener::bind("127.0.0.1:1080").await?;
tokio::spawn(Socks5Server::new(stack.clone()).with_credentials("user", "pass").serve(listener));

// Host 127.0.0.1:8080 -> Yggdrasil target
let l = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
tokio::spawn(forward_local_tcp(stack.clone(), l, "[200:1234::1]:80".parse()?));

// Yggdrasil port 80 -> host 127.0.0.1:8000 (publish a local service)
tokio::spawn(forward_remote_tcp(stack.clone(), 80, "127.0.0.1:8000".parse()?));

// UDP equivalents; sessions idle for 120 s are dropped.
tokio::spawn(forward_local_udp(stack.clone(), udp_socket, target));
tokio::spawn(forward_remote_udp(stack.clone(), 53, "127.0.0.1:53".parse()?));
```

### `yggdrasil-proxy` tool

The same as a standalone program, for applications that can use a SOCKS5
proxy or a local port:

```bash
cargo build --release -p yggdrasil-stack --features cli
```

```bash
yggdrasil-proxy -c node.toml -p tls://peer.example.org:443 \
    --socks 127.0.0.1:1080 \
    --local-tcp 127.0.0.1:8080=[200:1234::1]:80 \
    --remote-tcp 80=127.0.0.1:8000
```

```bash
curl --socks5-hostname 127.0.0.1:1080 http://<hex key>.pk.ygg/
```

`-c` takes a regular Yggdrasil config (TUN settings are ignored); without it
an ephemeral key is used. `--admin` starts the admin socket from the config.

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
