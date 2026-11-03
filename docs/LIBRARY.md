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
| `yggdrasil-embed` | Shared core of the bindings below: `EmbeddedNode`, a synchronous Rust API that returns connections as OS sockets. |
| `yggdrasil-ffi` | C ABI (`libygg.so` / `ygg.dll` / `libygg.dylib`, plus static `libygg.a`), header `crates/yggdrasil-ffi/include/ygg.h`. |
| `yggdrasil-py` | Python package `ygg` (PyO3, abi3 wheel for CPython ≥ 3.9). |
| `yggdrasil-uniffi` | UniFFI bindings (Kotlin; Swift possible); generated Kotlin in `bindings/kotlin`. |
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

## C library (`libygg`)

```bash
cargo build --release -p yggdrasil-ffi   # target/release/libygg.{so,a}
cargo build --release -p yggdrasil-ffi --no-default-features   # without ws/quic, smaller
```

Every connection is returned as an ordinary OS socket: one end of a socket
pair whose other end the library bridges to the Yggdrasil network. The
application reads, writes and polls it with its own I/O (select/poll, epoll,
kqueue, IOCP, Python `socket`/`asyncio`, ...); the data path never calls back
into the library, and there are no callbacks to marshal across threads.

| Platform | Stream sockets | Datagram sockets |
|---|---|---|
| Linux, Android, *BSD | `socketpair(AF_UNIX, SOCK_STREAM)` | `SOCK_SEQPACKET` |
| macOS, iOS | `socketpair(AF_UNIX, SOCK_STREAM)` | `SOCK_DGRAM` |
| Windows | loopback TCP pair (`SOCKET`) | connected loopback UDP pair |

```c
#include "ygg.h"

ygg_node *node = ygg_node_start(config_toml, 0);   /* NULL config: ephemeral */
if (!node) fprintf(stderr, "%s\n", ygg_last_error_message());

/* Client: a connected stream socket */
ygg_socket s = ygg_tcp_connect(node, "<hex key>.pk.ygg", 80, 0);
write(s, req, len); read(s, buf, sizeof buf); close(s);

/* Server: the listener handle becomes readable when a connection is pending */
ygg_socket l = ygg_tcp_listen(node, 7000);
/* poll(l, POLLIN) ... */
char peer[64];
ygg_socket c = ygg_tcp_accept(node, l, peer, sizeof peer, 0);  /* 0 = don't wait */

/* UDP: each datagram = 16-byte IPv6 address + 2-byte port (BE) + payload */
uint16_t port;
ygg_socket u = ygg_udp_bind(node, 0, &port);

int64_t rtt_us = ygg_ping(node, "200:1234::1", 5000);
char *json = ygg_node_admin(node, "{\"request\":\"getPeers\"}");
ygg_free_string(json);

int id = ygg_socks5_start(node, "127.0.0.1:1080", NULL, NULL);
ygg_service_stop(node, id);

ygg_tcp_listener_close(node, l);
ygg_udp_close(node, u);
ygg_node_stop(node);
```

Conventions (details in the header):

- `int` results are `>= 0` on success and `-YGG_ERR_*` on failure; socket
  results are `YGG_INVALID_SOCKET` and pointer results `NULL` on failure.
  `ygg_last_error()` / `ygg_last_error_message()` describe the last failure
  on the calling thread.
- Calls that wait (start, connect, accept with a timeout, ping, admin) block
  the calling thread; everything else runs on the library's own threads.
- Stream sockets close like TCP: `shutdown(SHUT_WR)` sends FIN, `close()`
  ends the connection.
- Listener handles and UDP sockets are closed with `ygg_tcp_listener_close` /
  `ygg_udp_close`, which also stop the network side.
- `ygg_node_stop` ends every connection (the application's sockets see EOF);
  the application still closes its own sockets.
- Logs go nowhere until `ygg_set_logger` installs a callback. Never call
  `ygg_*` functions from inside the callback.
- On Windows, initialise Winsock (`WSAStartup`) before using the sockets.

Example: `crates/yggdrasil-ffi/examples/c/ygg_echo.c`, a `poll()`-based echo
server. A minimal ctypes binding is in
`crates/yggdrasil-ffi/examples/python/ygg.py`; prefer the native package
below.

## Python package (`ygg`)

```bash
cd crates/yggdrasil-py
pip install maturin
maturin build --release      # abi3 wheel in target/wheels/, CPython >= 3.9
maturin develop --release    # or install into the active virtualenv
```

```python
import ygg

with ygg.Node(peers=["tls://peer.example.org:443"]) as node:
    s = node.connect("<hex key>.pk.ygg", 80)       # a normal socket.socket
    with node.listen(8080) as listener:            # fileno() works with selectors
        conn, peer = listener.accept()
    with node.udp_bind() as u:                     # (data, (host, port)) API
        u.sendto(b"hi", ("200:1234::1", 5353))
    node.ping("200:1234::1"); node.admin("getPeers")

# asyncio
reader, writer = await node.open_connection("200:1234::1", 80)
server = await node.start_server(handle, 8080)
```

Blocking calls release the GIL; `node.close()` wakes threads blocked in
`accept`. Errors map to built-in exceptions (`ConnectionRefusedError`,
`TimeoutError`, `BlockingIOError`, `ConnectionError`, `ValueError`,
`OSError` with `errno`). `ygg.log_to_python()` routes logs into `logging`.
See `crates/yggdrasil-py/README.md`.

The crate is its own Cargo workspace (built by maturin), so the main
workspace builds without Python.

## Kotlin / Android (`link.yggdrasil.embed`)

UniFFI bindings in `crates/yggdrasil-uniffi`; the generated Kotlin
(`yggdrasil_uniffi.kt`, uses JNA) and hand-written helpers (`YggStreams.kt`)
are in `bindings/kotlin/src/main/kotlin`. Regenerate after changing the
Rust API with `bindings/kotlin/generate.sh`.

```kotlin
import link.yggdrasil.embed.*

val node = YggNode(configToml)                      // null: ephemeral key
node.connect("<hex key>.pk.ygg", 80).use { s ->     // YggStream
    s.output.write(request)
    s.shutdownOutput()                              // FIN, keep reading
    val reply = s.input.readBytes()
}
node.listen(8080).use { l -> val conn = l.accept() }   // conn.peer = "[addr]:port"
node.udp().use { u -> u.send("200:1234::1", 5353, data); val d = u.receive() }
node.pingMillis("200:1234::1")
node.admin("""{"request":"getPeers"}""")
setLogger(object : LogSink { override fun log(level: Int, message: String) = Log.i("ygg", message) }, "info")
node.close()                                        // stops the node, frees the handle
```

All calls block, so run them off the main thread (`Dispatchers.IO`). Errors
are `YggException` subclasses (`ConnectionRefused`, `TimedOut`, `WouldBlock`,
`Closed`, ...). The raw API (`tcpConnect`, `tcpAccept`, `udpBind`, ... returning
descriptors as `Int`) is available too; on Android wrap a descriptor with
`ParcelFileDescriptor.adoptFd(fd)`.

Android integration in an app:

1. Build the library per ABI, e.g. with
   [cargo-ndk](https://github.com/bbqsrc/cargo-ndk):
   `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs build --release -p yggdrasil-uniffi`
2. Add `bindings/kotlin/src/main/kotlin` to the module's sources and
   `implementation("net.java.dev.jna:jna:5.17.0@aar")` to its dependencies.
3. With R8/ProGuard, keep JNA and the bindings:
   `-keep class com.sun.jna.** { *; }` and `-keep class link.yggdrasil.embed.** { *; }`.
4. The app needs the `INTERNET` permission; no `VpnService` is involved.

If the app already ships a UniFFI library, depend on `yggdrasil-uniffi` from
that crate instead of shipping a second copy of the runtime; the exports are
picked up when its bindings are generated.

`bindings/kotlin` is also a Gradle JVM project whose tests run the bindings
against `target/debug` (`cargo build -p yggdrasil-uniffi`, then
`gradle test` in `bindings/kotlin`).

`bindings/android` is an Android library module (AGP 8.7, Gradle 8.14) over
the same sources. Its instrumented tests run the JVM suite unchanged plus
Android-specific checks (descriptors adopted by `ParcelFileDescriptor` under
fdsan, no leaks or double closes over many open/close cycles):

```bash
rustup target add x86_64-linux-android      # plus aarch64-linux-android etc.
cargo install cargo-ndk
ABIS="x86_64" bindings/android/build-native.sh   # needs ANDROID_NDK_HOME
cd bindings/android && gradle connectedDebugAndroidTest   # device or emulator attached
```

CI runs them on an API 30 x86_64 emulator. The module can also serve as the
starting point for an AAR (`gradle assembleRelease` after building all ABIs).

## Roadmap

- Swift bindings from the same UniFFI crate.
