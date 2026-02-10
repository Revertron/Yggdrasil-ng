# Ironwood

Ironwood is a routing library that provides a `PacketConn` interface using Ed25519 public keys as network addresses. It lets nodes communicate across a network without requiring direct connectivity between every pair of nodes, by routing packets over a spanning tree embedding.

This is a Rust rewrite of the [Go ironwood library](https://github.com/Arceliar/ironwood), originally written as the routing layer for [Yggdrasil](https://github.com/yggdrasil-network/yggdrasil-go). The Rust implementation is async, built on [tokio](https://tokio.rs/).

> **Status:** Pre-alpha, work-in-progress. No stable API, no versioning guarantees, no security audit. Use at your own risk.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ironwood = { path = "crates/ironwood" }
tokio = { version = "1", features = ["full"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
```

### Basic example

```rust
use std::sync::Arc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use ironwood::{new_packet_conn, Addr, Config, PacketConn};

#[tokio::main]
async fn main() {
    // Create two nodes with random keys
    let node_a = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let node_b = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

    // Connect them over any AsyncRead + AsyncWrite transport
    let (stream_a, stream_b) = tokio::io::duplex(65536);

    let addr_a = node_a.local_addr();
    let addr_b = node_b.local_addr();

    let a = Arc::clone(&node_a);
    let b = Arc::clone(&node_b);
    tokio::spawn(async move { a.handle_conn(addr_b, Box::new(stream_a), 0).await });
    tokio::spawn(async move { b.handle_conn(addr_a, Box::new(stream_b), 0).await });

    // After tree convergence (~2s), send packets by public key
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    node_a.write_to(b"hello", &addr_b).await.unwrap();

    let mut buf = [0u8; 4096];
    let (n, from) = node_b.read_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, addr_a);

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
}
```

## Modules

### `PacketConn` (plain)

The base implementation. Packets are unencrypted and unsigned, similar to UDP. Useful as a building block for wrapping with your own security protocol (DTLS, QUIC, TLS-over-uTP, etc.).

Internally, protocol traffic (tree announcements, path lookups) is signed for authentication, but user data is not.

```rust
use ironwood::{new_packet_conn, Config};

let conn = new_packet_conn(signing_key, Config::default());
```

### `EncryptedPacketConn`

Wraps the plain `PacketConn` with end-to-end [NaCl box](https://nacl.cr.yp.to/box.html) encryption (X25519 / XSalsa20 / Poly1305). Provides authenticated encryption with forward secrecy through key ratcheting.

Sessions are established automatically: the first write triggers a handshake (Init -> Ack -> Traffic), after which all packets are encrypted with ephemeral keys.

```rust
use ironwood::{new_encrypted_packet_conn, Config};

let conn = new_encrypted_packet_conn(signing_key, Config::default());
```

### `SignedPacketConn`

Wraps the plain `PacketConn` with Ed25519 signature authentication. Each packet is prepended with a 64-byte signature on send and verified on receive. No encryption is provided.

Designed for restricted networks (e.g. amateur radio) where encryption is prohibited but authentication is desired.

```rust
use ironwood::{new_signed_packet_conn, Config};

let conn = new_signed_packet_conn(signing_key, Config::default());
```

## Configuration

All conn types accept a `Config` with builder-style methods:

```rust
use std::time::Duration;
use ironwood::Config;

let config = Config::default()
    .with_peer_timeout(Duration::from_secs(5))
    .with_path_timeout(Duration::from_secs(120))
    .with_peer_max_message_size(2 * 1024 * 1024);
```

| Option | Default | Description |
|--------|---------|-------------|
| `router_refresh` | 4 min | How often to refresh tree announcements |
| `router_timeout` | 5 min | Timeout before expiring a peer's tree info |
| `peer_keepalive_delay` | 1 sec | Delay before sending keepalive to idle peer |
| `peer_timeout` | 3 sec | Timeout before considering a peer dead |
| `peer_max_message_size` | 1 MB | Maximum size of a single wire message |
| `path_timeout` | 1 min | Timeout before expiring a cached path |
| `path_throttle` | 1 sec | Minimum interval between lookups to the same destination |
| `bloom_transform` | None | Transform applied to keys before bloom filter insertion |
| `path_notify` | None | Callback invoked when a new path is discovered |

## Transports

Ironwood is transport-agnostic. Any type implementing `AsyncRead + AsyncWrite + Send + Unpin` can be passed to `handle_conn()`. This includes:

- `tokio::net::TcpStream`
- `tokio::io::DuplexStream` (for testing)
- TLS streams (`tokio-rustls`, `tokio-native-tls`)
- WebSocket streams
- QUIC streams
- Unix sockets

Each call to `handle_conn()` blocks until the peer disconnects, so it should be spawned as a separate task.

## How routing works

1. **Spanning tree:** Nodes form a spanning tree using a CRDT-based protocol. Each node selects a parent peer, creating a tree rooted at the node with the highest public key. Tree state is gossiped between peers and converges eventually.

2. **Greedy routing:** Packets are forwarded greedily through the tree metric space, where distance is defined by the tree path between two nodes. Each hop picks the neighbor closest to the destination.

3. **Path discovery:** When a node doesn't know the destination's location in tree-space, it performs a lookup using bloom filter multicast over the spanning tree. Each on-tree link maintains a bloom filter of reachable keys in its subtree, allowing lookups to be routed with constant state per peer.

4. **Path repair:** If a packet reaches a dead end, a "path broken" notification is sent back to the sender, which triggers a new lookup.

### Bloom filter details

- 8192-bit filter (1024 bytes), 8 hash functions
- Leaf nodes have a false positive rate comparable to an 80-bit address collision
- In a 1M-node network, false positives are expected when a subtree reaches ~200 nodes
- Filters are compatible with the Go [bits-and-blooms/bloom](https://github.com/bits-and-blooms/bloom) library (FNV-128 hash)

## Testing

```bash
# Run all tests (54 unit + 5 integration)
cargo test -p ironwood

# Run only integration tests
cargo test -p ironwood --test integration

# Run only unit tests
cargo test -p ironwood --lib
```

## Differences from the Go implementation

- **Async/await** with tokio instead of goroutines
- **`Arc<Mutex<T>>`** ownership model instead of the [phony](https://github.com/Arceliar/phony) actor framework
- **Decoupled I/O:** Router produces `Vec<RouterAction>` instead of directly calling peer methods, making the core logic testable without network I/O
- **RustCrypto** ecosystem (ed25519-dalek, x25519-dalek, crypto_box) instead of Go's standard library crypto

## License

Same license as the upstream ironwood project.
