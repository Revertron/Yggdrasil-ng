# ygg_stream: Stream Multiplexing for Yggdrasil

A lightweight stream multiplexing library built on top of ironwood's encrypted PacketConn. Provides QUIC-like ergonomics (multiple concurrent streams, AsyncRead/AsyncWrite) without the complexity of QUIC protocol implementation.

## Features

- **Multiple concurrent streams** per peer connection
- **Stream-oriented API** - continuous byte streams with AsyncRead + AsyncWrite
- **No additional encryption** - leverages Yggdrasil's existing encryption at PacketConn layer
- **Simple custom protocol** - optimized for PacketConn semantics (7-byte header overhead)
- **Flow control** - window-based flow control (256 KB default) prevents buffer overflow
- **Graceful shutdown** - proper FIN handshake for clean stream closure

## Architecture

```
Application
    ↓
ygg_stream (stream multiplexing)
    ↓
ironwood (encrypted PacketConn)
```

### Protocol Design

**Packet Format** (7 bytes + data):
```
[stream_id: u32][flags: u8][length: u16][data: bytes]
```

**Flags**:
- `SYN (0x01)`: Open stream
- `ACK (0x02)`: Acknowledge
- `FIN (0x04)`: Close gracefully
- `RST (0x08)`: Reset stream (immediate close)

**Stream Lifecycle**:
1. **SYN**: Initiator opens stream
2. **SYN-ACK**: Acceptor responds
3. **DATA**: Bidirectional data transfer with ACK
4. **FIN**: Graceful close (both sides send FIN)
5. **RST**: Immediate close (error or abort)

**Stream ID Allocation**:
- Initiator uses **odd IDs** (1, 3, 5, ...)
- Acceptor uses **even IDs** (2, 4, 6, ...)
- Prevents collision when both sides open simultaneously

## Integration with Yggdrasil

The `ygg_stream` library is designed to work seamlessly with a complete Yggdrasil node. The Yggdrasil `Core` handles all network transport (TCP/TLS listeners and peer connections), while `ygg_stream` provides stream multiplexing on top.

### Complete Node Example

```rust
use ed25519_dalek::SigningKey;
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::StreamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Yggdrasil configuration
    let mut config = Config::default();
    config.listen = vec!["tcp://0.0.0.0:1234".to_string()];
    config.peers = vec!["tcp://peer.example.com:1234".to_string()];

    // Create Yggdrasil core
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let core = Core::new(signing_key, config);

    // Initialize and start the node
    core.init_links().await;
    core.start().await;  // Starts TCP listeners and connects to peers

    // Create stream manager on top of Yggdrasil core
    let mut stream_manager = StreamManager::new(core.packet_conn());

    // Now use stream multiplexing
    let connection = stream_manager.accept().await?;
    let mut stream = connection.accept_stream().await?;

    // Use standard async I/O
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    stream.write_all(&buf[..n]).await?;

    Ok(())
}
```

## Usage Examples

### Echo Server

```rust
use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ygg_stream::StreamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create ironwood node
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());

    // Create stream manager
    let mut manager = StreamManager::new(conn);

    // Accept connections
    loop {
        let connection = manager.accept().await?;
        tokio::spawn(async move {
            loop {
                let mut stream = connection.accept_stream().await?;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1024];
                    loop {
                        let n = stream.read(&mut buf).await?;
                        if n == 0 { break; }
                        stream.write_all(&buf[..n]).await?;
                    }
                    Ok::<_, Box<dyn std::error::Error>>(())
                });
            }
        });
    }
}
```

### Client

```rust
use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, Addr, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ygg_stream::StreamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());

    let mut manager = StreamManager::new(conn);

    // Connect to peer
    let peer_key: [u8; 32] = /* peer's public key */;
    let connection = manager.connect(Addr::from(peer_key)).await?;

    // Open stream
    let mut stream = connection.open_stream().await?;

    // Send/receive data
    stream.write_all(b"Hello, Yggdrasil!").await?;
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    println!("Received: {}", String::from_utf8_lossy(&buf[..n]));

    stream.shutdown().await?;
    Ok(())
}
```

### Multiple Concurrent Streams

```rust
let connection = manager.connect(peer_addr).await?;

// Open multiple streams
let mut stream1 = connection.open_stream().await?;
let mut stream2 = connection.open_stream().await?;
let mut stream3 = connection.open_stream().await?;

// Use streams independently in parallel
tokio::spawn(async move {
    stream1.write_all(b"Stream 1 data").await?;
    Ok::<_, Box<dyn std::error::Error>>(())
});

tokio::spawn(async move {
    stream2.write_all(b"Stream 2 data").await?;
    Ok::<_, Box<dyn std::error::Error>>(())
});
```

## Running Examples

### Full Yggdrasil Node with Stream Multiplexing

**Server** (listens on TCP port 1234):
```bash
cargo run -p ygg_stream --example full_node --features full-node server
```

**Client** (connects to server):
```bash
cargo run -p ygg_stream --example full_node --features full-node client tcp://127.0.0.1:1234 <server_public_key_hex>
```

This example demonstrates:
- Complete Yggdrasil node with TCP transport
- Automatic peer connection management
- Stream multiplexing on top of Yggdrasil
- Bidirectional communication

### Echo Server (standalone, for testing)
```bash
cargo run -p ygg_stream --example echo
```

### Client (standalone, for testing)
```bash
cargo run -p ygg_stream --example client <peer_public_key_hex>
```

## Implementation Details

### Components

1. **StreamManager** (`manager.rs`)
   - Manages connections and stream multiplexing per peer
   - Background reader task demultiplexes packets to connections
   - Background writer tasks aggregate packets from streams

2. **Connection** (`connection.rs`)
   - Represents multiplexed connection to single peer
   - Manages multiple streams
   - Stream ID allocation (odd/even separation)

3. **Stream** (`stream.rs`)
   - Individual bidirectional stream
   - Implements `AsyncRead` + `AsyncWrite`
   - Flow control with send/receive windows
   - State machine: Opening → Open → Closing → Closed

4. **Protocol** (`protocol.rs`)
   - Packet encoding/decoding
   - Protocol constants and flags

### Flow Control

Each stream tracks:
- **send_window**: Bytes we can send (based on peer's last ACK)
- **recv_window**: Bytes we can receive (our buffer space)

On write:
- Check available window
- Send up to window size
- Decrease send_window
- Wait for ACK to increase window

On receive:
- Buffer data
- Update recv_window
- Send ACK with current window size

## Testing

Run tests:
```bash
cargo test -p ygg_stream
```

Integration tests demonstrate:
- Bidirectional communication
- Multiple concurrent streams
- Stream ID allocation
- Connection lifecycle

## Advantages Over QUIC

1. **Simpler**: ~1000 LOC vs ~3000+ for QUIC integration
2. **No Dependencies**: Custom protocol, no Quinn/rustls
3. **No Address Translation**: Direct use of ed25519 keys
4. **No TLS Overhead**: Yggdrasil already encrypts
5. **Optimized**: Designed for PacketConn semantics
6. **Cleaner API**: Native Rust async I/O, no QUIC concepts

## Performance

- **Header Overhead**: 7 bytes per packet (vs ~14+ for QUIC)
- **Max Packet Size**: 65,535 bytes
- **Default Window Size**: 256 KB (configurable)
- **Connection Pooling**: Reuses existing connections

## Future Enhancements

Potential additions (not currently implemented):
- Priority streams (weighted fair queuing)
- Stream cancellation with reason codes
- Connection migration
- Advanced congestion control
- Zero-copy optimizations
- Connection statistics

## License

LGPL-3.0 (matching Yggdrasil project)

## Contributing

This is part of the Yggdrasil-ng Rust rewrite project. See main project README for contribution guidelines.
