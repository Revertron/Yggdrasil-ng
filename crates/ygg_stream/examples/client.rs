//! Simple client example
//!
//! Connects to a peer and sends a message, prints the response.

use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, Addr, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;
use ygg_stream::StreamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,ironwood=info")
        .init();

    // Parse peer address from command line
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <peer_public_key_hex>", args[0]);
        eprintln!("Example: {} a1b2c3d4e5f6...", args[0]);
        std::process::exit(1);
    }

    let peer_hex = &args[1];
    let peer_bytes = hex::decode(peer_hex)?;
    if peer_bytes.len() != 32 {
        eprintln!("Error: Peer key must be 32 bytes (64 hex characters)");
        std::process::exit(1);
    }

    let mut peer_key = [0u8; 32];
    peer_key.copy_from_slice(&peer_bytes);
    let peer_addr = Addr::from(peer_key);

    // Generate a random key for this client
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());
    let local_addr = conn.local_addr();

    info!("Client started");
    info!("Local address: {}", local_addr);
    info!("Connecting to peer: {}", peer_addr);

    // Create stream manager
    let manager = StreamManager::new(conn);

    // Connect to peer
    let connection = manager.connect(peer_addr).await?;
    info!("Connected to peer");

    // Open a stream
    let mut stream = connection.open_stream().await?;
    info!("Opened stream {}", stream.id());

    // Send a message
    let message = b"Hello, Yggdrasil!";
    info!("Sending message: {}", String::from_utf8_lossy(message));
    stream.write_all(message).await?;
    stream.flush().await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    info!("Received response: {}", String::from_utf8_lossy(&buf[..n]));

    // Close stream gracefully
    stream.shutdown().await?;
    info!("Stream closed");

    // Close connection
    connection.close().await;
    info!("Connection closed");

    manager.close().await;

    Ok(())
}
