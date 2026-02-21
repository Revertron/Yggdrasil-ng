//! Complete Yggdrasil node with stream multiplexing
//!
//! This example shows how to integrate ygg_stream with a full Yggdrasil node
//! that has TCP/TLS listeners and peer connections.

use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};
use yggdrasil::config::Config;
use yggdrasil::core::Core;
use ygg_stream::StreamManager;

const YGG_NODE: &str = "tcp://192.168.44.77:7743";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,yggdrasil=info,ironwood=info")
        .init();

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");

    // Create configuration
    let mut config = Config::default();
    config.peers = vec![YGG_NODE.to_string()];

    // Generate signing key (in production, load from config)
    let signing_key = SigningKey::generate(&mut rand::thread_rng());

    // Create Yggdrasil core
    let core = Core::new(signing_key, config);

    info!("Your IPv6 address: {}", core.address());
    info!("Your IPv6 subnet: {}", core.subnet());
    info!("Your public key: {}", hex::encode(core.public_key()));

    // Initialize links and start listening/connecting
    core.init_links().await;
    core.start().await;

    info!("Yggdrasil node started successfully");

    // Give connections time to establish
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    info!("Yggdrasil routing should be ready");

    // Create stream manager using the Yggdrasil core's packet connection
    let stream_manager = StreamManager::new(core.packet_conn());

    if mode == "server" {
        info!("Stream manager ready - waiting for incoming connections...");
        run_server(stream_manager).await?;
    } else {
        info!("Stream manager ready - will connect to peer");

        // In client mode, we need to know the server's public key
        let server_pubkey = args.get(2)
            .ok_or("Usage: full_node client SERVER_PUBLIC_KEY_HEX")?;

        run_client(stream_manager, server_pubkey).await?;
    }

    Ok(())
}

async fn run_server(mut manager: StreamManager) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        // Accept incoming connection
        let connection = manager.accept().await?;
        let peer = connection.peer_addr();
        info!("Accepted connection from peer {}", hex::encode(&peer.as_ref()[..8]));

        // Spawn task to handle this connection
        tokio::spawn(async move {
            loop {
                match connection.accept_stream().await {
                    Ok(mut stream) => {
                        info!("Accepted stream {} from peer {}",
                            stream.id(),
                            hex::encode(&peer.as_ref()[..8])
                        );

                        // Spawn task to handle this stream
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 1024];
                            loop {
                                match stream.read(&mut buf).await {
                                    Ok(0) => {
                                        info!("Stream {} closed by peer", stream.id());
                                        break;
                                    }
                                    Ok(n) => {
                                        info!("Stream {}: received {} bytes", stream.id(), n);

                                        // Echo back
                                        if let Err(e) = stream.write_all(&buf[..n]).await {
                                            error!("Write error: {}", e);
                                            break;
                                        }
                                        if let Err(e) = stream.flush().await {
                                            error!("Flush error: {}", e);
                                            break;
                                        }

                                        info!("Stream {}: echoed {} bytes", stream.id(), n);
                                    }
                                    Err(e) => {
                                        error!("Read error: {}", e);
                                        break;
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Error accepting stream: {}", e);
                        break;
                    }
                }
            }
        });
    }
}

async fn run_client(manager: StreamManager, server_pubkey_hex: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Decode server public key
    let pubkey_bytes = hex::decode(server_pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err("Server public key must be 32 bytes (64 hex chars)".into());
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);
    let server_addr = ironwood::Addr::from(pubkey);

    info!("Connecting to server with public key {}", server_pubkey_hex);

    // Wait a bit for the peer connection to be established
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Connect to server
    let connection = manager.connect(server_addr).await?;
    info!("Connected to server!");

    // Open a stream
    let mut stream = connection.open_stream().await?;
    info!("Opened stream {}", stream.id());

    // Send some messages
    for i in 1..=5 {
        let message = format!("Hello from client, message {}", i);
        info!("Sending: {}", message);

        stream.write_all(message.as_bytes()).await?;
        stream.flush().await?;

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await?;
        let response = String::from_utf8_lossy(&buf[..n]);
        info!("Received: {}", response);

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    // Close stream
    stream.shutdown().await?;
    info!("Stream closed gracefully");

    // Keep connection alive for a bit
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    Ok(())
}