//! Simple echo server example
//!
//! Accepts incoming connections and streams, echoes back any data received.

use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, PacketConn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};
use ygg_stream::StreamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info,ygg_stream=debug,ironwood=info")
        .init();

    // Generate a random key for this node
    let signing_key = SigningKey::generate(&mut rand::thread_rng());
    let conn = new_encrypted_packet_conn(signing_key, Default::default());
    let local_addr = conn.local_addr();

    info!("Echo server started");
    info!("Local address: {}", local_addr);

    // Create stream manager
    let mut manager = StreamManager::new(conn);

    info!("Waiting for connections...");

    // Accept connections in a loop
    loop {
        match manager.accept().await {
            Ok(connection) => {
                let peer = connection.peer_addr();
                info!("Accepted connection from peer {}", peer);

                // Spawn a task to handle this connection
                tokio::spawn(async move {
                    loop {
                        match connection.accept_stream().await {
                            Ok(stream) => {
                                info!("Accepted stream {} from peer {}", stream.id(), peer);

                                // Spawn a task to handle this stream
                                tokio::spawn(async move {
                                    if let Err(e) = handle_stream(stream).await {
                                        error!("Stream error: {}", e);
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
            Err(e) => {
                error!("Error accepting connection: {}", e);
                break;
            }
        }
    }

    Ok(())
}

async fn handle_stream(mut stream: ygg_stream::Stream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = vec![0u8; 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            // EOF
            info!("Stream {} closed by peer", stream.id());
            break;
        }

        info!("Stream {}: received {} bytes", stream.id(), n);

        // Echo back
        stream.write_all(&buf[..n]).await?;
        stream.flush().await?;

        info!("Stream {}: echoed {} bytes", stream.id(), n);
    }

    Ok(())
}
