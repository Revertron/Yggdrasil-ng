use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::protocol::Packet;
use ironwood::{Addr, EncryptedPacketConn, PacketConn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, trace, warn};

/// StreamManager manages connections and stream multiplexing
///
/// Wraps an EncryptedPacketConn and provides stream-oriented API.
pub struct StreamManager {
    /// Underlying encrypted packet connection
    conn: Arc<EncryptedPacketConn>,

    /// Active connections (peer address -> Connection)
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,

    /// Channel for incoming connections
    incoming_connections: mpsc::Receiver<Arc<Connection>>,

    /// Cancellation token for graceful shutdown
    cancel: CancellationToken,
}

impl StreamManager {
    /// Create a new stream manager
    pub fn new(conn: Arc<EncryptedPacketConn>) -> Self {
        let (incoming_tx, incoming_connections) = mpsc::channel(16);

        let manager = Self {
            conn: conn.clone(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_connections,
            cancel: CancellationToken::new(),
        };

        // Spawn background reader task
        let connections = manager.connections.clone();
        let cancel = manager.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = reader_task(conn, connections, incoming_tx, cancel).await {
                error!("Reader task error: {}", e);
            }
        });

        manager
    }

    /// Connect to a peer (or reuse existing connection)
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", &peer.as_ref()[..8]);
                    return Ok(conn.clone());
                }
            }
        }

        // Create new connection as initiator
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let connection = Arc::new(Connection::new_initiator(peer, outgoing_tx));

        // Register connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, connection.clone());
        }

        // Spawn writer task for this connection
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
            }
        });

        debug!("Created new connection to peer {:?}", &peer.as_ref()[..8]);

        Ok(connection)
    }

    /// Accept an incoming connection
    pub async fn accept(&mut self) -> Result<Arc<Connection>> {
        tokio::select! {
            conn = self.incoming_connections.recv() => {
                conn.ok_or(Error::ConnectionClosed)
            }
            _ = self.cancel.cancelled() => {
                Err(Error::ConnectionClosed)
            }
        }
    }

    /// Close all connections and shut down
    pub async fn close(&self) {
        self.cancel.cancel();

        // Close all connections
        let connections = {
            let mut connections_lock = self.connections.write().await;
            let current_connections: Vec<_> = connections_lock.values().cloned().collect();
            connections_lock.clear();
            current_connections
        };

        for conn in connections {
            conn.close().await;
        }

        debug!("StreamManager closed");
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Get the local node address
    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Split into a shareable connect handle and an exclusive accept receiver.
    ///
    /// Use this when you need concurrent connect and accept without shared locking:
    /// - Give `ConnectHandle` to any code that needs to open streams.
    /// - Move `mpsc::Receiver<Arc<Connection>>` into a single background accept loop.
    ///
    /// After calling `split()`, `accept()` on the original manager will always
    /// return `ConnectionClosed` (the receiver has been moved out).
    pub fn split(mut self) -> (ConnectHandle, mpsc::Receiver<Arc<Connection>>) {
        let (dummy_tx, dummy_rx) = mpsc::channel(1);
        let incoming_rx = std::mem::replace(&mut self.incoming_connections, dummy_rx);
        // Drop dummy_tx so the manager's own accept() immediately returns Err.
        drop(dummy_tx);

        let handle = ConnectHandle {
            conn: self.conn.clone(),
            connections: self.connections.clone(),
            cancel: self.cancel.clone(),
        };

        // Keep the manager alive (its reader_task still pushes to incoming_rx via incoming_tx).
        // We do this by leaking the manager into a background task that never returns.
        // The manager's cancel token controls shutdown.
        tokio::spawn(async move {
            let _manager = self; // keeps reader_task alive
            std::future::pending::<()>().await;
        });

        (handle, incoming_rx)
    }
}

/// A cloneable handle for opening new connections (connect-only side of a StreamManager).
///
/// All fields are `Arc`-wrapped, so cloning is cheap and safe for concurrent use.
#[derive(Clone)]
pub struct ConnectHandle {
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,
    cancel: CancellationToken,
}

impl ConnectHandle {
    /// Connect to a peer (or reuse existing connection).
    pub async fn connect(&self, peer: Addr) -> Result<Arc<Connection>> {
        // Check if connection already exists
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(&peer) {
                if conn.is_alive() {
                    debug!("Reusing existing connection to peer {:?}", &peer.as_ref()[..8]);
                    return Ok(conn.clone());
                }
            }
        }

        // Create new connection as initiator
        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
        let connection = Arc::new(Connection::new_initiator(peer, outgoing_tx));

        // Register connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(peer, connection.clone());
        }

        // Spawn writer task for this connection
        let conn = self.conn.clone();
        let cancel = self.cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = writer_task(conn, peer, outgoing_rx, cancel).await {
                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
            }
        });

        debug!("Created new connection to peer {:?}", &peer.as_ref()[..8]);
        Ok(connection)
    }

    /// Get the local node address.
    pub fn local_addr(&self) -> Addr {
        self.conn.local_addr()
    }

    /// Force-close and remove a cached connection to a peer.
    pub async fn close_connection(&self, addr: Addr) {
        let conn = {
            let mut guard = self.connections.write().await;
            guard.remove(&addr)
        };
        if let Some(c) = conn {
            c.close().await;
        }
    }
}

/// Background reader task
///
/// Continuously reads packets from the underlying connection and routes them
/// to the appropriate Connection.
async fn reader_task(
    conn: Arc<EncryptedPacketConn>,
    connections: Arc<RwLock<HashMap<Addr, Arc<Connection>>>>,
    incoming_tx: mpsc::Sender<Arc<Connection>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            result = conn.read_from(&mut buf) => {
                let (n, peer) = result?;
                trace!("Received {} bytes from peer {:?}", n, &peer.as_ref()[..8]);

                // Decode packet
                let packet = match Packet::decode(&buf[..n]) {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("Failed to decode packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                        continue;
                    }
                };

                // Route to connection
                let connection = {
                    let conns = connections.read().await;
                    conns.get(&peer).cloned()
                };

                if let Some(conn) = connection {
                    // Existing connection
                    if let Err(e) = conn.handle_packet(packet).await {
                        warn!("Error handling packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                    }
                } else {
                    // New incoming connection
                    if packet.is_syn() && !packet.is_ack() {
                        debug!("New incoming connection from peer {:?}", &peer.as_ref()[..8]);

                        // Create connection as acceptor
                        let (outgoing_tx, outgoing_rx) = mpsc::channel(256);
                        let connection = Arc::new(Connection::new_acceptor(peer, outgoing_tx));

                        // Register connection
                        {
                            let mut conns = connections.write().await;
                            conns.insert(peer, connection.clone());
                        }

                        // Spawn writer task
                        let conn_clone = conn.clone();
                        let cancel_clone = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = writer_task(conn_clone, peer, outgoing_rx, cancel_clone).await {
                                error!("Writer task error for peer {:?}: {}", &peer.as_ref()[..8], e);
                            }
                        });

                        // Handle the SYN packet
                        if let Err(e) = connection.handle_packet(packet).await {
                            warn!("Error handling SYN packet from peer {:?}: {}", &peer.as_ref()[..8], e);
                            continue;
                        }

                        // Notify incoming connections channel
                        if let Err(_) = incoming_tx.send(connection).await {
                            warn!("Failed to send incoming connection");
                        }
                    } else {
                        trace!("Received packet from unknown peer {:?}, ignoring", &peer.as_ref()[..8]);
                    }
                }
            }
            _ = cancel.cancelled() => {
                debug!("Reader task cancelled");
                return Ok(());
            }
        }
    }
}

/// Background writer task per connection
///
/// Aggregates packets from a connection's streams and writes them to the network.
async fn writer_task(
    conn: Arc<EncryptedPacketConn>,
    peer: Addr,
    mut outgoing: mpsc::Receiver<Packet>,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        tokio::select! {
            packet = outgoing.recv() => {
                match packet {
                    Some(pkt) => {
                        let data = pkt.encode()?;
                        conn.write_to(&data, &peer).await?;
                        trace!("Sent {} bytes to peer {:?} (stream {})", data.len(), &peer.as_ref()[..8], pkt.stream_id);
                    }
                    None => {
                        debug!("Outgoing channel closed for peer {:?}", &peer.as_ref()[..8]);
                        return Ok(());
                    }
                }
            }
            _ = cancel.cancelled() => {
                debug!("Writer task cancelled for peer {:?}", &peer.as_ref()[..8]);
                return Ok(());
            }
        }
    }
}

impl Drop for StreamManager {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ironwood::new_encrypted_packet_conn;

    #[tokio::test]
    async fn test_manager_creation() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let manager = StreamManager::new(conn);

        assert_eq!(manager.connection_count().await, 0);
    }

    #[tokio::test]
    async fn test_manager_local_addr() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let conn = new_encrypted_packet_conn(signing_key, Default::default());
        let local_addr = conn.local_addr();

        let manager = StreamManager::new(conn);
        assert_eq!(manager.local_addr(), local_addr);
    }
}
