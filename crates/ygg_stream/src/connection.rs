use crate::error::{Error, Result};
use crate::protocol::Packet;
use crate::stream::{Stream, StreamState};
use ironwood::Addr;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

/// Connection represents a multiplexed connection to a single peer
///
/// Manages multiple streams and handles packet demultiplexing.
pub struct Connection {
    /// Remote peer address
    peer: Addr,

    /// Active streams (stream_id -> Stream)
    streams: Arc<RwLock<HashMap<u32, Arc<Stream>>>>,

    /// Channel for incoming streams (accepted by peer)
    incoming_streams: Arc<Mutex<mpsc::Receiver<Arc<Stream>>>>,

    /// Sender for incoming streams (used internally)
    incoming_tx: mpsc::Sender<Arc<Stream>>,

    /// Next stream ID for outgoing streams (odd for initiator, even for acceptor)
    next_stream_id: AtomicU32,

    /// Channel to send outgoing packets
    outgoing: mpsc::Sender<Packet>,

    /// Cancellation token for graceful shutdown
    cancel: CancellationToken,

    /// Whether this connection is the initiator
    is_initiator: bool,
}

impl Connection {
    /// Create a new connection as initiator (uses odd stream IDs)
    pub fn new_initiator(peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(16);

        Self {
            peer,
            streams: Arc::new(RwLock::new(HashMap::new())),
            incoming_streams: Arc::new(Mutex::new(incoming_rx)),
            incoming_tx,
            next_stream_id: AtomicU32::new(1), // Start with 1 (odd)
            outgoing,
            cancel: CancellationToken::new(),
            is_initiator: true,
        }
    }

    /// Create a new connection as acceptor (uses even stream IDs)
    pub fn new_acceptor(peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        let (incoming_tx, incoming_rx) = mpsc::channel(16);

        Self {
            peer,
            streams: Arc::new(RwLock::new(HashMap::new())),
            incoming_streams: Arc::new(Mutex::new(incoming_rx)),
            incoming_tx,
            next_stream_id: AtomicU32::new(2), // Start with 2 (even)
            outgoing,
            cancel: CancellationToken::new(),
            is_initiator: false,
        }
    }

    /// Get the remote peer address
    pub fn peer_addr(&self) -> Addr {
        self.peer
    }

    /// Check if connection is alive
    pub fn is_alive(&self) -> bool {
        !self.cancel.is_cancelled()
    }

    /// Open a new stream to the peer
    ///
    /// Sends SYN packets with retransmission until SYN-ACK is received or timeout occurs.
    /// Retransmits every 500ms. Default timeout is 30 seconds.
    pub async fn open_stream(&self) -> Result<Stream> {
        self.open_stream_timeout(std::time::Duration::from_secs(30)).await
    }

    /// Open a new stream to the peer with custom timeout
    ///
    /// Sends SYN packets every 500ms until SYN-ACK is received or timeout occurs.
    pub async fn open_stream_timeout(&self, timeout: std::time::Duration) -> Result<Stream> {
        if self.cancel.is_cancelled() {
            return Err(Error::ConnectionClosed);
        }

        // Allocate stream ID (odd for initiator, even for acceptor)
        let stream_id = self.allocate_stream_id();

        // Create stream
        let stream = Stream::new(stream_id, self.peer, self.outgoing.clone());
        let stream_arc = Arc::new(stream.clone());

        // Register stream
        {
            let mut streams = self.streams.write().await;
            if streams.contains_key(&stream_id) {
                return Err(Error::StreamExists(stream_id));
            }
            streams.insert(stream_id, stream_arc);
        }

        debug!(
            "Opening stream {} to peer {:?}, timeout: {:?}",
            stream_id,
            &self.peer,
            timeout
        );

        // Send SYN with retransmission until we get SYN-ACK or timeout
        let start = tokio::time::Instant::now();
        loop {
            // Send SYN packet
            stream.send_syn().await?;
            trace!("Sent SYN for stream {}", stream_id);

            // Wait 500ms for SYN-ACK
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                // Cleanup: remove stream from registry
                let mut streams = self.streams.write().await;
                streams.remove(&stream_id);
                return Err(Error::Timeout);
            }

            let wait_time = std::cmp::min(
                std::time::Duration::from_millis(500),
                remaining
            );

            tokio::select! {
                _ = tokio::time::sleep(wait_time) => {
                    // Check if stream is now open
                    if stream.state().await == StreamState::Open {
                        debug!("Stream {} opened successfully", stream_id);
                        return Ok(stream);
                    }
                    // Loop continues to retransmit
                }
                _ = self.cancel.cancelled() => {
                    // Cleanup
                    let mut streams = self.streams.write().await;
                    streams.remove(&stream_id);
                    return Err(Error::ConnectionClosed);
                }
            }
        }
    }

    /// Accept an incoming stream from the peer
    pub async fn accept_stream(&self) -> Result<Stream> {
        if self.cancel.is_cancelled() {
            return Err(Error::ConnectionClosed);
        }

        let mut incoming = self.incoming_streams.lock().await;

        tokio::select! {
            stream_arc = incoming.recv() => {
                let arc = stream_arc.ok_or(Error::ConnectionClosed)?;
                // Clone the stream data (not the Arc)
                Ok((*arc).clone())
            }
            _ = self.cancel.cancelled() => {
                Err(Error::ConnectionClosed)
            }
        }
    }

    /// Handle an incoming packet and route it to the appropriate stream
    pub async fn handle_packet(&self, packet: Packet) -> Result<()> {
        let stream_id = packet.stream_id;

        // Check if this is a SYN packet (new stream from peer)
        if packet.is_syn() && !packet.is_ack() {
            return self.handle_incoming_stream(packet).await;
        }

        // Route to existing stream
        let stream = {
            let streams = self.streams.read().await;
            streams.get(&stream_id).cloned()
        };

        if let Some(stream) = stream {
            stream.handle_packet(packet).await?;

            // Remove stream if closed
            if stream.is_closed().await {
                let mut streams = self.streams.write().await;
                streams.remove(&stream_id);
                trace!("Removed closed stream {}", stream_id);
            }
        } else {
            warn!(
                "Received packet for unknown stream {} from peer {:?}",
                stream_id,
                &self.peer
            );
        }

        Ok(())
    }

    /// Handle a new incoming stream (SYN packet)
    async fn handle_incoming_stream(&self, packet: Packet) -> Result<()> {
        let stream_id = packet.stream_id;

        // Validate stream ID (should not match our allocation scheme)
        if self.is_initiator && stream_id % 2 == 1 {
            return Err(Error::Protocol(format!(
                "Received odd stream ID {} from peer (we are initiator)",
                stream_id
            )));
        }
        if !self.is_initiator && stream_id % 2 == 0 {
            return Err(Error::Protocol(format!(
                "Received even stream ID {} from peer (we are acceptor)",
                stream_id
            )));
        }

        // Check if stream already exists
        {
            let streams = self.streams.read().await;
            if streams.contains_key(&stream_id) {
                // Duplicate SYN, ignore
                debug!("Duplicate SYN for stream {}", stream_id);
                return Ok(());
            }
        }

        // Create new stream and transition to Open state immediately
        let stream = Arc::new(Stream::new(stream_id, self.peer, self.outgoing.clone()));

        // For acceptor, transition directly to Open state (we don't need to wait for SYN-ACK)
        stream.transition_to_open().await;

        // Send SYN-ACK to client
        let syn_ack = Packet::syn_ack(stream_id);
        self.outgoing
            .send(syn_ack)
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        // Register stream
        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream.clone());
        }

        // Notify incoming stream channel
        self.incoming_tx
            .send(stream)
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        debug!(
            "Accepted incoming stream {} from peer {:?}",
            stream_id,
            &self.peer
        );

        Ok(())
    }

    /// Allocate a new stream ID
    fn allocate_stream_id(&self) -> u32 {
        // Odd IDs for initiator, even for acceptor
        let increment = 2;
        self.next_stream_id.fetch_add(increment, Ordering::Relaxed)
    }

    /// Close the connection and all streams
    pub async fn close(&self) {
        self.cancel.cancel();

        // Close all streams
        let streams = {
            let mut streams_lock = self.streams.write().await;
            let current_streams: Vec<_> = streams_lock.values().cloned().collect();
            streams_lock.clear();
            current_streams
        };

        for stream in streams {
            let _ = stream.abort().await;
        }

        debug!("Closed connection to peer {:?}", &self.peer);
    }

    /// Get the number of active streams
    pub async fn stream_count(&self) -> usize {
        self.streams.read().await.len()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_creation_initiator() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([1u8; 32]);
        let conn = Connection::new_initiator(peer, tx);

        assert_eq!(conn.peer_addr(), peer);
        assert!(conn.is_initiator);
        assert_eq!(conn.next_stream_id.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_connection_creation_acceptor() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([2u8; 32]);
        let conn = Connection::new_acceptor(peer, tx);

        assert_eq!(conn.peer_addr(), peer);
        assert!(!conn.is_initiator);
        assert_eq!(conn.next_stream_id.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn test_stream_id_allocation_initiator() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([0u8; 32]);
        let conn = Connection::new_initiator(peer, tx);

        let id1 = conn.allocate_stream_id();
        let id2 = conn.allocate_stream_id();
        let id3 = conn.allocate_stream_id();

        // Should allocate odd IDs
        assert_eq!(id1, 1);
        assert_eq!(id2, 3);
        assert_eq!(id3, 5);
    }

    #[test]
    fn test_stream_id_allocation_acceptor() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([0u8; 32]);
        let conn = Connection::new_acceptor(peer, tx);

        let id1 = conn.allocate_stream_id();
        let id2 = conn.allocate_stream_id();
        let id3 = conn.allocate_stream_id();

        // Should allocate even IDs
        assert_eq!(id1, 2);
        assert_eq!(id2, 4);
        assert_eq!(id3, 6);
    }

    #[tokio::test]
    async fn test_connection_is_alive() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([0u8; 32]);
        let conn = Connection::new_initiator(peer, tx);

        assert!(conn.is_alive());

        conn.close().await;
        assert!(!conn.is_alive());
    }

    #[tokio::test]
    async fn test_stream_count() {
        let (tx, _rx) = mpsc::channel(10);
        let peer = Addr::from([0u8; 32]);
        let conn = Connection::new_initiator(peer, tx);

        assert_eq!(conn.stream_count().await, 0);

        // Note: open_stream() now waits for SYN-ACK, so we use a short timeout
        // In a unit test without a reader task, this will timeout
        let result1 = conn.open_stream_timeout(std::time::Duration::from_millis(100)).await;
        assert!(result1.is_err()); // Should timeout
        assert_eq!(conn.stream_count().await, 0); // Stream removed on timeout

        // Test that streams ARE registered during the opening process
        // We can't easily test successful open without a full integration test
    }
}
