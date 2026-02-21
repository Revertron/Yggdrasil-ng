use crate::error::{Error, Result};
use crate::protocol::{Packet, DEFAULT_WINDOW_SIZE};
use ironwood::Addr;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// SYN sent, waiting for SYN-ACK
    Opening,
    /// Active, can send/receive
    Open,
    /// FIN sent, waiting for peer FIN
    Closing,
    /// Both sides closed
    Closed,
}

/// Individual bidirectional stream
///
/// Implements AsyncRead + AsyncWrite for standard Rust async I/O.
#[derive(Clone)]
pub struct Stream {
    /// Stream identifier
    id: u32,

    /// Remote peer address (for debugging/logging)
    peer: Addr,

    /// Receive buffer (data received from peer)
    recv_buf: Arc<Mutex<VecDeque<u8>>>,

    /// Send window (bytes we can send based on peer's last ACK)
    send_window: Arc<AtomicUsize>,

    /// Receive window (bytes we can receive - our buffer space)
    recv_window: Arc<AtomicUsize>,

    /// Channel to send outgoing packets
    outgoing: mpsc::Sender<Packet>,

    /// Stream state
    state: Arc<Mutex<StreamState>>,

    /// Notify when data arrives for reading
    read_notify: Arc<Notify>,

    /// Notify when window space becomes available for writing
    write_notify: Arc<Notify>,

    /// Notify when stream is closed
    close_notify: Arc<Notify>,
}

impl Stream {
    /// Create a new stream
    pub fn new(id: u32, peer: Addr, outgoing: mpsc::Sender<Packet>) -> Self {
        Self {
            id,
            peer,
            recv_buf: Arc::new(Mutex::new(VecDeque::new())),
            send_window: Arc::new(AtomicUsize::new(DEFAULT_WINDOW_SIZE)),
            recv_window: Arc::new(AtomicUsize::new(DEFAULT_WINDOW_SIZE)),
            outgoing,
            state: Arc::new(Mutex::new(StreamState::Opening)),
            read_notify: Arc::new(Notify::new()),
            write_notify: Arc::new(Notify::new()),
            close_notify: Arc::new(Notify::new()),
        }
    }

    /// Get stream ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get remote peer address
    pub fn peer_addr(&self) -> Addr {
        self.peer
    }

    /// Get current stream state
    pub async fn state(&self) -> StreamState {
        *self.state.lock().await
    }

    /// Transition stream to Open state (used for acceptor side)
    pub(crate) async fn transition_to_open(&self) {
        let mut state = self.state.lock().await;
        *state = StreamState::Open;
        self.write_notify.notify_one();
    }

    /// Handle incoming packet
    pub async fn handle_packet(&self, packet: Packet) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            StreamState::Opening => {
                if packet.is_syn() && packet.is_ack() {
                    // Received SYN-ACK, transition to Open
                    *state = StreamState::Open;
                    // Update send window from SYN-ACK
                    self.send_window.store(packet.window, Ordering::Release);
                    self.write_notify.notify_one();
                    Ok(())
                } else {
                    Err(Error::Protocol(format!(
                        "Unexpected packet in Opening state: flags={:02x}",
                        packet.flags
                    )))
                }
            }
            StreamState::Open => {
                if packet.is_rst() {
                    // Stream reset by peer
                    *state = StreamState::Closed;
                    self.read_notify.notify_waiters();
                    self.write_notify.notify_waiters();
                    self.close_notify.notify_waiters();
                    return Err(Error::StreamReset);
                }

                if packet.is_fin() {
                    // Peer initiated close - send FIN back and transition to Closed
                    *state = StreamState::Closed;
                    self.read_notify.notify_waiters();
                    self.close_notify.notify_waiters();

                    // Release the lock before sending FIN
                    drop(state);

                    // Send FIN to acknowledge
                    let fin = Packet::fin(self.id);
                    let _ = self.outgoing.send(fin).await;

                    return Ok(());
                }

                // Update send window if ACK
                if packet.is_ack() {
                    self.send_window.store(packet.window, Ordering::Release);
                    self.write_notify.notify_one();
                }

                // Deliver data if present
                if !packet.data.is_empty() {
                    let mut recv_buf = self.recv_buf.lock().await;
                    recv_buf.extend(&packet.data);
                    self.read_notify.notify_one();

                    // Update our receive window
                    let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len());
                    self.recv_window.store(available, Ordering::Release);

                    // Send ACK with updated window
                    drop(recv_buf); // Release lock before sending
                    self.send_ack().await?;
                }

                Ok(())
            }
            StreamState::Closing => {
                if packet.is_fin() {
                    // Both sides closed
                    *state = StreamState::Closed;
                    self.close_notify.notify_waiters();
                }
                Ok(())
            }
            StreamState::Closed => {
                // Ignore packets on closed stream
                Ok(())
            }
        }
    }

    /// Send an ACK packet with current receive window
    async fn send_ack(&self) -> Result<()> {
        let window = self.recv_window.load(Ordering::Acquire);
        let packet = Packet::ack(self.id, window);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(())
    }

    /// Send a SYN packet to initiate the stream
    pub async fn send_syn(&self) -> Result<()> {
        let packet = Packet::syn(self.id);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(())
    }

    /// Immediate close (RST)
    pub async fn abort(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        if *state == StreamState::Closed {
            return Ok(());
        }

        *state = StreamState::Closed;
        let packet = Packet::rst(self.id);
        let _ = self.outgoing.send(packet).await;

        self.read_notify.notify_waiters();
        self.write_notify.notify_waiters();
        self.close_notify.notify_waiters();

        Ok(())
    }

    /// Graceful close (FIN)
    pub async fn close(&self) -> Result<()> {
        let mut state = self.state.lock().await;

        match *state {
            StreamState::Closed => return Ok(()),
            StreamState::Closing => {
                // Already closing, wait for completion
                drop(state);
                self.close_notify.notified().await;
                return Ok(());
            }
            _ => {}
        }

        *state = StreamState::Closing;
        let packet = Packet::fin(self.id);
        self.outgoing
            .send(packet)
            .await
            .map_err(|_| Error::ConnectionClosed)?;

        drop(state);

        // Wait for peer's FIN
        self.close_notify.notified().await;
        Ok(())
    }

    /// Check if stream is closed
    pub async fn is_closed(&self) -> bool {
        *self.state.lock().await == StreamState::Closed
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Try to lock recv_buf
        let mut recv_buf = match this.recv_buf.try_lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Lock contention, register waker and return pending
                this.read_notify.notify_one();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        // Check if we have data available
        if !recv_buf.is_empty() {
            let to_read = std::cmp::min(buf.remaining(), recv_buf.len());
            let data: Vec<u8> = recv_buf.drain(..to_read).collect();
            buf.put_slice(&data);

            // Update receive window
            let available = DEFAULT_WINDOW_SIZE.saturating_sub(recv_buf.len());
            this.recv_window.store(available, Ordering::Release);

            return Poll::Ready(Ok(()));
        }

        // No data available, check stream state
        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        match state {
            StreamState::Closed | StreamState::Closing => {
                // Stream closed or closing, return EOF (no data)
                Poll::Ready(Ok(()))
            }
            _ => {
                // Wait for data
                let waker = cx.waker().clone();
                let notify = this.read_notify.clone();
                tokio::spawn(async move {
                    notify.notified().await;
                    waker.wake();
                });
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Check stream state
        let state = match this.state.try_lock() {
            Ok(guard) => *guard,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if state == StreamState::Closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Stream closed",
            )));
        }

        if state != StreamState::Open {
            // Wait for stream to open
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // Check available window
        let window = this.send_window.load(Ordering::Acquire);
        if window == 0 {
            // No space available, wait for ACK
            let waker = cx.waker().clone();
            let notify = this.write_notify.clone();
            tokio::spawn(async move {
                notify.notified().await;
                waker.wake();
            });
            return Poll::Pending;
        }

        // Send what we can within the window
        let to_send = std::cmp::min(buf.len(), window);
        let data = buf[..to_send].to_vec();
        let window_after = this.recv_window.load(Ordering::Acquire);
        let packet = Packet::data_ack(this.id, data, window_after);

        // Decrease send window
        this.send_window.fetch_sub(to_send, Ordering::Release);

        // Send packet asynchronously
        let outgoing = this.outgoing.clone();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let _ = outgoing.send(packet).await;
            waker.wake();
        });

        Poll::Ready(Ok(to_send))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // No internal write buffer; flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Initiate graceful close
        let state = match this.state.try_lock() {
            Ok(mut guard) => {
                let current = *guard;
                if current == StreamState::Open {
                    *guard = StreamState::Closing;
                    drop(guard);

                    // Send FIN packet
                    let packet = Packet::fin(this.id);
                    let outgoing = this.outgoing.clone();
                    tokio::spawn(async move {
                        let _ = outgoing.send(packet).await;
                    });
                }
                current
            }
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if state == StreamState::Closed {
            return Poll::Ready(Ok(()));
        }

        // Wait for close to complete
        let waker = cx.waker().clone();
        let notify = this.close_notify.clone();
        tokio::spawn(async move {
            notify.notified().await;
            waker.wake();
        });
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{FLAG_ACK, FLAG_SYN};

    #[tokio::test]
    async fn test_stream_creation() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        assert_eq!(stream.id(), 1);
        assert_eq!(stream.state().await, StreamState::Opening);
        assert_eq!(stream.peer_addr(), Addr::from([0u8; 32]));
    }

    #[tokio::test]
    async fn test_stream_state_transitions() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        // Initial state
        assert_eq!(stream.state().await, StreamState::Opening);

        // Receive SYN-ACK -> Open
        let syn_ack = Packet::syn_ack(1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        // Note: close() waits for peer's FIN, so we can't fully test it in isolation
        // Just verify we can initiate the close
        let close_task = tokio::spawn({
            let stream = stream.clone();
            async move {
                stream.close().await
            }
        });

        // Give it a moment to send FIN
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(stream.state().await, StreamState::Closing);

        // Abort the close task since we can't complete it in unit test
        close_task.abort();
    }

    #[tokio::test]
    async fn test_stream_abort() {
        let (tx, mut rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        // Transition to Open first
        let syn_ack = Packet::syn_ack(1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Abort stream
        stream.abort().await.unwrap();
        assert_eq!(stream.state().await, StreamState::Closed);

        // Should have sent RST packet
        let packet = rx.recv().await.unwrap();
        assert!(packet.is_rst());
        assert_eq!(packet.stream_id, 1);
    }

    #[tokio::test]
    async fn test_stream_data_delivery() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        // Transition to Open
        let syn_ack = Packet::syn_ack(1);
        stream.handle_packet(syn_ack).await.unwrap();

        // Deliver data
        let data_packet = Packet::data(1, b"hello".to_vec());
        stream.handle_packet(data_packet).await.unwrap();

        // Check recv_buf has data
        let recv_buf = stream.recv_buf.lock().await;
        assert_eq!(recv_buf.len(), 5);
        let data: Vec<u8> = recv_buf.iter().copied().collect();
        assert_eq!(data, b"hello");
    }

    #[tokio::test]
    async fn test_stream_flow_control() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        // Initial send window
        assert_eq!(
            stream.send_window.load(Ordering::Acquire),
            DEFAULT_WINDOW_SIZE
        );

        // Receive ACK with new window
        let ack = Packet {
            stream_id: 1,
            flags: FLAG_ACK | FLAG_SYN,
            data: Vec::new(),
            window: 1024,
        };
        stream.handle_packet(ack).await.unwrap();

        // Window should be updated
        assert_eq!(stream.send_window.load(Ordering::Acquire), 1024);
    }

    #[tokio::test]
    async fn test_stream_reset_on_rst() {
        let (tx, _rx) = mpsc::channel(10);
        let stream = Stream::new(1, Addr::from([0u8; 32]), tx);

        // Transition to Open
        let syn_ack = Packet::syn_ack(1);
        stream.handle_packet(syn_ack).await.unwrap();
        assert_eq!(stream.state().await, StreamState::Open);

        // Receive RST
        let rst = Packet::rst(1);
        let result = stream.handle_packet(rst).await;
        assert!(matches!(result, Err(Error::StreamReset)));
        assert_eq!(stream.state().await, StreamState::Closed);
    }
}
