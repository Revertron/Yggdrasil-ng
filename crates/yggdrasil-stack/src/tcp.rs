//! TCP streams and listeners.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV6;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{self, CongestionControl, RecvError, SendError};
use smoltcp::storage::RingBuffer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stack::{check_remote, to_smol, to_std, Inner, StackConfig};

fn new_socket(config: &StackConfig) -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        RingBuffer::new(vec![0u8; config.tcp_rx_buffer]),
        RingBuffer::new(vec![0u8; config.tcp_tx_buffer]),
    );
    socket.set_congestion_control(CongestionControl::Cubic);
    socket
}

pub(crate) fn new_listen_socket(config: &StackConfig, port: u16) -> io::Result<tcp::Socket<'static>> {
    let mut socket = new_socket(config);
    socket
        .listen(port)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(socket)
}

/// A TCP connection over Yggdrasil. Implements tokio's `AsyncRead` and
/// `AsyncWrite`; use `tokio::io::split` to read and write from separate tasks.
///
/// Dropping the stream closes it gracefully in the background.
pub struct TcpStream {
    stack: Arc<Inner>,
    handle: SocketHandle,
    local: SocketAddrV6,
    peer: SocketAddrV6,
}

impl TcpStream {
    pub(crate) async fn connect(stack: Arc<Inner>, addr: SocketAddrV6) -> io::Result<Self> {
        check_remote(addr.ip())?;
        if addr.port() == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "port 0 is not connectable"));
        }
        let shared = &stack.shared;
        let stream = {
            let mut guard = shared.lock();
            let st = &mut *guard;
            st.check_open()?;
            let local_port = st.alloc_tcp_port()?;
            let mut socket = new_socket(&shared.config);
            socket
                .connect(st.iface.context(), to_smol(addr), local_port)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let handle = st.sockets.add(socket);
            let local = SocketAddrV6::new(shared.address, local_port, 0, 0);
            // From here on, dropping the stream (error, timeout or a cancelled
            // future) hands the socket back to the driver for cleanup.
            TcpStream { stack: stack.clone(), handle, local, peer: addr }
        };
        shared.poke();

        match tokio::time::timeout(
            shared.config.connect_timeout,
            poll_fn(|cx| stream.poll_established(cx)),
        )
        .await
        {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connection timed out")),
        }
    }

    fn poll_established(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.with_socket(|socket| match socket.state() {
            tcp::State::SynSent | tcp::State::SynReceived => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            tcp::State::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "connection refused",
            ))),
            _ => Poll::Ready(Ok(())),
        })
    }

    /// Run `f` on the socket, failing if the stack has shut down.
    fn with_socket<R>(&self, f: impl FnOnce(&mut tcp::Socket<'static>) -> Poll<io::Result<R>>) -> Poll<io::Result<R>> {
        let mut st = self.stack.shared.lock();
        if let Err(e) = st.check_open() {
            return Poll::Ready(Err(e));
        }
        f(st.sockets.get_mut::<tcp::Socket>(self.handle))
    }

    pub fn local_addr(&self) -> SocketAddrV6 {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddrV6 {
        self.peer
    }

    /// Disable (`true`) or enable Nagle's algorithm. Enabled by default.
    pub fn set_nodelay(&self, nodelay: bool) {
        let mut st = self.stack.shared.lock();
        st.sockets.get_mut::<tcp::Socket>(self.handle).set_nagle_enabled(!nodelay);
    }

    /// Send keep-alive probes after `interval` of inactivity. Off by default.
    pub fn set_keepalive(&self, interval: Option<Duration>) {
        {
            let mut st = self.stack.shared.lock();
            st.sockets
                .get_mut::<tcp::Socket>(self.handle)
                .set_keep_alive(interval.map(Into::into));
        }
        self.stack.shared.poke();
    }

    /// Abort the connection when sent data stays unacknowledged for `timeout`
    /// (also applies to keep-alive probes). Off by default.
    pub fn set_timeout(&self, timeout: Option<Duration>) {
        let mut st = self.stack.shared.lock();
        st.sockets
            .get_mut::<tcp::Socket>(self.handle)
            .set_timeout(timeout.map(Into::into));
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let result = self.with_socket(|socket| match socket.recv_slice(buf.initialize_unfilled()) {
            Ok(0) => {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(true))
            }
            // Peer sent FIN and everything has been read.
            Err(RecvError::Finished) => Poll::Ready(Ok(false)),
            Err(RecvError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "connection reset",
            ))),
        });
        match result {
            Poll::Ready(Ok(read)) => {
                // Draining the buffer opens the receive window.
                if read {
                    self.stack.shared.poke();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let result = self.with_socket(|socket| match socket.send_slice(data) {
            Ok(0) if socket.may_send() => {
                socket.register_send_waker(cx.waker());
                Poll::Pending
            }
            Ok(0) | Err(SendError::InvalidState) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed for writing",
            ))),
            Ok(n) => Poll::Ready(Ok(n)),
        });
        if let Poll::Ready(Ok(_)) = result {
            self.stack.shared.poke();
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Data handed to the socket is already queued for transmission.
        Poll::Ready(Ok(()))
    }

    /// Send FIN once the queued data is out. Reading stays possible.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.with_socket(|socket| {
            socket.close();
            Poll::Ready(Ok(()))
        });
        self.stack.shared.poke();
        result
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        {
            let mut st = self.stack.shared.lock();
            if st.closed {
                st.sockets.remove(self.handle);
            } else {
                st.orphan_tcp(self.handle);
            }
        }
        self.stack.shared.poke();
    }
}

/// Accepts TCP connections on one port of the node's address.
///
/// Up to [`StackConfig::tcp_backlog`] connections can be handshaking or
/// waiting for [`accept`](Self::accept); SYNs beyond that are dropped so the
/// client retries later.
pub struct TcpListener {
    stack: Arc<Inner>,
    port: u16,
}

impl TcpListener {
    pub(crate) fn bind(stack: Arc<Inner>, port: u16) -> io::Result<Self> {
        if port == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot listen on port 0"));
        }
        let shared = &stack.shared;
        {
            let mut st = shared.lock();
            st.check_open()?;
            if st.listeners.contains_key(&port) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("TCP port {port} is already in use"),
                ));
            }
            // One spare listening socket; the driver adds more as SYNs arrive.
            let handles = vec![st.sockets.add(new_listen_socket(&shared.config, port)?)];
            st.listeners.insert(port, handles);
        }
        Ok(Self { stack, port })
    }

    pub fn local_addr(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.stack.shared.address, self.port, 0, 0)
    }

    /// Wait for the next established connection.
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddrV6)> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Poll for an established connection. Only the most recent waker is kept,
    /// so accept from one task at a time.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddrV6)>> {
        let shared = &self.stack.shared;
        let mut guard = shared.lock();
        let st = &mut *guard;
        if let Err(e) = st.check_open() {
            return Poll::Ready(Err(e));
        }
        let Some(backlog) = st.listeners.get_mut(&self.port) else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "listener closed")));
        };

        for i in 0..backlog.len() {
            let socket = st.sockets.get_mut::<tcp::Socket>(backlog[i]);
            match socket.state() {
                tcp::State::Listen | tcp::State::SynReceived => {
                    socket.register_recv_waker(cx.waker());
                }
                tcp::State::Closed => {
                    // Handshake reset before it was accepted: listen again.
                    let _ = socket.listen(self.port);
                    socket.register_recv_waker(cx.waker());
                }
                _ => {
                    let local = socket.local_endpoint().map(to_std).unwrap_or_else(|| self.local_addr());
                    let peer = socket.remote_endpoint().map(to_std).unwrap_or(local);
                    let accepted = backlog.swap_remove(i);
                    if backlog.is_empty() {
                        match new_listen_socket(&shared.config, self.port) {
                            Ok(s) => backlog.push(st.sockets.add(s)),
                            Err(e) => tracing::warn!("stack: cannot re-arm listener: {}", e),
                        }
                    }
                    drop(guard);
                    let stream = TcpStream {
                        stack: self.stack.clone(),
                        handle: accepted,
                        local,
                        peer,
                    };
                    return Poll::Ready(Ok((stream, peer)));
                }
            }
        }
        Poll::Pending
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        {
            let mut st = self.stack.shared.lock();
            if let Some(backlog) = st.listeners.remove(&self.port) {
                for handle in backlog {
                    if st.closed {
                        st.sockets.remove(handle);
                    } else {
                        st.orphan_tcp(handle);
                    }
                }
            }
        }
        self.stack.shared.poke();
    }
}
