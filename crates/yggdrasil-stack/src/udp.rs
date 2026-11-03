//! UDP sockets.

use std::future::poll_fn;
use std::io;
use std::net::SocketAddrV6;
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::udp::{self, PacketBuffer, PacketMetadata, RecvError, SendError};

use crate::stack::{check_remote, to_smol, to_std, Inner};

/// A UDP socket bound to a port of the node's address.
///
/// Datagrams larger than the stack MTU minus headers are rejected; IPv6
/// fragmentation is not supported.
pub struct UdpSocket {
    stack: Arc<Inner>,
    handle: SocketHandle,
    port: u16,
}

impl UdpSocket {
    pub(crate) fn bind(stack: Arc<Inner>, port: u16) -> io::Result<Self> {
        let shared = &stack.shared;
        let config = &shared.config;
        let handle = {
            let mut st = shared.lock();
            st.check_open()?;
            let port = if port == 0 {
                st.alloc_udp_port()?
            } else if st.udp_port_used(port) {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("UDP port {port} is already in use"),
                ));
            } else {
                port
            };
            let mut socket = udp::Socket::new(
                PacketBuffer::new(
                    vec![PacketMetadata::EMPTY; config.udp_queue],
                    vec![0u8; config.udp_rx_buffer],
                ),
                PacketBuffer::new(
                    vec![PacketMetadata::EMPTY; config.udp_queue],
                    vec![0u8; config.udp_tx_buffer],
                ),
            );
            socket
                .bind(port)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            (st.sockets.add(socket), port)
        };
        Ok(Self { stack, handle: handle.0, port: handle.1 })
    }

    pub fn local_addr(&self) -> SocketAddrV6 {
        SocketAddrV6::new(self.stack.shared.address, self.port, 0, 0)
    }

    /// Largest datagram payload this socket can send.
    pub fn max_datagram_size(&self) -> usize {
        // IPv6 header (40) + UDP header (8).
        self.stack.shared.mtu - 48
    }

    /// Send `data` as one datagram to `target`.
    pub async fn send_to(&self, data: &[u8], target: SocketAddrV6) -> io::Result<usize> {
        poll_fn(|cx| self.poll_send_to(cx, data, target)).await
    }

    /// Receive one datagram. Bytes that do not fit in `buf` are discarded.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddrV6)> {
        poll_fn(|cx| self.poll_recv_from(cx, buf)).await
    }

    pub fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        data: &[u8],
        target: SocketAddrV6,
    ) -> Poll<io::Result<usize>> {
        check_remote(target.ip())?;
        if target.port() == 0 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "port 0 is not addressable")));
        }
        if data.len() > self.max_datagram_size() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("datagram of {} bytes exceeds {}", data.len(), self.max_datagram_size()),
            )));
        }
        let result = {
            let mut st = self.stack.shared.lock();
            if let Err(e) = st.check_open() {
                return Poll::Ready(Err(e));
            }
            let socket = st.sockets.get_mut::<udp::Socket>(self.handle);
            if data.len() > socket.payload_send_capacity() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram larger than the socket send buffer",
                )));
            }
            match socket.send_slice(data, to_smol(target)) {
                Ok(()) => Poll::Ready(Ok(data.len())),
                Err(SendError::BufferFull) => {
                    socket.register_send_waker(cx.waker());
                    return Poll::Pending;
                }
                Err(SendError::Unaddressable) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination is not addressable",
                ))),
            }
        };
        self.stack.shared.poke();
        result
    }

    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddrV6)>> {
        let mut st = self.stack.shared.lock();
        if let Err(e) = st.check_open() {
            return Poll::Ready(Err(e));
        }
        let socket = st.sockets.get_mut::<udp::Socket>(self.handle);
        match socket.recv() {
            Ok((data, meta)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Poll::Ready(Ok((n, to_std(meta.endpoint))))
            }
            Err(RecvError::Exhausted) | Err(RecvError::Truncated) => {
                socket.register_recv_waker(cx.waker());
                Poll::Pending
            }
        }
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        let mut st = self.stack.shared.lock();
        if st.closed {
            st.sockets.remove(self.handle);
        } else {
            st.orphan_udp(self.handle);
        }
    }
}
