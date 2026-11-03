//! ICMPv6 echo (ping). Echo requests to the node's address are answered by
//! smoltcp itself.

use std::future::poll_fn;
use std::io;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use rand::Rng;
use smoltcp::iface::SocketHandle;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::icmp::{self, Endpoint, PacketBuffer, PacketMetadata};
use smoltcp::wire::{IpAddress, Icmpv6Packet, Icmpv6Repr};

use crate::stack::{check_remote, Inner};

const PAYLOAD_LEN: usize = 16;
const SOCKET_BUFFER: usize = 4096;

/// Removes the ICMP socket when the ping finishes, fails or is cancelled.
struct PingSocket<'a> {
    stack: &'a Arc<Inner>,
    handle: SocketHandle,
    ident: u16,
}

impl Drop for PingSocket<'_> {
    fn drop(&mut self) {
        let mut st = self.stack.shared.lock();
        st.sockets.remove(self.handle);
        st.icmp_idents.remove(&self.ident);
    }
}

pub(crate) async fn ping(stack: &Arc<Inner>, addr: Ipv6Addr, timeout: Duration) -> io::Result<Duration> {
    check_remote(&addr)?;
    let shared = &stack.shared;
    let mut payload = [0u8; PAYLOAD_LEN];
    rand::thread_rng().fill(&mut payload);
    let seq_no = 1;

    let socket = {
        let mut st = shared.lock();
        st.check_open()?;
        let mut rng = rand::thread_rng();
        let ident = loop {
            let ident = rng.r#gen::<u16>();
            if ident != 0 && st.icmp_idents.insert(ident) {
                break ident;
            }
        };
        let mut socket = icmp::Socket::new(
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; SOCKET_BUFFER]),
            PacketBuffer::new(vec![PacketMetadata::EMPTY; 4], vec![0u8; SOCKET_BUFFER]),
        );
        socket
            .bind(Endpoint::Ident(ident))
            .map_err(|e| io::Error::other(e.to_string()))?;

        let request = Icmpv6Repr::EchoRequest { ident, seq_no, data: &payload };
        let mut bytes = vec![0u8; request.buffer_len()];
        request.emit(
            &shared.address,
            &addr,
            &mut Icmpv6Packet::new_unchecked(&mut bytes[..]),
            &ChecksumCapabilities::default(),
        );
        socket
            .send_slice(&bytes, IpAddress::Ipv6(addr))
            .map_err(|e| io::Error::other(e.to_string()))?;

        let handle = st.sockets.add(socket);
        PingSocket { stack, handle, ident }
    };
    let start = Instant::now();
    shared.poke();

    let reply = poll_fn(|cx| {
        let mut st = shared.lock();
        if let Err(e) = st.check_open() {
            return Poll::Ready(Err(e));
        }
        let s = st.sockets.get_mut::<icmp::Socket>(socket.handle);
        while let Ok((data, from)) = s.recv() {
            #[allow(irrefutable_let_patterns)]
            let IpAddress::Ipv6(from) = from else { continue };
            let Ok(packet) = Icmpv6Packet::new_checked(data) else { continue };
            let Ok(repr) = Icmpv6Repr::parse(
                &from,
                &shared.address,
                &packet,
                &ChecksumCapabilities::default(),
            ) else {
                continue;
            };
            if let Icmpv6Repr::EchoReply { ident, seq_no: seq, data } = repr
                && from == addr
                && ident == socket.ident
                && seq == seq_no
                && data == payload
            {
                return Poll::Ready(Ok(start.elapsed()));
            }
        }
        s.register_recv_waker(cx.waker());
        Poll::Pending
    });

    match tokio::time::timeout(timeout, reply).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "ping timed out")),
    }
}
