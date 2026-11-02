//! Connected socket pairs: one end is handed to the application as a plain OS
//! socket, the library drives the other end asynchronously.
//!
//! Unix: `socketpair(AF_UNIX)`, `SOCK_STREAM` for TCP and `SOCK_SEQPACKET`
//! (where available, else `SOCK_DGRAM`) for UDP. Windows has no socketpair,
//! so a loopback TCP connection and a pair of connected loopback UDP sockets
//! stand in.

use std::io;

#[cfg(unix)]
pub type CSocket = std::ffi::c_int;
#[cfg(windows)]
pub type CSocket = usize;

#[cfg(unix)]
pub const INVALID_SOCKET: CSocket = -1;
#[cfg(windows)]
pub const INVALID_SOCKET: CSocket = usize::MAX;

/// Socket buffer for datagram pairs; also lifts macOS's 2 KiB default limit
/// on AF_UNIX datagram size.
const DGRAM_BUFFER: usize = 512 * 1024;

#[cfg(unix)]
mod imp {
    use super::*;
    use socket2::{Domain, Socket, Type};
    use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
    use std::pin::Pin;
    use std::task::{Context, Poll, ready};
    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    #[cfg(not(target_vendor = "apple"))]
    const SEND_FLAGS: std::ffi::c_int = libc::MSG_NOSIGNAL;
    #[cfg(target_vendor = "apple")]
    const SEND_FLAGS: std::ffi::c_int = 0;

    /// Prepare the library end: non-blocking, and never raise SIGPIPE in the
    /// host process when the application has closed its end.
    fn lib_socket(s: Socket) -> io::Result<AsyncFd<Socket>> {
        #[cfg(target_vendor = "apple")]
        s.set_nosigpipe(true)?;
        s.set_nonblocking(true)?;
        // SAFETY: the Socket owns its descriptor, which stays open and
        // unchanged until the AsyncFd (and with it the Socket) is dropped.
        unsafe { AsyncFd::register(s) }.map_err(|e| e.into_parts().1)
    }

    /// Library end of a stream pair.
    pub struct LibStream(AsyncFd<Socket>);

    impl AsyncRead for LibStream {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            loop {
                let mut guard = ready!(self.0.poll_read_ready(cx))?;
                // SAFETY: recv only writes initialised bytes into the unfilled part.
                let unfilled = unsafe { buf.unfilled_mut() };
                match guard.try_io(|s| s.get_ref().recv(unfilled)) {
                    Ok(Ok(n)) => {
                        // SAFETY: recv initialised the first n bytes.
                        unsafe { buf.assume_init(n) };
                        buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
        }
    }

    impl AsyncWrite for LibStream {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = ready!(self.0.poll_write_ready(cx))?;
                match guard.try_io(|s| s.get_ref().send_with_flags(data, SEND_FLAGS)) {
                    Ok(r) => return Poll::Ready(r),
                    Err(_would_block) => continue,
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(self.0.get_ref().shutdown(std::net::Shutdown::Write))
        }
    }

    pub fn stream_pair() -> io::Result<(CSocket, LibStream)> {
        let (app, lib) = Socket::pair(Domain::UNIX, Type::STREAM, None)?;
        Ok((app.into_raw_fd(), LibStream(lib_socket(lib)?)))
    }

    /// Library end of a datagram pair.
    pub struct LibDgram(AsyncFd<Socket>);

    impl LibDgram {
        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.0.readable().await?;
                match guard.try_io(|s| {
                    // SAFETY: recv only writes initialised bytes into `buf`.
                    let uninit = unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
                    s.get_ref().recv(uninit)
                }) {
                    Ok(r) => return r,
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            loop {
                let mut guard = self.0.writable().await?;
                match guard.try_io(|s| s.get_ref().send_with_flags(buf, SEND_FLAGS)) {
                    Ok(r) => return r,
                    Err(_would_block) => continue,
                }
            }
        }

        /// Whether a zero-length read means the application closed its end.
        pub const ZERO_IS_EOF: bool = SEQPACKET;
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd"))]
    const SEQPACKET: bool = true;
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "netbsd", target_os = "openbsd")))]
    const SEQPACKET: bool = false;

    pub fn dgram_pair() -> io::Result<(CSocket, LibDgram)> {
        let ty = if SEQPACKET { Type::SEQPACKET } else { Type::DGRAM };
        let (app, lib) = Socket::pair(Domain::UNIX, ty, None)?;
        for s in [&app, &lib] {
            let _ = s.set_send_buffer_size(DGRAM_BUFFER);
            let _ = s.set_recv_buffer_size(DGRAM_BUFFER);
        }
        Ok((app.into_raw_fd(), LibDgram(lib_socket(lib)?)))
    }

    /// Close an application-side socket the library takes back.
    pub fn close(s: CSocket) {
        // SAFETY: the caller hands over ownership of `s`.
        drop(unsafe { OwnedFd::from_raw_fd(s) });
    }

    /// Consume one notification byte from `s` if one is available, without
    /// blocking and without changing the socket's mode.
    pub fn drain_byte(s: CSocket) {
        let mut b = 0u8;
        // SAFETY: plain recv of one byte into a local buffer.
        unsafe { libc::recv(s, (&mut b as *mut u8).cast(), 1, libc::MSG_DONTWAIT) };
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::os::windows::io::{FromRawSocket, IntoRawSocket, OwnedSocket, RawSocket};
    use windows_sys::Win32::Networking::WinSock::{FIONREAD, ioctlsocket, recv};

    pub type LibStream = tokio::net::TcpStream;

    pub fn stream_pair() -> io::Result<(CSocket, LibStream)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let app = TcpStream::connect(listener.local_addr()?)?;
        let expected = app.local_addr()?;
        // Only accept our own connection, not another local process's.
        let lib = loop {
            let (s, from) = listener.accept()?;
            if from == expected {
                break s;
            }
        };
        app.set_nodelay(true)?;
        lib.set_nodelay(true)?;
        lib.set_nonblocking(true)?;
        Ok((app.into_raw_socket() as CSocket, LibStream::from_std(lib)?))
    }

    pub struct LibDgram(tokio::net::UdpSocket);

    impl LibDgram {
        pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf).await
        }

        pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
            self.0.send(buf).await
        }

        pub const ZERO_IS_EOF: bool = false;
    }

    pub fn dgram_pair() -> io::Result<(CSocket, LibDgram)> {
        let local: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
        let app = UdpSocket::bind(local)?;
        let lib = UdpSocket::bind(local)?;
        app.connect(lib.local_addr()?)?;
        lib.connect(app.local_addr()?)?;
        for s in [&app, &lib] {
            let s = socket2::SockRef::from(s);
            let _ = s.set_send_buffer_size(DGRAM_BUFFER);
            let _ = s.set_recv_buffer_size(DGRAM_BUFFER);
        }
        lib.set_nonblocking(true)?;
        Ok((app.into_raw_socket() as CSocket, LibDgram(tokio::net::UdpSocket::from_std(lib)?)))
    }

    pub fn close(s: CSocket) {
        // SAFETY: the caller hands over ownership of `s`.
        drop(unsafe { OwnedSocket::from_raw_socket(s as RawSocket) });
    }

    pub fn drain_byte(s: CSocket) {
        let mut available: u32 = 0;
        // SAFETY: FIONREAD only reports the number of queued bytes.
        let ok = unsafe { ioctlsocket(s as _, FIONREAD, &mut available) } == 0;
        if ok && available > 0 {
            let mut b = 0u8;
            // SAFETY: a byte is queued, so this recv does not block.
            unsafe { recv(s as _, &mut b, 1, 0) };
        }
    }
}

pub use imp::*;
