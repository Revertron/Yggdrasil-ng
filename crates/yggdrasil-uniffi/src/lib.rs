//! UniFFI bindings (Kotlin, Swift) for an embedded Yggdrasil node.
//!
//! A thin layer over `yggdrasil-embed`. Connections are returned as file
//! descriptors (`Int`); on Android wrap them with
//! `ParcelFileDescriptor.adoptFd(fd)`. See `bindings/kotlin` for the
//! generated package, helpers and tests.
//!
//! The exports can also be pulled into an existing UniFFI library: depend on
//! this crate and generate bindings for the combined library.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use yggdrasil_embed as embed;
use yggdrasil_embed::{EmbeddedNode, Host, StartOptions, Target};

uniffi::setup_scaffolding!();

/// Errors raised by [`YggNode`]; the message carries the details.
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum YggException {
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    ConnectionRefused(String),
    #[error("{0}")]
    TimedOut(String),
    #[error("{0}")]
    AddrInUse(String),
    /// The node, listener or connection is closed.
    #[error("{0}")]
    Closed(String),
    /// Nothing pending (non-blocking accept).
    #[error("{0}")]
    WouldBlock(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Io(String),
}

impl From<embed::Error> for YggException {
    fn from(e: embed::Error) -> Self {
        let m = e.message;
        match e.code {
            embed::ERR_INVALID_ARGUMENT => Self::InvalidArgument(m),
            embed::ERR_CONFIG => Self::Config(m),
            embed::ERR_CONNECTION_REFUSED => Self::ConnectionRefused(m),
            embed::ERR_TIMED_OUT => Self::TimedOut(m),
            embed::ERR_ADDR_IN_USE => Self::AddrInUse(m),
            embed::ERR_CLOSED => Self::Closed(m),
            embed::ERR_WOULD_BLOCK => Self::WouldBlock(m),
            embed::ERR_NOT_FOUND => Self::NotFound(m),
            _ => Self::Io(m),
        }
    }
}

type Result<T> = std::result::Result<T, YggException>;

fn parse<T: std::str::FromStr<Err = std::io::Error>>(s: &str) -> Result<T> {
    s.parse::<T>().map_err(|e| YggException::InvalidArgument(e.to_string()))
}

fn socket_addr(s: &str) -> Result<SocketAddr> {
    s.parse()
        .map_err(|_| YggException::InvalidArgument(format!("{s:?} is not an IP:port address")))
}

fn millis(ms: Option<u32>) -> Option<Duration> {
    ms.map(|ms| Duration::from_millis(ms.into()))
}

/// Descriptors are file descriptors on Unix (Android, Linux, macOS, iOS).
/// (The casts matter on Windows, where sockets are `usize`.)
#[allow(clippy::unnecessary_cast)]
fn fd(s: embed::CSocket) -> i32 {
    s as i32
}

#[allow(clippy::unnecessary_cast)]
fn csock(fd: i32) -> embed::CSocket {
    fd as embed::CSocket
}

/// A connection accepted by [`YggNode::tcp_accept`].
#[derive(uniffi::Record)]
pub struct Accepted {
    /// Connected stream socket; the caller owns it.
    pub fd: i32,
    /// "[address]:port" of the remote side.
    pub peer: String,
}

/// A UDP socket from [`YggNode::udp_bind`].
#[derive(uniffi::Record)]
pub struct UdpBinding {
    /// Datagram socket; each datagram starts with an 18-byte header (IPv6
    /// address, big-endian port). Close with [`YggNode::udp_close`].
    pub fd: i32,
    pub port: u16,
}

/// Receives the library's log lines (from library threads).
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    /// `level`: 1 = error, 2 = warn, 3 = info, 4 = debug, 5 = trace.
    fn log(&self, level: i32, message: String);
}

/// Route library logs to `sink`. `filter` uses tracing EnvFilter syntax
/// ("info", "warn,yggdrasil::links=debug"). Once per process.
#[uniffi::export]
pub fn set_logger(sink: Arc<dyn LogSink>, filter: String) -> Result<()> {
    embed::set_logger(move |level, message| sink.log(level, message.to_string()), &filter)?;
    Ok(())
}

/// A new TOML configuration with a fresh private key.
#[uniffi::export]
pub fn generate_config() -> String {
    EmbeddedNode::generate_config()
}

/// Half-close a stream socket from `tcp_connect`/`tcp_accept`: the peer sees
/// EOF while reading stays possible (Java streams on a descriptor cannot do
/// this themselves).
#[uniffi::export]
pub fn shutdown_write(fd: i32) -> Result<()> {
    embed::sockpair::shutdown_write(csock(fd)).map_err(|e| embed::Error::from(e).into())
}

/// Size of the address header on UDP datagrams.
#[uniffi::export]
pub fn udp_header_len() -> u32 {
    embed::UDP_HEADER_LEN as u32
}

/// A running node. Methods block the calling thread (call them off the main
/// thread, e.g. on `Dispatchers.IO`) and may be used from several threads.
/// `shutdown()` stops it; closing the Kotlin object (`close()`/`use {}`)
/// stops it and frees the handle.
#[derive(uniffi::Object)]
pub struct YggNode {
    node: Mutex<Option<Arc<EmbeddedNode>>>,
}

impl YggNode {
    fn get(&self) -> Result<Arc<EmbeddedNode>> {
        self.node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| YggException::Closed("node is closed".into()))
    }
}

#[uniffi::export]
impl YggNode {
    /// Start a node from TOML configuration (null: defaults with an ephemeral
    /// key). TUN settings are ignored; `admin` also starts the admin socket.
    #[uniffi::constructor(default(config_toml = None, admin = false))]
    pub fn new(config_toml: Option<String>, admin: bool) -> Result<Arc<Self>> {
        let node = EmbeddedNode::start_toml(config_toml.as_deref(), StartOptions { admin })?;
        Ok(Arc::new(Self { node: Mutex::new(Some(Arc::new(node))) }))
    }

    pub fn address(&self) -> Result<String> {
        Ok(self.get()?.address().to_string())
    }

    pub fn subnet(&self) -> Result<String> {
        Ok(self.get()?.subnet()?)
    }

    /// Hex-encoded public key; "<key>.pk.ygg" names this node.
    pub fn public_key(&self) -> Result<String> {
        Ok(hex::encode(self.get()?.public_key()?))
    }

    pub fn add_peer(&self, uri: String) -> Result<()> {
        Ok(self.get()?.add_peer(&uri)?)
    }

    pub fn remove_peer(&self, uri: String) -> Result<()> {
        Ok(self.get()?.remove_peer(&uri)?)
    }

    /// Admin API request as JSON (`{"request":"getPeers"}`); returns JSON.
    pub fn admin(&self, request_json: String) -> Result<String> {
        Ok(self.get()?.admin(&request_json)?)
    }

    /// Address of `host` (address, hex key or "<key>.pk.ygg").
    pub fn resolve(&self, host: String) -> Result<String> {
        let host: Host = parse(&host)?;
        Ok(self.get()?.resolve(&host)?.to_string())
    }

    /// Round-trip time in microseconds. `timeout_ms` null: 5 s.
    #[uniffi::method(default(timeout_ms = None))]
    pub fn ping(&self, host: String, timeout_ms: Option<u32>) -> Result<u64> {
        let host: Host = parse(&host)?;
        let rtt = self.get()?.ping(&host, millis(timeout_ms))?;
        Ok(rtt.as_micros().min(u64::MAX as u128) as u64)
    }

    /// Connect and return a connected stream socket (fd). `timeout_ms`
    /// null: 30 s.
    #[uniffi::method(default(timeout_ms = None))]
    pub fn tcp_connect(&self, host: String, port: u16, timeout_ms: Option<u32>) -> Result<i32> {
        if port == 0 {
            return Err(YggException::InvalidArgument("port is 0".into()));
        }
        let target = Target { host: parse(&host)?, port };
        Ok(fd(self.get()?.tcp_connect(&target, millis(timeout_ms))?))
    }

    /// Listen on `port`. The returned fd becomes readable when a connection
    /// is pending; do not read it. Close with [`tcp_listener_close`].
    pub fn tcp_listen(&self, port: u16) -> Result<i32> {
        Ok(fd(self.get()?.tcp_listen(port)?))
    }

    /// Accept a connection. `timeout_ms` null waits forever; 0 throws
    /// `WouldBlock` when nothing is pending.
    #[uniffi::method(default(timeout_ms = None))]
    pub fn tcp_accept(&self, listener: i32, timeout_ms: Option<u32>) -> Result<Accepted> {
        let (sock, peer) = self.get()?.tcp_accept(csock(listener), millis(timeout_ms))?;
        Ok(Accepted { fd: fd(sock), peer: peer.to_string() })
    }

    pub fn tcp_listener_close(&self, listener: i32) -> Result<()> {
        Ok(self.get()?.tcp_listener_close(csock(listener))?)
    }

    /// Bind a UDP port (0 picks one).
    #[uniffi::method(default(port = 0))]
    pub fn udp_bind(&self, port: u16) -> Result<UdpBinding> {
        let (sock, port) = self.get()?.udp_bind(port)?;
        Ok(UdpBinding { fd: fd(sock), port })
    }

    pub fn udp_close(&self, fd: i32) -> Result<()> {
        Ok(self.get()?.udp_close(csock(fd))?)
    }

    /// SOCKS5 server on host address `listen` ("127.0.0.1:1080"). Returns a
    /// service id for [`service_stop`].
    #[uniffi::method(default(username = None, password = None))]
    pub fn socks5_start(&self, listen: String, username: Option<String>, password: Option<String>) -> Result<i32> {
        let listen = socket_addr(&listen)?;
        let creds = match (&username, &password) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_str())),
            (None, None) => None,
            _ => {
                return Err(YggException::InvalidArgument(
                    "give both username and password, or neither".into(),
                ));
            }
        };
        Ok(self.get()?.socks5_start(listen, creds)?)
    }

    /// Host TCP `listen` -> Yggdrasil `target` ("[addr]:port" or "<key>.pk.ygg:port").
    pub fn forward_local_tcp(&self, listen: String, target: String) -> Result<i32> {
        let (listen, target): (SocketAddr, Target) = (socket_addr(&listen)?, parse(&target)?);
        Ok(self.get()?.forward_local_tcp(listen, target)?)
    }

    pub fn forward_local_udp(&self, listen: String, target: String) -> Result<i32> {
        let (listen, target): (SocketAddr, Target) = (socket_addr(&listen)?, parse(&target)?);
        Ok(self.get()?.forward_local_udp(listen, target)?)
    }

    /// Yggdrasil TCP `port` -> host service `target` ("127.0.0.1:8080").
    pub fn forward_remote_tcp(&self, port: u16, target: String) -> Result<i32> {
        Ok(self.get()?.forward_remote_tcp(port, socket_addr(&target)?)?)
    }

    pub fn forward_remote_udp(&self, port: u16, target: String) -> Result<i32> {
        Ok(self.get()?.forward_remote_udp(port, socket_addr(&target)?)?)
    }

    pub fn service_stop(&self, id: i32) -> Result<()> {
        Ok(self.get()?.service_stop(id)?)
    }

    pub fn is_closed(&self) -> bool {
        self.node.lock().unwrap_or_else(|e| e.into_inner()).is_none()
    }

    /// Stop the node. Idempotent; wakes threads blocked in `tcp_accept`.
    /// Connections see EOF; the caller still closes its own descriptors.
    /// Also happens when the Kotlin object is closed (`use { }`, `close()`).
    pub fn shutdown(&self) {
        let node = self.node.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(node) = node {
            node.shutdown();
        }
    }
}

impl Drop for YggNode {
    fn drop(&mut self) {
        self.shutdown();
    }
}
