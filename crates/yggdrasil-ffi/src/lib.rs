//! C ABI for an embedded Yggdrasil node (see `include/ygg.h`).
//!
//! Every connection is handed to the application as an ordinary OS socket:
//! one end of a socket pair whose other end the library bridges to the
//! Yggdrasil network. Applications use their usual `read`/`write`/`poll`
//! (or asyncio, epoll, IOCP, ...) on it and never call into the library on
//! the data path.

#![allow(clippy::missing_safety_doc)]

mod error;
mod logger;
mod sockpair;

use std::collections::{HashMap, VecDeque};
use std::ffi::{CStr, CString, c_char, c_void};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use yggdrasil::config::Config;
use yggdrasil::node::{Node, NodeBuilder};
use yggdrasil_stack::{Host, Target, TcpStream, UdpSocket, YggStack, proxy};

pub use error::*;
pub use logger::{LogFn, YGG_LOG_DEBUG, YGG_LOG_ERROR, YGG_LOG_INFO, YGG_LOG_TRACE, YGG_LOG_WARN};
pub use sockpair::{CSocket, INVALID_SOCKET};

/// `ygg_node_start` flag: also start the admin socket on `admin_listen`.
pub const YGG_START_ADMIN: u32 = 1;
/// Header in front of every datagram on a UDP socket: 16-byte IPv6 address
/// and 2-byte big-endian port of the remote side.
pub const YGG_UDP_HEADER_LEN: usize = 18;

const RUNTIME_WORKERS: usize = 2;
const UDP_BUFFER: usize = 65536 + YGG_UDP_HEADER_LEN;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Pending connections of a listener, shared with its accept task.
struct Listener {
    queue: Mutex<VecDeque<(TcpStream, SocketAddrV6)>>,
    ready: Condvar,
    closed: AtomicBool,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// An embedded node with its runtime and userspace stack. Opaque to C.
pub struct YggNode {
    runtime: Runtime,
    node: Mutex<Option<Node>>,
    stack: YggStack,
    listeners: Mutex<HashMap<CSocket, Arc<Listener>>>,
    udp: Mutex<HashMap<CSocket, JoinHandle<()>>>,
    services: Mutex<HashMap<i32, JoinHandle<()>>>,
    next_service: AtomicI32,
}

impl YggNode {
    fn start(config: Config, flags: u32) -> Result<Box<Self>> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(RUNTIME_WORKERS)
            .thread_name("ygg")
            .enable_all()
            .build()
            .map_err(Error::from)?;
        let admin = flags & YGG_START_ADMIN != 0;
        let node = runtime
            .block_on(
                NodeBuilder::new(config)
                    .embedded()
                    .admin(admin)
                    .admin_required(admin)
                    .start(),
            )
            .map_err(|e| Error::new(YGG_ERR_CONFIG, e.to_string()))?;
        let stack = {
            let _enter = runtime.enter();
            YggStack::new(&node)?
        };
        Ok(Box::new(Self {
            runtime,
            node: Mutex::new(Some(node)),
            stack,
            listeners: Mutex::default(),
            udp: Mutex::default(),
            services: Mutex::default(),
            next_service: AtomicI32::new(1),
        }))
    }

    fn with_node<R>(&self, f: impl FnOnce(&Node) -> R) -> Result<R> {
        let node = lock(&self.node);
        let node = node.as_ref().ok_or_else(|| Error::new(YGG_ERR_CLOSED, "node is stopped"))?;
        Ok(f(node))
    }

    /// Hand `stream` to the application as a socket.
    fn bridge_tcp(&self, stream: TcpStream) -> Result<CSocket> {
        let _enter = self.runtime.enter();
        let (app, mut lib) = sockpair::stream_pair()?;
        self.runtime.spawn(async move {
            let mut stream = stream;
            if let Err(e) = tokio::io::copy_bidirectional(&mut lib, &mut stream).await {
                tracing::debug!("ffi: tcp bridge ended: {}", e);
            }
        });
        Ok(app)
    }

    fn tcp_connect(&self, target: Target, timeout: Option<Duration>) -> Result<CSocket> {
        let stream = self.runtime.block_on(async {
            let connect = self.stack.tcp_connect_target(&target);
            match timeout {
                Some(t) => tokio::time::timeout(t, connect).await.unwrap_or_else(|_| {
                    Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"))
                }),
                None => connect.await,
            }
        })?;
        self.bridge_tcp(stream)
    }

    fn tcp_listen(&self, port: u16) -> Result<CSocket> {
        let listener = self.stack.tcp_listen(port)?;
        let _enter = self.runtime.enter();
        let (app, mut lib) = sockpair::stream_pair()?;
        let state = Arc::new(Listener {
            queue: Mutex::default(),
            ready: Condvar::new(),
            closed: AtomicBool::new(false),
            task: Mutex::new(None),
        });
        lock(&self.listeners).insert(app, state.clone());

        let task_state = state.clone();
        let task = self.runtime.spawn(async move {
            let state = task_state;
            let mut probe = [0u8; 64];
            loop {
                tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok(conn) => {
                            lock(&state.queue).push_back(conn);
                            state.ready.notify_all();
                            // One byte per queued connection makes the
                            // application's socket readable.
                            if lib.write_all(&[1]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    // EOF: the application closed its end.
                    r = lib.read(&mut probe) => if matches!(r, Ok(0) | Err(_)) {
                        break;
                    },
                }
            }
            state.closed.store(true, Ordering::Release);
            lock(&state.queue).clear();
            state.ready.notify_all();
        });
        *lock(&state.task) = Some(task);
        Ok(app)
    }

    fn listener(&self, sock: CSocket) -> Result<Arc<Listener>> {
        lock(&self.listeners)
            .get(&sock)
            .cloned()
            .ok_or_else(|| Error::new(YGG_ERR_NOT_FOUND, "not a listener socket"))
    }

    fn tcp_accept(&self, sock: CSocket, timeout: Option<Duration>) -> Result<(CSocket, SocketAddrV6)> {
        let listener = self.listener(sock)?;
        let deadline = timeout.map(|t| Instant::now() + t);
        let (stream, peer) = {
            let mut queue = lock(&listener.queue);
            loop {
                if let Some(conn) = queue.pop_front() {
                    break conn;
                }
                if listener.closed.load(Ordering::Acquire) {
                    return Err(Error::new(YGG_ERR_CLOSED, "listener closed"));
                }
                match deadline {
                    Some(d) => {
                        let now = Instant::now();
                        if now >= d {
                            // Readability may have been spurious; clear it.
                            sockpair::drain_byte(sock);
                            return Err(Error::new(YGG_ERR_WOULD_BLOCK, "no pending connection"));
                        }
                        queue = listener
                            .ready
                            .wait_timeout(queue, d - now)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                    }
                    None => queue = listener.ready.wait(queue).unwrap_or_else(|e| e.into_inner()),
                }
            }
        };
        sockpair::drain_byte(sock);
        Ok((self.bridge_tcp(stream)?, peer))
    }

    fn tcp_listener_close(&self, sock: CSocket) -> Result<()> {
        let listener = lock(&self.listeners)
            .remove(&sock)
            .ok_or_else(|| Error::new(YGG_ERR_NOT_FOUND, "not a listener socket"))?;
        if let Some(task) = lock(&listener.task).take() {
            task.abort();
        }
        listener.closed.store(true, Ordering::Release);
        lock(&listener.queue).clear();
        listener.ready.notify_all();
        sockpair::close(sock);
        Ok(())
    }

    fn udp_bind(&self, port: u16) -> Result<(CSocket, u16)> {
        let socket = self.stack.udp_bind(port)?;
        let bound = socket.local_addr().port();
        let _enter = self.runtime.enter();
        let (app, lib) = sockpair::dgram_pair()?;
        let task = self.runtime.spawn(bridge_udp(socket, lib));
        lock(&self.udp).insert(app, task);
        Ok((app, bound))
    }

    fn udp_close(&self, sock: CSocket) -> Result<()> {
        let task = lock(&self.udp)
            .remove(&sock)
            .ok_or_else(|| Error::new(YGG_ERR_NOT_FOUND, "not a UDP socket"))?;
        task.abort();
        sockpair::close(sock);
        Ok(())
    }

    fn spawn_service<F>(&self, what: String, service: F) -> i32
    where
        F: Future<Output = std::io::Result<()>> + Send + 'static,
    {
        let id = self.next_service.fetch_add(1, Ordering::Relaxed);
        let task = self.runtime.spawn(async move {
            if let Err(e) = service.await {
                tracing::warn!("{} stopped: {}", what, e);
            }
        });
        lock(&self.services).insert(id, task);
        id
    }

    fn stop(self: Box<Self>) {
        let this = *self;
        for (_, task) in lock(&this.services).drain() {
            task.abort();
        }
        for (_, listener) in lock(&this.listeners).drain() {
            if let Some(task) = lock(&listener.task).take() {
                task.abort();
            }
            listener.closed.store(true, Ordering::Release);
            listener.ready.notify_all();
        }
        for (_, task) in lock(&this.udp).drain() {
            task.abort();
        }
        let node = lock(&this.node).take();
        this.runtime.block_on(async {
            this.stack.close();
            if let Some(node) = node {
                node.close().await;
            }
        });
        drop(this.stack);
        this.runtime.shutdown_timeout(Duration::from_secs(2));
    }
}

/// Moves datagrams between a Yggdrasil UDP socket and the application's
/// datagram socket, adding/stripping the address header.
async fn bridge_udp(socket: UdpSocket, lib: sockpair::LibDgram) {
    let mut from_app = vec![0u8; UDP_BUFFER];
    let mut to_app = vec![0u8; UDP_BUFFER];
    loop {
        tokio::select! {
            r = lib.recv(&mut from_app) => match r {
                Ok(0) if sockpair::LibDgram::ZERO_IS_EOF => break,
                Ok(n) if n >= YGG_UDP_HEADER_LEN => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&from_app[..16]);
                    let port = u16::from_be_bytes([from_app[16], from_app[17]]);
                    let dst = SocketAddrV6::new(Ipv6Addr::from(addr), port, 0, 0);
                    if let Err(e) = socket.send_to(&from_app[YGG_UDP_HEADER_LEN..n], dst).await {
                        tracing::debug!("ffi: udp send to {}: {}", dst, e);
                    }
                }
                Ok(_) => tracing::debug!("ffi: dropping datagram without header"),
                Err(_) => break,
            },
            r = socket.recv_from(&mut to_app[YGG_UDP_HEADER_LEN..]) => match r {
                Ok((n, from)) => {
                    to_app[..16].copy_from_slice(&from.ip().octets());
                    to_app[16..18].copy_from_slice(&from.port().to_be_bytes());
                    if lib.send(&to_app[..YGG_UDP_HEADER_LEN + n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Argument helpers

fn str_arg<'a>(p: *const c_char, what: &str) -> Result<&'a str> {
    if p.is_null() {
        return Err(Error::invalid(format!("{what} is NULL")));
    }
    // SAFETY: the caller passes a NUL-terminated string that outlives the call.
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map_err(|_| Error::invalid(format!("{what} is not valid UTF-8")))
}

fn opt_str_arg<'a>(p: *const c_char, what: &str) -> Result<Option<&'a str>> {
    if p.is_null() { Ok(None) } else { str_arg(p, what).map(Some) }
}

fn node_arg<'a>(p: *const YggNode) -> Result<&'a YggNode> {
    // SAFETY: the caller passes a pointer from ygg_node_start that has not
    // been stopped.
    unsafe { p.as_ref() }.ok_or_else(|| Error::invalid("node is NULL"))
}

/// `< 0`: wait forever, `0`: do not wait, `> 0`: milliseconds.
fn wait_arg(timeout_ms: i32) -> Option<Duration> {
    (timeout_ms >= 0).then(|| Duration::from_millis(timeout_ms as u64))
}

/// `<= 0`: library default, `> 0`: milliseconds.
fn timeout_arg(timeout_ms: i32) -> Option<Duration> {
    (timeout_ms > 0).then(|| Duration::from_millis(timeout_ms as u64))
}

fn target_arg(host: *const c_char, port: u16) -> Result<Target> {
    let host: Host = str_arg(host, "host")?.parse()?;
    if port == 0 {
        return Err(Error::invalid("port is 0"));
    }
    Ok(Target { host, port })
}

fn socket_addr_arg(p: *const c_char, what: &str) -> Result<SocketAddr> {
    str_arg(p, what)?
        .parse()
        .map_err(|_| Error::invalid(format!("{what} is not an IP:port address")))
}

/// snprintf-style copy: writes as much as fits (NUL-terminated) and returns
/// the full length.
fn write_str(s: &str, buf: *mut c_char, len: usize) -> i32 {
    if !buf.is_null() && len > 0 {
        let n = s.len().min(len - 1);
        // SAFETY: the caller provides `len` writable bytes at `buf`.
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), buf.cast(), n);
            *buf.add(n) = 0;
        }
    }
    s.len() as i32
}

/// Store `value` through an optional out-pointer.
fn write_out<T>(p: *mut T, value: T) {
    if !p.is_null() {
        // SAFETY: the caller passes NULL or a valid, writable pointer.
        unsafe { p.write(value) };
    }
}

fn into_c_string(s: String) -> *mut c_char {
    CString::new(s.replace('\0', " ")).map(CString::into_raw).unwrap_or(std::ptr::null_mut())
}

/// Run an int-returning body: `>= 0` on success, `-code` on error.
fn guard_int(f: impl FnOnce() -> Result<i32>) -> i32 {
    let r = guard(i32::MIN, f);
    if r == i32::MIN { -ygg_last_error() } else { r }
}

// ---------------------------------------------------------------------------
// Library

/// Library version, e.g. "0.1.0".
#[unsafe(no_mangle)]
pub extern "C" fn ygg_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

/// Free a string returned by the library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: `s` came from CString::into_raw in this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// A new configuration (TOML) with a freshly generated private key.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_generate_config() -> *mut c_char {
    guard(std::ptr::null_mut(), || Ok(into_c_string(Config::generate_config_text())))
}

/// Route the library's log output to `callback`. Can be set once per process.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_set_logger(callback: Option<LogFn>, userdata: *mut c_void, filter: *const c_char) -> i32 {
    guard_int(|| {
        let callback = callback.ok_or_else(|| Error::invalid("callback is NULL"))?;
        logger::install(callback, userdata, filter)?;
        Ok(0)
    })
}

// ---------------------------------------------------------------------------
// Node

/// Start a node from a TOML configuration (NULL: defaults with an ephemeral
/// key). Returns NULL on error.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_start(config_toml: *const c_char, flags: u32) -> *mut YggNode {
    guard(std::ptr::null_mut(), || {
        let config = match opt_str_arg(config_toml, "config")? {
            Some(text) if !text.trim().is_empty() => toml::from_str::<Config>(text)
                .map_err(|e| Error::new(YGG_ERR_CONFIG, format!("invalid config: {e}")))?,
            _ => Config::default(),
        };
        Ok(Box::into_raw(YggNode::start(config, flags)?))
    })
}

/// Stop the node and free it. Sockets handed out by the node see EOF and must
/// still be closed by the application.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ygg_node_stop(node: *mut YggNode) {
    guard((), || {
        if !node.is_null() {
            // SAFETY: `node` came from ygg_node_start and is not used again.
            unsafe { Box::from_raw(node) }.stop();
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_address(node: *const YggNode, buf: *mut c_char, len: usize) -> i32 {
    guard_int(|| Ok(write_str(&node_arg(node)?.stack.address().to_string(), buf, len)))
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_subnet(node: *const YggNode, buf: *mut c_char, len: usize) -> i32 {
    guard_int(|| {
        let subnet = node_arg(node)?.with_node(|n| n.subnet().to_string())?;
        Ok(write_str(&subnet, buf, len))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_public_key(node: *const YggNode, buf: *mut c_char, len: usize) -> i32 {
    guard_int(|| {
        let key = node_arg(node)?.with_node(|n| hex::encode(n.public_key()))?;
        Ok(write_str(&key, buf, len))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_add_peer(node: *const YggNode, uri: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let uri = str_arg(uri, "uri")?;
        let core = node.with_node(|n| n.core().clone())?;
        node.runtime.block_on(core.add_peer(uri)).map_err(Error::invalid)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_remove_peer(node: *const YggNode, uri: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let uri = str_arg(uri, "uri")?;
        let core = node.with_node(|n| n.core().clone())?;
        node.runtime.block_on(core.remove_peer(uri)).map_err(|e| Error::new(YGG_ERR_NOT_FOUND, e))?;
        Ok(0)
    })
}

/// Run an admin API request, e.g. `{"request":"getPeers"}`. Returns the JSON
/// response (free with ygg_free_string), or NULL on error.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_admin(node: *const YggNode, request_json: *const c_char) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        let node = node_arg(node)?;
        let request = str_arg(request_json, "request")?;
        let core = node.with_node(|n| n.core().clone())?;
        let response = node.runtime.block_on(yggdrasil::admin::handle_json(&core, request));
        Ok(into_c_string(response))
    })
}

// ---------------------------------------------------------------------------
// TCP

/// Connect to `host` (IPv6 address, hex public key or `<key>.pk.ygg`) and
/// `port`. Blocks until connected. Returns a connected stream socket.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_tcp_connect(node: *const YggNode, host: *const c_char, port: u16, timeout_ms: i32) -> CSocket {
    guard(INVALID_SOCKET, || {
        let node = node_arg(node)?;
        node.tcp_connect(target_arg(host, port)?, timeout_arg(timeout_ms))
    })
}

/// Listen on `port`. The returned socket becomes readable when a connection
/// can be accepted with ygg_tcp_accept; close it with ygg_tcp_listener_close.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_tcp_listen(node: *const YggNode, port: u16) -> CSocket {
    guard(INVALID_SOCKET, || node_arg(node)?.tcp_listen(port))
}

/// Accept a connection. `timeout_ms`: < 0 wait forever, 0 do not wait
/// (YGG_ERR_WOULD_BLOCK when none is pending). Writes "[addr]:port" of the
/// peer to `peer_buf` if not NULL.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_tcp_accept(
    node: *const YggNode,
    listener: CSocket,
    peer_buf: *mut c_char,
    peer_len: usize,
    timeout_ms: i32,
) -> CSocket {
    guard(INVALID_SOCKET, || {
        let (sock, peer) = node_arg(node)?.tcp_accept(listener, wait_arg(timeout_ms))?;
        write_str(&peer.to_string(), peer_buf, peer_len);
        Ok(sock)
    })
}

/// Stop listening and close the listener socket.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_tcp_listener_close(node: *const YggNode, listener: CSocket) -> i32 {
    guard_int(|| node_arg(node)?.tcp_listener_close(listener).map(|_| 0))
}

// ---------------------------------------------------------------------------
// UDP

/// Bind a UDP port (0 picks one; the result is stored in `bound_port` if not
/// NULL). Returns a datagram socket; each datagram carries a
/// YGG_UDP_HEADER_LEN header with the remote address and port.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_udp_bind(node: *const YggNode, port: u16, bound_port: *mut u16) -> CSocket {
    guard(INVALID_SOCKET, || {
        let (sock, bound) = node_arg(node)?.udp_bind(port)?;
        write_out(bound_port, bound);
        Ok(sock)
    })
}

/// Unbind and close a socket from ygg_udp_bind.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_udp_close(node: *const YggNode, sock: CSocket) -> i32 {
    guard_int(|| node_arg(node)?.udp_close(sock).map(|_| 0))
}

// ---------------------------------------------------------------------------
// ICMPv6

/// Ping `host`; returns the round-trip time in microseconds, or `-code`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_ping(node: *const YggNode, host: *const c_char, timeout_ms: i32) -> i64 {
    let r = guard(i64::MIN, || {
        let node = node_arg(node)?;
        let host: Host = str_arg(host, "host")?.parse()?;
        let timeout = timeout_arg(timeout_ms).unwrap_or(Duration::from_secs(5));
        let rtt = node.runtime.block_on(async {
            let addr = node.stack.resolve(&host).await;
            node.stack.ping(addr, timeout).await
        })?;
        Ok(rtt.as_micros().min(i64::MAX as u128) as i64)
    });
    if r == i64::MIN { -(ygg_last_error() as i64) } else { r }
}

// ---------------------------------------------------------------------------
// Proxy services

/// Start a SOCKS5 server on `listen` ("127.0.0.1:1080"). `username` and
/// `password` may be NULL for no authentication. Returns a service id.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_socks5_start(
    node: *const YggNode,
    listen: *const c_char,
    username: *const c_char,
    password: *const c_char,
) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let listen = socket_addr_arg(listen, "listen")?;
        let mut server = proxy::Socks5Server::new(node.stack.clone());
        match (opt_str_arg(username, "username")?, opt_str_arg(password, "password")?) {
            (Some(u), Some(p)) => server = server.with_credentials(u, p),
            (None, None) => {}
            _ => return Err(Error::invalid("give both username and password, or neither")),
        }
        let listener = node.runtime.block_on(tokio::net::TcpListener::bind(listen))?;
        Ok(node.spawn_service(format!("SOCKS5 on {listen}"), server.serve(listener)))
    })
}

/// Forward TCP connections accepted on host address `listen` to `target`
/// ("[addr]:port" or "<key>.pk.ygg:port"). Returns a service id.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_local_tcp(node: *const YggNode, listen: *const c_char, target: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let listen = socket_addr_arg(listen, "listen")?;
        let target: Target = str_arg(target, "target")?.parse()?;
        let listener = node.runtime.block_on(tokio::net::TcpListener::bind(listen))?;
        let what = format!("TCP forward {listen} -> {target}");
        Ok(node.spawn_service(what, proxy::forward_local_tcp(node.stack.clone(), listener, target)))
    })
}

/// Forward UDP datagrams received on host address `listen` to `target`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_local_udp(node: *const YggNode, listen: *const c_char, target: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let listen = socket_addr_arg(listen, "listen")?;
        let target: Target = str_arg(target, "target")?.parse()?;
        let socket = node.runtime.block_on(tokio::net::UdpSocket::bind(listen))?;
        let what = format!("UDP forward {listen} -> {target}");
        Ok(node.spawn_service(what, proxy::forward_local_udp(node.stack.clone(), socket, target)))
    })
}

/// Expose host TCP service `target` ("127.0.0.1:8080") on Yggdrasil `port`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_remote_tcp(node: *const YggNode, port: u16, target: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let target = socket_addr_arg(target, "target")?;
        let listener = node.stack.tcp_listen(port)?;
        let what = format!("TCP forward :{port} -> {target}");
        Ok(node.spawn_service(what, proxy::serve_remote_tcp(listener, target)))
    })
}

/// Expose host UDP service `target` on Yggdrasil `port`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_remote_udp(node: *const YggNode, port: u16, target: *const c_char) -> i32 {
    guard_int(|| {
        let node = node_arg(node)?;
        let target = socket_addr_arg(target, "target")?;
        let socket = node.stack.udp_bind(port)?;
        let what = format!("UDP forward :{port} -> {target}");
        Ok(node.spawn_service(what, proxy::serve_remote_udp(socket, target)))
    })
}

/// Stop a service started by ygg_socks5_start or ygg_forward_*.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_service_stop(node: *const YggNode, id: i32) -> i32 {
    guard_int(|| {
        let task = lock(&node_arg(node)?.services)
            .remove(&id)
            .ok_or_else(|| Error::new(YGG_ERR_NOT_FOUND, "no such service"))?;
        task.abort();
        Ok(0)
    })
}
