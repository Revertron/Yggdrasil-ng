//! C ABI for an embedded Yggdrasil node (see `include/ygg.h`).
//!
//! Every connection is handed to the application as an ordinary OS socket:
//! one end of a socket pair whose other end the library bridges to the
//! Yggdrasil network. Applications use their usual `read`/`write`/`poll`
//! (or asyncio, epoll, IOCP, ...) on it and never call into the library on
//! the data path. The implementation lives in `yggdrasil-embed`; this crate
//! only adapts it to C conventions.

#![allow(clippy::missing_safety_doc)]

mod error;

use std::ffi::{CStr, CString, c_char, c_void};
use std::net::SocketAddr;
use std::time::Duration;

use yggdrasil_embed::{EmbeddedNode, Host, StartOptions, Target};

pub use error::*;
pub use yggdrasil_embed::{CSocket, INVALID_SOCKET};

/// Opaque node handle (`ygg_node` in C).
pub type YggNode = EmbeddedNode;

pub const YGG_LOG_ERROR: i32 = yggdrasil_embed::LOG_ERROR;
pub const YGG_LOG_WARN: i32 = yggdrasil_embed::LOG_WARN;
pub const YGG_LOG_INFO: i32 = yggdrasil_embed::LOG_INFO;
pub const YGG_LOG_DEBUG: i32 = yggdrasil_embed::LOG_DEBUG;
pub const YGG_LOG_TRACE: i32 = yggdrasil_embed::LOG_TRACE;

/// `ygg_node_start` flag: also start the admin socket on `admin_listen`.
pub const YGG_START_ADMIN: u32 = 1;
/// Header in front of every datagram on a UDP socket: 16-byte IPv6 address
/// and 2-byte big-endian port of the remote side.
pub const YGG_UDP_HEADER_LEN: usize = yggdrasil_embed::UDP_HEADER_LEN;

pub type LogFn = extern "C" fn(userdata: *mut c_void, level: i32, message: *const c_char);

/// C callback plus its userdata, callable from any thread per the API contract.
#[derive(Clone, Copy)]
struct CLogger {
    f: LogFn,
    userdata: *mut c_void,
}

// SAFETY: the API requires the callback and userdata to be usable from any thread.
unsafe impl Send for CLogger {}
unsafe impl Sync for CLogger {}

impl CLogger {
    fn log(&self, level: i32, message: &str) {
        if let Ok(msg) = CString::new(message.replace('\0', " ")) {
            (self.f)(self.userdata, level, msg.as_ptr());
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
    guard(std::ptr::null_mut(), || Ok(into_c_string(EmbeddedNode::generate_config())))
}

/// Route the library's log output to `callback`. Can be set once per process.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_set_logger(callback: Option<LogFn>, userdata: *mut c_void, filter: *const c_char) -> i32 {
    guard_int(|| {
        let callback = callback.ok_or_else(|| Error::invalid("callback is NULL"))?;
        let filter = opt_str_arg(filter, "filter")?.unwrap_or("info");
        let logger = CLogger { f: callback, userdata };
        yggdrasil_embed::set_logger(move |level, message| logger.log(level, message), filter)?;
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
        let options = StartOptions { admin: flags & YGG_START_ADMIN != 0 };
        let node = EmbeddedNode::start_toml(opt_str_arg(config_toml, "config")?, options)?;
        Ok(Box::into_raw(Box::new(node)))
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
    guard_int(|| Ok(write_str(&node_arg(node)?.address().to_string(), buf, len)))
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_subnet(node: *const YggNode, buf: *mut c_char, len: usize) -> i32 {
    guard_int(|| {
        let subnet = node_arg(node)?.subnet()?;
        Ok(write_str(&subnet, buf, len))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_public_key(node: *const YggNode, buf: *mut c_char, len: usize) -> i32 {
    guard_int(|| {
        let key = hex::encode(node_arg(node)?.public_key()?);
        Ok(write_str(&key, buf, len))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_add_peer(node: *const YggNode, uri: *const c_char) -> i32 {
    guard_int(|| {
        node_arg(node)?.add_peer(str_arg(uri, "uri")?)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_remove_peer(node: *const YggNode, uri: *const c_char) -> i32 {
    guard_int(|| {
        node_arg(node)?.remove_peer(str_arg(uri, "uri")?)?;
        Ok(0)
    })
}

/// Run an admin API request, e.g. `{"request":"getPeers"}`. Returns the JSON
/// response (free with ygg_free_string), or NULL on error.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_node_admin(node: *const YggNode, request_json: *const c_char) -> *mut c_char {
    guard(std::ptr::null_mut(), || {
        let response = node_arg(node)?.admin(str_arg(request_json, "request")?)?;
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
        node_arg(node)?.tcp_connect(&target_arg(host, port)?, timeout_arg(timeout_ms))
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
        let host: Host = str_arg(host, "host")?.parse()?;
        let rtt = node_arg(node)?.ping(&host, timeout_arg(timeout_ms))?;
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
        let listen = socket_addr_arg(listen, "listen")?;
        let credentials = match (opt_str_arg(username, "username")?, opt_str_arg(password, "password")?) {
            (Some(u), Some(p)) => Some((u, p)),
            (None, None) => None,
            _ => return Err(Error::invalid("give both username and password, or neither")),
        };
        node_arg(node)?.socks5_start(listen, credentials)
    })
}

/// Forward TCP connections accepted on host address `listen` to `target`
/// ("[addr]:port" or "<key>.pk.ygg:port"). Returns a service id.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_local_tcp(node: *const YggNode, listen: *const c_char, target: *const c_char) -> i32 {
    guard_int(|| {
        let listen = socket_addr_arg(listen, "listen")?;
        let target: Target = str_arg(target, "target")?.parse()?;
        node_arg(node)?.forward_local_tcp(listen, target)
    })
}

/// Forward UDP datagrams received on host address `listen` to `target`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_local_udp(node: *const YggNode, listen: *const c_char, target: *const c_char) -> i32 {
    guard_int(|| {
        let listen = socket_addr_arg(listen, "listen")?;
        let target: Target = str_arg(target, "target")?.parse()?;
        node_arg(node)?.forward_local_udp(listen, target)
    })
}

/// Expose host TCP service `target` ("127.0.0.1:8080") on Yggdrasil `port`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_remote_tcp(node: *const YggNode, port: u16, target: *const c_char) -> i32 {
    guard_int(|| {
        let target = socket_addr_arg(target, "target")?;
        node_arg(node)?.forward_remote_tcp(port, target)
    })
}

/// Expose host UDP service `target` on Yggdrasil `port`.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_forward_remote_udp(node: *const YggNode, port: u16, target: *const c_char) -> i32 {
    guard_int(|| {
        let target = socket_addr_arg(target, "target")?;
        node_arg(node)?.forward_remote_udp(port, target)
    })
}

/// Stop a service started by ygg_socks5_start or ygg_forward_*.
#[unsafe(no_mangle)]
pub extern "C" fn ygg_service_stop(node: *const YggNode, id: i32) -> i32 {
    guard_int(|| {
        node_arg(node)?.service_stop(id)?;
        Ok(0)
    })
}
