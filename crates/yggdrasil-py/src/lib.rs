//! Native part of the `ygg` Python package (`ygg._native`).
//!
//! A thin layer over `yggdrasil-embed`: methods return socket descriptors as
//! integers, which the pure-Python layer (`python/ygg/__init__.py`) wraps in
//! `socket.socket` objects. Every call that touches the node releases the
//! GIL, so blocking calls do not stall other Python threads and log callbacks
//! (which need the GIL) cannot deadlock against them.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::exceptions::{
    PyBlockingIOError, PyConnectionError, PyConnectionRefusedError, PyOSError, PyRuntimeError,
    PyTimeoutError, PyValueError,
};
use pyo3::prelude::*;
use yggdrasil_embed as embed;
use yggdrasil_embed::{EmbeddedNode, Host, StartOptions, Target};

fn to_py(e: embed::Error) -> PyErr {
    let msg = e.message;
    match e.code {
        embed::ERR_INVALID_ARGUMENT | embed::ERR_CONFIG => PyValueError::new_err(msg),
        embed::ERR_CONNECTION_REFUSED => PyConnectionRefusedError::new_err(msg),
        embed::ERR_TIMED_OUT => PyTimeoutError::new_err(msg),
        embed::ERR_WOULD_BLOCK => PyBlockingIOError::new_err(msg),
        embed::ERR_CLOSED => PyConnectionError::new_err(msg),
        embed::ERR_ADDR_IN_USE => PyOSError::new_err((errno("EADDRINUSE"), msg)),
        embed::ERR_NOT_FOUND => PyOSError::new_err((errno("ENOENT"), msg)),
        _ => PyOSError::new_err(msg),
    }
}

/// The platform's value for an errno name, from Python's `errno` module.
fn errno(name: &str) -> i32 {
    Python::attach(|py| {
        py.import("errno")
            .and_then(|m| m.getattr(name))
            .and_then(|v| v.extract::<i32>())
            .unwrap_or(0)
    })
}

fn parse<T: std::str::FromStr<Err = std::io::Error>>(s: &str) -> PyResult<T> {
    s.parse::<T>().map_err(|e| PyValueError::new_err(e.to_string()))
}

fn socket_addr(s: &str) -> PyResult<SocketAddr> {
    s.parse()
        .map_err(|_| PyValueError::new_err(format!("{s:?} is not an IP:port address")))
}

/// (name, index, [IPv6 address, ...]) as passed from Python.
type Interface = (String, u32, Vec<String>);

fn interfaces(list: Vec<Interface>) -> PyResult<Vec<embed::NetworkInterface>> {
    list.into_iter()
        .map(|(name, index, addrs)| {
            let addrs = addrs
                .iter()
                .map(|a| a.parse().map_err(|_| PyValueError::new_err(format!("{a:?} is not an IPv6 address"))))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(embed::NetworkInterface { name, index, addrs })
        })
        .collect()
}

/// Seconds (float) to a duration; `None` stays `None`, negatives are rejected.
fn duration(seconds: Option<f64>) -> PyResult<Option<Duration>> {
    match seconds {
        None => Ok(None),
        Some(s) if s.is_finite() && s >= 0.0 => Ok(Some(Duration::from_secs_f64(s))),
        Some(_) => Err(PyValueError::new_err("timeout must be a non-negative number or None")),
    }
}

/// Socket handles cross into Python as plain integers (fd / SOCKET).
fn sock(s: embed::CSocket) -> i64 {
    s as i64
}

fn csock(s: i64) -> embed::CSocket {
    s as embed::CSocket
}

/// Handle to a running node. Use `ygg.Node` instead of this class directly.
#[pyclass(frozen, module = "ygg._native")]
struct NativeNode {
    node: Mutex<Option<Arc<EmbeddedNode>>>,
}

impl NativeNode {
    fn get(&self) -> PyResult<Arc<EmbeddedNode>> {
        self.node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| PyConnectionError::new_err("node is closed"))
    }

    /// Run `f` on the node with the GIL released.
    fn call<R: Send>(
        &self,
        py: Python<'_>,
        f: impl FnOnce(&EmbeddedNode) -> embed::Result<R> + Send,
    ) -> PyResult<R> {
        let node = self.get()?;
        py.detach(move || f(&node)).map_err(to_py)
    }
}

#[pymethods]
impl NativeNode {
    #[new]
    #[pyo3(signature = (config_toml=None, admin=false, network_interfaces=None))]
    fn new(
        py: Python<'_>,
        config_toml: Option<String>,
        admin: bool,
        network_interfaces: Option<Vec<Interface>>,
    ) -> PyResult<Self> {
        let network_interfaces = network_interfaces.map(interfaces).transpose()?;
        let options = StartOptions { admin, network_interfaces };
        let node = py
            .detach(move || EmbeddedNode::start_toml(config_toml.as_deref(), options))
            .map_err(to_py)?;
        Ok(Self { node: Mutex::new(Some(Arc::new(node))) })
    }

    /// Redial peers that are down now and re-announce the node.
    fn network_changed(&self, py: Python<'_>) -> PyResult<()> {
        self.call(py, |n| n.network_changed())
    }

    /// Interfaces for multicast discovery: [(name, index, [ipv6, ...]), ...].
    fn set_network_interfaces(&self, py: Python<'_>, network_interfaces: Vec<Interface>) -> PyResult<()> {
        let list = interfaces(network_interfaces)?;
        self.call(py, move |n| n.set_network_interfaces(list))
    }

    /// Start a non-blocking connect; returns a handle that turns readable
    /// when tcp_connect_finish has the outcome.
    #[pyo3(signature = (host, port, timeout=None))]
    fn tcp_connect_start(&self, py: Python<'_>, host: &str, port: u16, timeout: Option<f64>) -> PyResult<i64> {
        if port == 0 {
            return Err(PyValueError::new_err("port is 0"));
        }
        let target = Target { host: parse(host)?, port };
        let timeout = duration(timeout)?;
        self.call(py, move |n| n.tcp_connect_start(target, timeout).map(sock))
    }

    /// Socket handle of the finished connect; BlockingIOError while running.
    fn tcp_connect_finish(&self, py: Python<'_>, pending: i64) -> PyResult<i64> {
        self.call(py, move |n| n.tcp_connect_finish(csock(pending)).map(sock))
    }

    fn tcp_connect_cancel(&self, py: Python<'_>, pending: i64) -> PyResult<()> {
        self.call(py, move |n| n.tcp_connect_cancel(csock(pending)))
    }

    fn address(&self, py: Python<'_>) -> PyResult<String> {
        self.call(py, |n| Ok(n.address().to_string()))
    }

    fn subnet(&self, py: Python<'_>) -> PyResult<String> {
        self.call(py, |n| n.subnet())
    }

    fn public_key(&self, py: Python<'_>) -> PyResult<String> {
        self.call(py, |n| n.public_key().map(hex::encode))
    }

    fn add_peer(&self, py: Python<'_>, uri: String) -> PyResult<()> {
        self.call(py, move |n| n.add_peer(&uri))
    }

    fn remove_peer(&self, py: Python<'_>, uri: String) -> PyResult<()> {
        self.call(py, move |n| n.remove_peer(&uri))
    }

    /// Admin API request as JSON text; returns the JSON response text.
    fn admin(&self, py: Python<'_>, request_json: String) -> PyResult<String> {
        self.call(py, move |n| n.admin(&request_json))
    }

    /// Address for `host` (address, hex key or `<key>.pk.ygg`).
    fn resolve(&self, py: Python<'_>, host: &str) -> PyResult<String> {
        let host: Host = parse(host)?;
        self.call(py, move |n| n.resolve(&host).map(|a| a.to_string()))
    }

    /// Round-trip time in seconds.
    #[pyo3(signature = (host, timeout=None))]
    fn ping(&self, py: Python<'_>, host: &str, timeout: Option<f64>) -> PyResult<f64> {
        let host: Host = parse(host)?;
        let timeout = duration(timeout)?;
        self.call(py, move |n| n.ping(&host, timeout).map(|d| d.as_secs_f64()))
    }

    #[pyo3(signature = (host, port, timeout=None))]
    fn tcp_connect(&self, py: Python<'_>, host: &str, port: u16, timeout: Option<f64>) -> PyResult<i64> {
        let target = Target { host: parse(host)?, port };
        if port == 0 {
            return Err(PyValueError::new_err("port is 0"));
        }
        let timeout = duration(timeout)?;
        self.call(py, move |n| n.tcp_connect(&target, timeout).map(sock))
    }

    fn tcp_listen(&self, py: Python<'_>, port: u16) -> PyResult<i64> {
        self.call(py, move |n| n.tcp_listen(port).map(sock))
    }

    /// Returns (socket handle, "[addr]:port"). `timeout`: None waits forever,
    /// 0 raises BlockingIOError when nothing is pending.
    #[pyo3(signature = (listener, timeout=None))]
    fn tcp_accept(&self, py: Python<'_>, listener: i64, timeout: Option<f64>) -> PyResult<(i64, String)> {
        let timeout = duration(timeout)?;
        self.call(py, move |n| {
            n.tcp_accept(csock(listener), timeout)
                .map(|(s, peer)| (sock(s), peer.to_string()))
        })
    }

    fn tcp_listener_close(&self, py: Python<'_>, listener: i64) -> PyResult<()> {
        self.call(py, move |n| n.tcp_listener_close(csock(listener)))
    }

    /// Returns (socket handle, bound port).
    #[pyo3(signature = (port=0))]
    fn udp_bind(&self, py: Python<'_>, port: u16) -> PyResult<(i64, u16)> {
        self.call(py, move |n| n.udp_bind(port).map(|(s, p)| (sock(s), p)))
    }

    fn udp_close(&self, py: Python<'_>, sock: i64) -> PyResult<()> {
        self.call(py, move |n| n.udp_close(csock(sock)))
    }

    #[pyo3(signature = (listen, username=None, password=None))]
    fn socks5_start(
        &self,
        py: Python<'_>,
        listen: &str,
        username: Option<String>,
        password: Option<String>,
    ) -> PyResult<i32> {
        let listen = socket_addr(listen)?;
        let creds = match (username, password) {
            (Some(u), Some(p)) => Some((u, p)),
            (None, None) => None,
            _ => return Err(PyValueError::new_err("give both username and password, or neither")),
        };
        self.call(py, move |n| {
            n.socks5_start(listen, creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())))
        })
    }

    fn forward_local_tcp(&self, py: Python<'_>, listen: &str, target: &str) -> PyResult<i32> {
        let (listen, target): (SocketAddr, Target) = (socket_addr(listen)?, parse(target)?);
        self.call(py, move |n| n.forward_local_tcp(listen, target))
    }

    fn forward_local_udp(&self, py: Python<'_>, listen: &str, target: &str) -> PyResult<i32> {
        let (listen, target): (SocketAddr, Target) = (socket_addr(listen)?, parse(target)?);
        self.call(py, move |n| n.forward_local_udp(listen, target))
    }

    fn forward_remote_tcp(&self, py: Python<'_>, port: u16, target: &str) -> PyResult<i32> {
        let target = socket_addr(target)?;
        self.call(py, move |n| n.forward_remote_tcp(port, target))
    }

    fn forward_remote_udp(&self, py: Python<'_>, port: u16, target: &str) -> PyResult<i32> {
        let target = socket_addr(target)?;
        self.call(py, move |n| n.forward_remote_udp(port, target))
    }

    fn service_stop(&self, py: Python<'_>, id: i32) -> PyResult<()> {
        self.call(py, move |n| n.service_stop(id))
    }

    fn closed(&self) -> bool {
        self.node.lock().unwrap_or_else(|e| e.into_inner()).is_none()
    }

    /// Stop the node. Idempotent; wakes threads blocked in accept.
    fn close(&self, py: Python<'_>) {
        let node = self.node.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(node) = node {
            // Dropping the last reference (possibly after in-flight calls
            // return) also stops the runtime threads.
            py.detach(move || node.shutdown());
        }
    }
}

/// A new TOML configuration with a fresh private key.
#[pyfunction]
fn generate_config() -> String {
    EmbeddedNode::generate_config()
}

/// Send library logs to `callback(level: int, message: str)`; levels are
/// 1=error .. 5=trace. Can be installed once per process.
#[pyfunction]
#[pyo3(signature = (callback, filter="info"))]
fn set_logger(callback: Py<PyAny>, filter: &str) -> PyResult<()> {
    embed::set_logger(
        move |level, message| {
            // Skipped while the interpreter is shutting down.
            let _ = Python::try_attach(|py| {
                if let Err(e) = callback.call1(py, (level, message)) {
                    e.write_unraisable(py, None);
                }
            });
        },
        filter,
    )
    .map_err(|e| PyRuntimeError::new_err(e.message))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NativeNode>()?;
    m.add_function(wrap_pyfunction!(generate_config, m)?)?;
    m.add_function(wrap_pyfunction!(set_logger, m)?)?;
    m.add("UDP_HEADER_LEN", embed::UDP_HEADER_LEN)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
