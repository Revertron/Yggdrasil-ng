//! An embedded Yggdrasil node that hands out every connection as an ordinary
//! OS socket: one end of a socket pair whose other end is bridged to the
//! Yggdrasil network by the node's own runtime.
//!
//! This is the shared core of the C (`yggdrasil-ffi`), Python (`yggdrasil-py`)
//! and Kotlin (`yggdrasil-uniffi`) bindings. All methods are synchronous and
//! may be called from any thread except the node's own runtime threads (for
//! example from inside a log callback).
//!
//! Socket kinds (see [`sockpair`]): stream sockets for TCP; datagram sockets
//! for UDP, each datagram prefixed with a [`UDP_HEADER_LEN`]-byte header
//! (16-byte IPv6 address, 2-byte big-endian port of the remote side);
//! listener handles that become readable when [`EmbeddedNode::tcp_accept`]
//! has a connection.

mod error;
mod logger;
pub mod sockpair;

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use yggdrasil::config::Config;
use yggdrasil::node::{Node, NodeBuilder};
use yggdrasil_stack::{TcpStream, UdpSocket, YggStack, proxy};

pub use error::*;
pub use logger::{LOG_DEBUG, LOG_ERROR, LOG_INFO, LOG_TRACE, LOG_WARN, set_logger};
pub use sockpair::{CSocket, INVALID_SOCKET};
pub use yggdrasil::multicast::NetworkInterface;
pub use yggdrasil_stack::{Host, Target};

/// Header in front of every datagram on a UDP socket.
pub const UDP_HEADER_LEN: usize = 18;

const RUNTIME_WORKERS: usize = 2;
const UDP_BUFFER: usize = 65536 + UDP_HEADER_LEN;
const DEFAULT_PING_TIMEOUT: Duration = Duration::from_secs(5);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Options for [`EmbeddedNode::start`].
#[derive(Clone, Debug, Default)]
pub struct StartOptions {
    /// Also start the admin socket on the config's `admin_listen`.
    pub admin: bool,
    /// Interfaces for multicast discovery supplied by the app (Android's
    /// ConnectivityManager, where `getifaddrs()` is restricted). Must be
    /// given here for multicast to follow them; update them later with
    /// [`EmbeddedNode::set_network_interfaces`].
    pub network_interfaces: Option<Vec<NetworkInterface>>,
}

/// A connect started with [`EmbeddedNode::tcp_connect_start`].
#[derive(Default)]
struct PendingConnect {
    /// The outcome once known, unless the connect was cancelled.
    result: Mutex<PendingState>,
    task: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
enum PendingState {
    #[default]
    Running,
    Done(Result<CSocket>),
    Cancelled,
}

/// Aborts a task when the future awaiting it is dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn connect_stream(stack: YggStack, target: Target, timeout: Option<Duration>) -> std::io::Result<TcpStream> {
    let connect = stack.tcp_connect_target(&target);
    match timeout {
        Some(t) => tokio::time::timeout(t, connect).await.unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "connection timed out"))
        }),
        None => connect.await,
    }
}

/// Hand `stream` to the application as a socket. Must run inside the node's
/// runtime.
fn bridge_in_runtime(stream: TcpStream) -> Result<CSocket> {
    let (app, mut lib) = sockpair::stream_pair()?;
    tokio::spawn(async move {
        let mut stream = stream;
        if let Err(e) = tokio::io::copy_bidirectional(&mut lib, &mut stream).await {
            tracing::debug!("embed: tcp bridge ended: {}", e);
        }
    });
    Ok(app)
}

/// Pending connections of a listener, shared with its accept task.
struct Listener {
    queue: Mutex<VecDeque<(TcpStream, SocketAddrV6)>>,
    ready: Condvar,
    closed: AtomicBool,
    task: Mutex<Option<JoinHandle<()>>>,
}

/// An embedded node with its own runtime and userspace TCP/IP stack.
pub struct EmbeddedNode {
    runtime: Runtime,
    node: Mutex<Option<Node>>,
    stack: YggStack,
    listeners: Mutex<HashMap<CSocket, Arc<Listener>>>,
    udp: Mutex<HashMap<CSocket, JoinHandle<()>>>,
    pending: Mutex<HashMap<CSocket, Arc<PendingConnect>>>,
    services: Mutex<HashMap<i32, JoinHandle<()>>>,
    next_service: AtomicI32,
}

impl EmbeddedNode {
    /// Start a node. TUN settings in `config` are ignored.
    pub fn start(config: Config, options: StartOptions) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(RUNTIME_WORKERS)
            .thread_name("ygg")
            .enable_all()
            .build()
            .map_err(Error::from)?;
        let mut builder = NodeBuilder::new(config)
            .embedded()
            .admin(options.admin)
            .admin_required(options.admin);
        if let Some(interfaces) = options.network_interfaces {
            builder = builder.network_interfaces(interfaces);
        }
        let node = runtime
            .block_on(builder.start())
            .map_err(|e| Error::new(ERR_CONFIG, e.to_string()))?;
        let stack = {
            let _enter = runtime.enter();
            YggStack::new(&node)?
        };
        Ok(Self {
            runtime,
            node: Mutex::new(Some(node)),
            stack,
            listeners: Mutex::default(),
            udp: Mutex::default(),
            pending: Mutex::default(),
            services: Mutex::default(),
            next_service: AtomicI32::new(1),
        })
    }

    /// Start a node from TOML configuration text; `None` or blank text starts
    /// with defaults and an ephemeral key.
    pub fn start_toml(config_toml: Option<&str>, options: StartOptions) -> Result<Self> {
        let config = match config_toml {
            Some(text) if !text.trim().is_empty() => toml::from_str::<Config>(text)
                .map_err(|e| Error::new(ERR_CONFIG, format!("invalid config: {e}")))?,
            _ => Config::default(),
        };
        Self::start(config, options)
    }

    /// A new TOML configuration with a fresh private key.
    pub fn generate_config() -> String {
        Config::generate_config_text()
    }

    fn with_node<R>(&self, f: impl FnOnce(&Node) -> R) -> Result<R> {
        let node = lock(&self.node);
        let node = node.as_ref().ok_or_else(|| Error::new(ERR_CLOSED, "node is stopped"))?;
        Ok(f(node))
    }

    // ---- identity and control

    pub fn address(&self) -> Ipv6Addr {
        self.stack.address()
    }

    /// The node's /64, e.g. "300:1234:5678:9abc::/64".
    pub fn subnet(&self) -> Result<String> {
        self.with_node(|n| n.subnet().to_string())
    }

    pub fn public_key(&self) -> Result<[u8; 32]> {
        self.with_node(|n| *n.public_key())
    }

    pub fn add_peer(&self, uri: &str) -> Result<()> {
        let core = self.with_node(|n| n.core().clone())?;
        self.runtime.block_on(core.add_peer(uri)).map_err(Error::invalid)
    }

    /// Tell the node the network changed (interface up/down, Wi-Fi <->
    /// mobile, resume from Doze): peers that are down are redialled now
    /// instead of after their backoff, and the node re-announces itself.
    pub fn network_changed(&self) -> Result<()> {
        let core = self.with_node(|n| n.core().clone())?;
        self.runtime.block_on(core.retry_peers_now());
        core.force_router_refresh();
        Ok(())
    }

    /// Replace the externally supplied interfaces used by multicast discovery
    /// (see [`StartOptions::network_interfaces`]).
    pub fn set_network_interfaces(&self, interfaces: Vec<NetworkInterface>) -> Result<()> {
        self.with_node(|n| n.core().update_network_interfaces(interfaces))
    }

    pub fn remove_peer(&self, uri: &str) -> Result<()> {
        let core = self.with_node(|n| n.core().clone())?;
        self.runtime
            .block_on(core.remove_peer(uri))
            .map_err(|e| Error::new(ERR_NOT_FOUND, e))
    }

    /// Run an admin API request (JSON, e.g. `{"request":"getPeers"}`) and
    /// return the JSON response.
    pub fn admin(&self, request_json: &str) -> Result<String> {
        let core = self.with_node(|n| n.core().clone())?;
        Ok(self.runtime.block_on(yggdrasil::admin::handle_json(&core, request_json)))
    }

    /// Address of `host`; for a public key this also registers the key so the
    /// first packet does not wait for a lookup.
    pub fn resolve(&self, host: &Host) -> Result<Ipv6Addr> {
        if self.is_stopped() {
            return Err(Error::new(ERR_CLOSED, "node is stopped"));
        }
        Ok(self.runtime.block_on(self.stack.resolve(host)))
    }

    /// Echo request; returns the round-trip time. `None` uses 5 s.
    pub fn ping(&self, host: &Host, timeout: Option<Duration>) -> Result<Duration> {
        let timeout = timeout.unwrap_or(DEFAULT_PING_TIMEOUT);
        Ok(self.runtime.block_on(async {
            let addr = self.stack.resolve(host).await;
            self.stack.ping(addr, timeout).await
        })?)
    }

    // ---- TCP

    /// Hand `stream` to the application as a socket.
    fn bridge_tcp(&self, stream: TcpStream) -> Result<CSocket> {
        let _enter = self.runtime.enter();
        bridge_in_runtime(stream)
    }

    /// Connect and return a connected stream socket. `None` uses the stack's
    /// connect timeout (30 s).
    pub fn tcp_connect(&self, target: &Target, timeout: Option<Duration>) -> Result<CSocket> {
        let stream = self
            .runtime
            .block_on(connect_stream(self.stack.clone(), *target, timeout))?;
        self.bridge_tcp(stream)
    }

    /// Connect without blocking a thread. The future can be awaited on any
    /// executor (the work runs on the node's runtime). Dropping it cancels
    /// the connect; a connection that completes after that is closed.
    pub fn tcp_connect_async(
        &self,
        target: Target,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<CSocket>> + Send + 'static {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let stack = self.stack.clone();
        let task = self.runtime.spawn(async move {
            let result = match connect_stream(stack, target, timeout).await {
                Ok(stream) => bridge_in_runtime(stream),
                Err(e) => Err(e.into()),
            };
            // Nobody is waiting any more: do not leak the connection.
            if let Err(Ok(fd)) = tx.send(result) {
                sockpair::close(fd);
            }
        });
        let guard = AbortOnDrop(task.abort_handle());
        async move {
            let _guard = guard;
            rx.await
                .unwrap_or_else(|_| Err(Error::new(ERR_CLOSED, "node is stopped")))
        }
    }

    /// Start a connect for event loops that wait on descriptors. Returns a
    /// handle that becomes readable when the outcome is known; then call
    /// [`tcp_connect_finish`](Self::tcp_connect_finish). The handle must not
    /// be read or written.
    pub fn tcp_connect_start(&self, target: Target, timeout: Option<Duration>) -> Result<CSocket> {
        if self.is_stopped() {
            return Err(Error::new(ERR_CLOSED, "node is stopped"));
        }
        let _enter = self.runtime.enter();
        let (handle, mut lib) = sockpair::stream_pair()?;
        let state = Arc::new(PendingConnect::default());
        lock(&self.pending).insert(handle, state.clone());
        let stack = self.stack.clone();
        let task_state = state.clone();
        let task = self.runtime.spawn(async move {
            let result = match connect_stream(stack, target, timeout).await {
                Ok(stream) => bridge_in_runtime(stream),
                Err(e) => Err(e.into()),
            };
            {
                let mut slot = lock(&task_state.result);
                match *slot {
                    PendingState::Cancelled => {
                        if let Ok(fd) = result {
                            sockpair::close(fd);
                        }
                        return;
                    }
                    _ => *slot = PendingState::Done(result),
                }
            }
            // Makes the application's handle readable.
            let _ = lib.write_all(&[1]).await;
            // Keep our end open so the handle does not also report EOF.
            let mut probe = [0u8; 1];
            let _ = lib.read(&mut probe).await;
        });
        *lock(&state.task) = Some(task);
        Ok(handle)
    }

    /// Collect the outcome of [`tcp_connect_start`](Self::tcp_connect_start):
    /// `ERR_WOULD_BLOCK` while the connect is running; afterwards the
    /// connected stream socket or the connect error. Once the outcome is
    /// returned the pending handle is closed.
    pub fn tcp_connect_finish(&self, pending: CSocket) -> Result<CSocket> {
        let state = lock(&self.pending)
            .get(&pending)
            .cloned()
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "not a pending connect"))?;
        let outcome = {
            let mut slot = lock(&state.result);
            match std::mem::take(&mut *slot) {
                PendingState::Done(result) => result,
                other => {
                    *slot = other;
                    return Err(Error::new(ERR_WOULD_BLOCK, "connect in progress"));
                }
            }
        };
        lock(&self.pending).remove(&pending);
        if let Some(task) = lock(&state.task).take() {
            task.abort();
        }
        sockpair::close(pending);
        outcome
    }

    /// Abandon a connect from [`tcp_connect_start`](Self::tcp_connect_start)
    /// and close its pending handle.
    pub fn tcp_connect_cancel(&self, pending: CSocket) -> Result<()> {
        let state = lock(&self.pending)
            .remove(&pending)
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "not a pending connect"))?;
        Self::cancel_pending(&state);
        sockpair::close(pending);
        Ok(())
    }

    fn cancel_pending(state: &PendingConnect) {
        if let Some(task) = lock(&state.task).take() {
            task.abort();
        }
        let previous = std::mem::replace(&mut *lock(&state.result), PendingState::Cancelled);
        if let PendingState::Done(Ok(fd)) = previous {
            sockpair::close(fd);
        }
    }

    /// Listen on `port`. The returned handle becomes readable when a
    /// connection is pending; it must not be read or written, and is closed
    /// with [`tcp_listener_close`](Self::tcp_listener_close).
    pub fn tcp_listen(&self, port: u16) -> Result<CSocket> {
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
                            // application's handle readable.
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
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "not a listener socket"))
    }

    /// Accept a connection. `timeout`: `None` waits forever, zero does not
    /// wait (`ERR_WOULD_BLOCK` when nothing is pending).
    pub fn tcp_accept(&self, listener: CSocket, timeout: Option<Duration>) -> Result<(CSocket, SocketAddrV6)> {
        let state = self.listener(listener)?;
        let deadline = timeout.map(|t| Instant::now() + t);
        let (stream, peer) = {
            let mut queue = lock(&state.queue);
            loop {
                if let Some(conn) = queue.pop_front() {
                    break conn;
                }
                if state.closed.load(Ordering::Acquire) {
                    return Err(Error::new(ERR_CLOSED, "listener closed"));
                }
                match deadline {
                    Some(d) => {
                        let now = Instant::now();
                        if now >= d {
                            // Readability may have been spurious; clear it.
                            sockpair::drain_byte(listener);
                            return Err(Error::new(ERR_WOULD_BLOCK, "no pending connection"));
                        }
                        queue = state
                            .ready
                            .wait_timeout(queue, d - now)
                            .unwrap_or_else(|e| e.into_inner())
                            .0;
                    }
                    None => queue = state.ready.wait(queue).unwrap_or_else(|e| e.into_inner()),
                }
            }
        };
        sockpair::drain_byte(listener);
        Ok((self.bridge_tcp(stream)?, peer))
    }

    /// Stop listening and close the listener handle.
    pub fn tcp_listener_close(&self, listener: CSocket) -> Result<()> {
        let state = lock(&self.listeners)
            .remove(&listener)
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "not a listener socket"))?;
        if let Some(task) = lock(&state.task).take() {
            task.abort();
        }
        state.closed.store(true, Ordering::Release);
        lock(&state.queue).clear();
        state.ready.notify_all();
        sockpair::close(listener);
        Ok(())
    }

    // ---- UDP

    /// Bind a UDP port (0 picks one). Returns the datagram socket and the
    /// bound port.
    pub fn udp_bind(&self, port: u16) -> Result<(CSocket, u16)> {
        let socket = self.stack.udp_bind(port)?;
        let bound = socket.local_addr().port();
        let _enter = self.runtime.enter();
        let (app, lib) = sockpair::dgram_pair()?;
        let task = self.runtime.spawn(bridge_udp(socket, lib));
        lock(&self.udp).insert(app, task);
        Ok((app, bound))
    }

    /// Unbind and close a socket from [`udp_bind`](Self::udp_bind).
    pub fn udp_close(&self, sock: CSocket) -> Result<()> {
        let task = lock(&self.udp)
            .remove(&sock)
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "not a UDP socket"))?;
        task.abort();
        sockpair::close(sock);
        Ok(())
    }

    // ---- proxy services

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

    /// SOCKS5 server on host address `listen`; `credentials` = (user, pass).
    /// Returns a service id.
    pub fn socks5_start(&self, listen: SocketAddr, credentials: Option<(&str, &str)>) -> Result<i32> {
        let mut server = proxy::Socks5Server::new(self.stack.clone());
        if let Some((user, pass)) = credentials {
            server = server.with_credentials(user, pass);
        }
        let listener = self.runtime.block_on(tokio::net::TcpListener::bind(listen))?;
        Ok(self.spawn_service(format!("SOCKS5 on {listen}"), server.serve(listener)))
    }

    /// Host TCP listener on `listen` -> Yggdrasil `target`.
    pub fn forward_local_tcp(&self, listen: SocketAddr, target: Target) -> Result<i32> {
        let listener = self.runtime.block_on(tokio::net::TcpListener::bind(listen))?;
        let what = format!("TCP forward {listen} -> {target}");
        Ok(self.spawn_service(what, proxy::forward_local_tcp(self.stack.clone(), listener, target)))
    }

    /// Host UDP socket on `listen` -> Yggdrasil `target`.
    pub fn forward_local_udp(&self, listen: SocketAddr, target: Target) -> Result<i32> {
        let socket = self.runtime.block_on(tokio::net::UdpSocket::bind(listen))?;
        let what = format!("UDP forward {listen} -> {target}");
        Ok(self.spawn_service(what, proxy::forward_local_udp(self.stack.clone(), socket, target)))
    }

    /// Yggdrasil TCP `port` -> host service `target`.
    pub fn forward_remote_tcp(&self, port: u16, target: SocketAddr) -> Result<i32> {
        let listener = self.stack.tcp_listen(port)?;
        let what = format!("TCP forward :{port} -> {target}");
        Ok(self.spawn_service(what, proxy::serve_remote_tcp(listener, target)))
    }

    /// Yggdrasil UDP `port` -> host service `target`.
    pub fn forward_remote_udp(&self, port: u16, target: SocketAddr) -> Result<i32> {
        let socket = self.stack.udp_bind(port)?;
        let what = format!("UDP forward :{port} -> {target}");
        Ok(self.spawn_service(what, proxy::serve_remote_udp(socket, target)))
    }

    /// Stop a service started by `socks5_start` or `forward_*`.
    pub fn service_stop(&self, id: i32) -> Result<()> {
        let task = lock(&self.services)
            .remove(&id)
            .ok_or_else(|| Error::new(ERR_NOT_FOUND, "no such service"))?;
        task.abort();
        Ok(())
    }

    // ---- shutdown

    /// Shut the node down without consuming it: services stop, pending and
    /// future accepts fail, connections see EOF and later calls return
    /// `ERR_CLOSED`. Idempotent; safe to call while other threads are blocked
    /// in this node. The runtime threads exit when the node is dropped.
    pub fn shutdown(&self) {
        for (_, task) in lock(&self.services).drain() {
            task.abort();
        }
        for (_, listener) in lock(&self.listeners).drain() {
            if let Some(task) = lock(&listener.task).take() {
                task.abort();
            }
            listener.closed.store(true, Ordering::Release);
            listener.ready.notify_all();
        }
        for (_, task) in lock(&self.udp).drain() {
            task.abort();
        }
        // Pending handles belong to the application; connections that were
        // never collected are ours to close.
        for (_, state) in lock(&self.pending).drain() {
            Self::cancel_pending(&state);
        }
        let node = lock(&self.node).take();
        if let Some(node) = node {
            self.runtime.block_on(async {
                self.stack.close();
                node.close().await;
            });
        }
    }

    /// Whether [`shutdown`](Self::shutdown) or [`stop`](Self::stop) has run.
    pub fn is_stopped(&self) -> bool {
        lock(&self.node).is_none()
    }

    /// Stop the node and its runtime. Sockets it handed out see EOF; the
    /// application still closes its own sockets (listener and UDP handles
    /// included).
    pub fn stop(self) {
        self.shutdown();
        let Self { runtime, stack, .. } = self;
        drop(stack);
        runtime.shutdown_timeout(Duration::from_secs(2));
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
                Ok(n) if n >= UDP_HEADER_LEN => {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&from_app[..16]);
                    let port = u16::from_be_bytes([from_app[16], from_app[17]]);
                    let dst = SocketAddrV6::new(Ipv6Addr::from(addr), port, 0, 0);
                    if let Err(e) = socket.send_to(&from_app[UDP_HEADER_LEN..n], dst).await {
                        tracing::debug!("embed: udp send to {}: {}", dst, e);
                    }
                }
                Ok(_) => tracing::debug!("embed: dropping datagram without header"),
                Err(_) => break,
            },
            r = socket.recv_from(&mut to_app[UDP_HEADER_LEN..]) => match r {
                Ok((n, from)) => {
                    to_app[..16].copy_from_slice(&from.ip().octets());
                    to_app[16..18].copy_from_slice(&from.port().to_be_bytes());
                    if lib.send(&to_app[..UDP_HEADER_LEN + n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }
}
