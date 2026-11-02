//! Stack state, the driver task and the public [`YggStack`] handle.

use std::io;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rand::Rng;
use rustc_hash::{FxHashMap, FxHashSet};
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp, Socket};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;
use yggdrasil::address::addr_for_key;
use yggdrasil::ipv6rwc::ReadWriteCloser;
use yggdrasil::node::Node;

use crate::device::QueueDevice;
use crate::host::{Host, Target};
use crate::tcp::{new_listen_socket, TcpListener, TcpStream};
use crate::udp::UdpSocket;

/// Yggdrasil addresses (0x02..) and subnets (0x03..) share the 200::/7 prefix.
const YGGDRASIL_PREFIX_LEN: u8 = 7;
/// Ephemeral port range for outbound TCP connections and unbound UDP sockets.
const EPHEMERAL_PORTS: std::ops::RangeInclusive<u16> = 49152..=65535;
/// Packets queued between the node and the driver, per direction.
const PACKET_QUEUE: usize = 1024;
/// Most inbound packets handed to smoltcp in one poll, so egress keeps up.
const RX_BATCH: usize = 256;
/// Driver sleep when smoltcp has no timer pending.
const IDLE_POLL: Duration = Duration::from_secs(60);
/// How long a dropped TCP stream may keep closing gracefully before it is reset.
const ORPHAN_LINGER: Duration = Duration::from_secs(30);
/// How long a dropped UDP socket may keep flushing queued datagrams.
const UDP_LINGER: Duration = Duration::from_secs(1);
/// Upper bound on the driver sleep while orphans are pending.
const ORPHAN_CHECK: Duration = Duration::from_secs(1);
/// Read buffer for packets coming from the node: max overlay MTU plus the
/// session type byte `Core::read_from` reads in place.
const READ_BUFFER: usize = 65536 + 64;

/// Tuning knobs for a [`YggStack`].
#[derive(Clone, Debug)]
pub struct StackConfig {
    /// Interface MTU. `None` uses the node's overlay MTU (at most 65535).
    pub mtu: Option<usize>,
    /// Per-connection TCP receive buffer in bytes. Also bounds the advertised
    /// window, so it caps throughput at roughly `buffer / RTT`.
    pub tcp_rx_buffer: usize,
    /// Per-connection TCP send buffer in bytes.
    pub tcp_tx_buffer: usize,
    /// Connections per listening port that may be handshaking or waiting for
    /// `accept`. Further SYNs are dropped (the client retransmits).
    pub tcp_backlog: usize,
    /// How long `tcp_connect` waits for the handshake.
    pub connect_timeout: Duration,
    /// Per-socket UDP receive buffer in bytes.
    pub udp_rx_buffer: usize,
    /// Per-socket UDP send buffer in bytes.
    pub udp_tx_buffer: usize,
    /// Datagrams queued per UDP socket and direction.
    pub udp_queue: usize,
}

impl Default for StackConfig {
    /// Buffers are zero-filled allocations, so memory is only committed as
    /// data actually flows through them.
    fn default() -> Self {
        Self {
            mtu: None,
            tcp_rx_buffer: 1024 * 1024,
            tcp_tx_buffer: 1024 * 1024,
            tcp_backlog: 128,
            connect_timeout: Duration::from_secs(30),
            udp_rx_buffer: 256 * 1024,
            udp_tx_buffer: 256 * 1024,
            udp_queue: 128,
        }
    }
}

#[derive(Clone, Copy)]
enum OrphanKind {
    Tcp,
    Udp,
}

/// A socket whose user handle was dropped but which still has work to do
/// (TCP close handshake, queued UDP datagrams).
struct Orphan {
    handle: SocketHandle,
    kind: OrphanKind,
    deadline: std::time::Instant,
}

pub(crate) struct State {
    pub(crate) iface: Interface,
    pub(crate) device: QueueDevice,
    pub(crate) sockets: SocketSet<'static>,
    /// Listening port -> backlog of listening sockets.
    pub(crate) listeners: FxHashMap<u16, Vec<SocketHandle>>,
    pub(crate) icmp_idents: FxHashSet<u16>,
    orphans: Vec<Orphan>,
    /// Set once the driver has stopped; every socket operation then fails.
    pub(crate) closed: bool,
}

impl State {
    pub(crate) fn check_open(&self) -> io::Result<()> {
        if self.closed {
            Err(io::Error::new(io::ErrorKind::NotConnected, "yggdrasil stack is closed"))
        } else {
            Ok(())
        }
    }

    fn tcp_port_used(&self, port: u16) -> bool {
        self.listeners.contains_key(&port)
            || self.sockets.iter().any(|(_, s)| match s {
                Socket::Tcp(t) => t.local_endpoint().is_some_and(|e| e.port == port),
                _ => false,
            })
    }

    pub(crate) fn udp_port_used(&self, port: u16) -> bool {
        self.sockets.iter().any(|(_, s)| match s {
            Socket::Udp(u) => u.endpoint().port == port,
            _ => false,
        })
    }

    pub(crate) fn alloc_tcp_port(&self) -> io::Result<u16> {
        alloc_port(|p| self.tcp_port_used(p))
    }

    pub(crate) fn alloc_udp_port(&self) -> io::Result<u16> {
        alloc_port(|p| self.udp_port_used(p))
    }

    /// Hand a TCP socket over to the driver: close it gracefully and remove
    /// it once closed, or reset it after [`ORPHAN_LINGER`].
    pub(crate) fn orphan_tcp(&mut self, handle: SocketHandle) {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.close();
        socket.set_timeout(Some(ORPHAN_LINGER.into()));
        self.orphans.push(Orphan {
            handle,
            kind: OrphanKind::Tcp,
            deadline: std::time::Instant::now() + ORPHAN_LINGER,
        });
    }

    /// Hand a UDP socket over to the driver so queued datagrams still go out.
    pub(crate) fn orphan_udp(&mut self, handle: SocketHandle) {
        self.orphans.push(Orphan {
            handle,
            kind: OrphanKind::Udp,
            deadline: std::time::Instant::now() + UDP_LINGER,
        });
    }

    /// Make sure a listening socket is free for a SYN to `port`. Returns
    /// false when the listener's backlog is full and the SYN must be dropped.
    ///
    /// Listening sockets are created on demand, one per incoming SYN, up to
    /// `tcp_backlog` pending connections. smoltcp would answer a SYN that finds
    /// no listening socket with RST; dropping it instead lets the client
    /// retransmit once `accept` has made room, as kernel stacks do.
    fn make_room_for_syn(&mut self, port: u16, config: &StackConfig) -> bool {
        let Some(backlog) = self.listeners.get_mut(&port) else {
            return true;
        };
        let sockets = &mut self.sockets;
        if backlog
            .iter()
            .any(|&h| sockets.get::<tcp::Socket>(h).state() == tcp::State::Listen)
        {
            return true;
        }
        if backlog.len() >= config.tcp_backlog.max(1) {
            tracing::trace!("stack: backlog full on port {}, dropping SYN", port);
            return false;
        }
        match new_listen_socket(config, port) {
            Ok(socket) => {
                backlog.push(sockets.add(socket));
                true
            }
            Err(_) => false,
        }
    }

    fn reap_orphans(&mut self) {
        let now = std::time::Instant::now();
        let sockets = &mut self.sockets;
        self.orphans.retain(|orphan| match orphan.kind {
            OrphanKind::Tcp => {
                let socket = sockets.get_mut::<tcp::Socket>(orphan.handle);
                match socket.state() {
                    tcp::State::Closed | tcp::State::TimeWait => {
                        sockets.remove(orphan.handle);
                        false
                    }
                    _ => {
                        if now >= orphan.deadline {
                            // The RST goes out on the next poll; the socket is
                            // then Closed and removed on the following reap.
                            socket.abort();
                        }
                        true
                    }
                }
            }
            OrphanKind::Udp => {
                let socket = sockets.get_mut::<udp::Socket>(orphan.handle);
                if socket.send_queue() == 0 || now >= orphan.deadline {
                    sockets.remove(orphan.handle);
                    false
                } else {
                    true
                }
            }
        });
    }
}

/// Destination port of a TCP connection request (SYN without ACK). Only the
/// fixed IPv6 header directly followed by TCP is recognised; anything else is
/// left to smoltcp.
fn syn_port(packet: &[u8]) -> Option<u16> {
    const TCP: u8 = 6;
    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    if packet.len() < 40 + 20 || packet[6] != TCP || packet[40 + 13] & (SYN | ACK) != SYN {
        return None;
    }
    Some(u16::from_be_bytes([packet[42], packet[43]]))
}

fn alloc_port(used: impl Fn(u16) -> bool) -> io::Result<u16> {
    let mut rng = rand::thread_rng();
    for _ in 0..128 {
        let port = rng.gen_range(EPHEMERAL_PORTS);
        if !used(port) {
            return Ok(port);
        }
    }
    EPHEMERAL_PORTS
        .clone()
        .find(|&p| !used(p))
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrInUse, "no free ephemeral port"))
}

/// State shared between user handles and the driver task.
pub(crate) struct Shared {
    state: Mutex<State>,
    /// Wakes the driver after a user operation changed socket state.
    notify: Notify,
    pub(crate) address: Ipv6Addr,
    pub(crate) mtu: usize,
    pub(crate) config: StackConfig,
}

impl Shared {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ask the driver to poll the interface soon.
    pub(crate) fn poke(&self) {
        self.notify.notify_one();
    }

    /// Run the interface once. Returns the packets to send and how long the
    /// driver may sleep before the next poll.
    fn poll(&self) -> (Vec<Vec<u8>>, Duration) {
        let mut guard = self.lock();
        let st = &mut *guard;
        let now = SmolInstant::now();
        // Same sequence as `Interface::poll`, but ingress goes one packet at a
        // time so SYNs can be checked against the backlog as it fills up.
        st.iface.poll_maintenance(now);
        while let Some(packet) = st.device.rx.front() {
            if let Some(port) = syn_port(packet)
                && !st.make_room_for_syn(port, &self.config)
            {
                st.device.rx.pop_front();
                continue;
            }
            st.iface.poll_ingress_single(now, &mut st.device, &mut st.sockets);
        }
        while st.iface.poll_egress(now, &mut st.device, &mut st.sockets) == PollResult::SocketStateChanged {}
        st.reap_orphans();

        let mut delay = st
            .iface
            .poll_delay(now, &st.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(IDLE_POLL);
        if !st.orphans.is_empty() {
            delay = delay.min(ORPHAN_CHECK);
        }
        if !st.device.rx.is_empty() {
            delay = Duration::ZERO;
        }
        (std::mem::take(&mut st.device.tx), delay)
    }

    /// Mark the stack closed and fail every socket so waiters wake up.
    fn shutdown(&self) {
        let mut st = self.lock();
        st.closed = true;
        for (_, socket) in st.sockets.iter_mut() {
            match socket {
                Socket::Tcp(t) => t.abort(),
                Socket::Udp(u) => u.close(),
                _ => {}
            }
        }
    }
}

/// Owner of the background tasks; dropping the last reference stops them.
pub(crate) struct Inner {
    pub(crate) shared: Arc<Shared>,
    rwc: Arc<ReadWriteCloser>,
    cancel: CancellationToken,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// A userspace TCP/UDP/ICMPv6 stack on top of an embedded Yggdrasil node.
///
/// The stack owns the node's packet read side ([`Node::rwc`]), so the node
/// must run without a TUN adapter (see `NodeBuilder::embedded`). Handles are
/// cheap to clone; the stack keeps running while any handle, stream, listener
/// or socket is alive, or until [`close`](Self::close) is called.
#[derive(Clone)]
pub struct YggStack {
    pub(crate) inner: Arc<Inner>,
}

impl YggStack {
    /// Start a stack with the default [`StackConfig`] on `node`.
    pub fn new(node: &Node) -> io::Result<Self> {
        Self::with_config(node, StackConfig::default())
    }

    /// Start a stack on `node`.
    pub fn with_config(node: &Node, config: StackConfig) -> io::Result<Self> {
        if node.has_tun() {
            return Err(io::Error::other(
                "node has a running TUN adapter; start it without TUN (NodeBuilder::embedded)",
            ));
        }
        Self::from_rwc(node.rwc().clone(), Ipv6Addr::from(node.address().0), config)
    }

    /// Start a stack directly on a packet interface. `address` must be the
    /// node's own address. Must be called within a tokio runtime.
    pub fn from_rwc(
        rwc: Arc<ReadWriteCloser>,
        address: Ipv6Addr,
        config: StackConfig,
    ) -> io::Result<Self> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| io::Error::other("YggStack must be created within a tokio runtime"))?;

        let mtu = config
            .mtu
            .unwrap_or(rwc.mtu() as usize)
            .clamp(1280, 65535);
        let mut device = QueueDevice::new(mtu);

        let mut iface_config = Config::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(address), YGGDRASIL_PREFIX_LEN))
                .expect("interface has room for one address");
        });

        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                iface,
                device,
                sockets: SocketSet::new(Vec::new()),
                listeners: FxHashMap::default(),
                icmp_idents: FxHashSet::default(),
                orphans: Vec::new(),
                closed: false,
            }),
            notify: Notify::new(),
            address,
            mtu,
            config,
        });

        let cancel = CancellationToken::new();
        let (inbound_tx, inbound_rx) = mpsc::channel(PACKET_QUEUE);
        let (outbound_tx, outbound_rx) = mpsc::channel(PACKET_QUEUE);
        runtime.spawn(read_packets(rwc.clone(), inbound_tx, cancel.clone()));
        runtime.spawn(write_packets(rwc.clone(), outbound_rx, cancel.clone()));
        runtime.spawn(drive(shared.clone(), inbound_rx, outbound_tx, cancel.clone()));

        Ok(Self {
            inner: Arc::new(Inner { shared, rwc, cancel }),
        })
    }

    /// The node's Yggdrasil address, used as the source of all traffic.
    pub fn address(&self) -> Ipv6Addr {
        self.inner.shared.address
    }

    /// Interface MTU in bytes.
    pub fn mtu(&self) -> usize {
        self.inner.shared.mtu
    }

    /// Open a TCP connection to `addr`.
    pub async fn tcp_connect(&self, addr: SocketAddrV6) -> io::Result<TcpStream> {
        TcpStream::connect(self.inner.clone(), addr).await
    }

    /// Open a TCP connection to the node with public key `key`.
    ///
    /// The key is registered with the node first, so the first packet does not
    /// wait for an address-to-key lookup.
    pub async fn tcp_connect_key(&self, key: &[u8; 32], port: u16) -> io::Result<TcpStream> {
        let addr = self.prepare_key(key).await;
        self.tcp_connect(SocketAddrV6::new(addr, port, 0, 0)).await
    }

    /// Listen for TCP connections on `port` of the node's address.
    pub fn tcp_listen(&self, port: u16) -> io::Result<TcpListener> {
        TcpListener::bind(self.inner.clone(), port)
    }

    /// Bind a UDP socket to `port` (0 picks an ephemeral port).
    pub fn udp_bind(&self, port: u16) -> io::Result<UdpSocket> {
        UdpSocket::bind(self.inner.clone(), port)
    }

    /// Send an ICMPv6 echo request to `addr` and return the round-trip time.
    pub async fn ping(&self, addr: Ipv6Addr, timeout: Duration) -> io::Result<Duration> {
        crate::icmp::ping(&self.inner, addr, timeout).await
    }

    /// Ping the node with public key `key`. See [`ping`](Self::ping).
    pub async fn ping_key(&self, key: &[u8; 32], timeout: Duration) -> io::Result<Duration> {
        let addr = self.prepare_key(key).await;
        self.ping(addr, timeout).await
    }

    /// Stop the stack. Open sockets fail with `NotConnected`; the node itself
    /// keeps running.
    pub fn close(&self) {
        self.inner.cancel.cancel();
    }

    /// Address of `host`. For a key, the key is also registered with the
    /// node so the first packet does not wait for an address-to-key lookup.
    pub async fn resolve(&self, host: &Host) -> Ipv6Addr {
        match host {
            Host::Addr(a) => *a,
            Host::Key(k) => self.prepare_key(k).await,
        }
    }

    /// Open a TCP connection to `target` (address or public key).
    pub async fn tcp_connect_target(&self, target: &Target) -> io::Result<TcpStream> {
        let addr = self.resolve(&target.host).await;
        self.tcp_connect(SocketAddrV6::new(addr, target.port, 0, 0)).await
    }

    async fn prepare_key(&self, key: &[u8; 32]) -> Ipv6Addr {
        self.inner.rwc.update_key(*key).await;
        Ipv6Addr::from(addr_for_key(key).0)
    }
}

/// Reject destinations outside the Yggdrasil range; smoltcp has no route there.
pub(crate) fn check_remote(addr: &Ipv6Addr) -> io::Result<()> {
    match addr.octets()[0] {
        0x02 | 0x03 => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{addr} is not a Yggdrasil address (200::/7)"),
        )),
    }
}

#[allow(unreachable_patterns)]
pub(crate) fn to_std(endpoint: IpEndpoint) -> SocketAddrV6 {
    match endpoint.addr {
        IpAddress::Ipv6(a) => SocketAddrV6::new(a, endpoint.port, 0, 0),
        _ => SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, endpoint.port, 0, 0),
    }
}

pub(crate) fn to_smol(addr: SocketAddrV6) -> IpEndpoint {
    IpEndpoint::new(IpAddress::Ipv6(*addr.ip()), addr.port())
}

/// Node -> driver: read IPv6 packets addressed to us.
async fn read_packets(
    rwc: Arc<ReadWriteCloser>,
    inbound: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; READ_BUFFER];
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => break,
            r = rwc.read(&mut buf) => match r {
                Ok(p) => p.to_vec(),
                Err(e) => {
                    tracing::debug!("stack: node read ended: {}", e);
                    break;
                }
            },
        };
        if inbound.send(packet).await.is_err() {
            break;
        }
    }
}

/// Driver -> node: send IPv6 packets produced by smoltcp.
async fn write_packets(
    rwc: Arc<ReadWriteCloser>,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) {
    loop {
        let packet = tokio::select! {
            _ = cancel.cancelled() => break,
            p = outbound.recv() => match p {
                Some(p) => p,
                None => break,
            },
        };
        if let Err(e) = rwc.write(&packet).await {
            tracing::trace!("stack: node write failed: {}", e);
        }
    }
}

/// Polls smoltcp whenever packets arrive, a user operation pokes it, or a
/// protocol timer is due.
async fn drive(
    shared: Arc<Shared>,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<Vec<u8>>,
    cancel: CancellationToken,
) {
    'run: loop {
        {
            let mut st = shared.lock();
            while st.device.rx.len() < RX_BATCH {
                match inbound.try_recv() {
                    Ok(packet) => st.device.rx.push_back(packet),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break 'run,
                }
            }
        }

        let (packets, delay) = shared.poll();
        for packet in packets {
            if outbound.send(packet).await.is_err() {
                break 'run;
            }
        }

        if delay.is_zero() {
            tokio::task::yield_now().await;
            continue;
        }

        tokio::select! {
            _ = cancel.cancelled() => break,
            packet = inbound.recv() => match packet {
                Some(packet) => shared.lock().device.rx.push_back(packet),
                None => break,
            },
            _ = shared.notify.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
    shared.shutdown();
    cancel.cancel();
}
