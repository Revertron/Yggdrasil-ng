//! Port forwarding between host sockets and the Yggdrasil network.
//!
//! Each function runs until its listening socket fails; spawn it and abort
//! the task to stop forwarding. Per-connection errors are logged and do not
//! stop the forwarder.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::UDP_SESSION_TIMEOUT;
use crate::host::Target;
use crate::{UdpSocket as YggUdpSocket, YggStack};

const UDP_BUFFER: usize = 65536;

/// Forward TCP connections accepted on a host `listener` to `target` on the
/// Yggdrasil network.
pub async fn forward_local_tcp(
    stack: YggStack,
    listener: tokio::net::TcpListener,
    target: Target,
) -> io::Result<()> {
    loop {
        let (mut client, from) = listener.accept().await?;
        let stack = stack.clone();
        tokio::spawn(async move {
            let _ = client.set_nodelay(true);
            let result = async {
                let mut remote = stack.tcp_connect_target(&target).await?;
                tokio::io::copy_bidirectional(&mut client, &mut remote).await
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("forward {} -> {}: {}", from, target, e);
            }
        });
    }
}

/// Accept TCP connections on Yggdrasil `port` and forward them to `target`
/// on the host network (exposes a local service on the node's address).
pub async fn forward_remote_tcp(stack: YggStack, port: u16, target: SocketAddr) -> io::Result<()> {
    let listener = stack.tcp_listen(port)?;
    loop {
        let (mut remote, from) = listener.accept().await?;
        tokio::spawn(async move {
            let result = async {
                let mut local = tokio::net::TcpStream::connect(target).await?;
                let _ = local.set_nodelay(true);
                tokio::io::copy_bidirectional(&mut remote, &mut local).await
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("forward {} -> {}: {}", from, target, e);
            }
        });
    }
}

/// Last-activity clock shared by both directions of a UDP session.
struct Activity {
    base: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self { base: Instant::now(), last_ms: AtomicU64::new(0) }
    }

    fn touch(&self) {
        self.last_ms.store(self.base.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Time left before the session counts as idle, or `None` if it already is.
    fn remaining(&self) -> Option<std::time::Duration> {
        let last = std::time::Duration::from_millis(self.last_ms.load(Ordering::Relaxed));
        (last + UDP_SESSION_TIMEOUT).checked_sub(self.base.elapsed())
    }
}

struct Session<S> {
    socket: Arc<S>,
    activity: Arc<Activity>,
}

type Sessions<K, S> = Arc<Mutex<HashMap<K, Session<S>>>>;

/// Forward UDP datagrams received on a host `socket` to `target` on the
/// Yggdrasil network. Each host client gets its own Yggdrasil source port, and
/// replies are sent back to that client.
pub async fn forward_local_udp(
    stack: YggStack,
    socket: tokio::net::UdpSocket,
    target: Target,
) -> io::Result<()> {
    let local = Arc::new(socket);
    let remote = SocketAddrV6::new(stack.resolve(&target.host).await, target.port, 0, 0);
    let sessions: Sessions<SocketAddr, YggUdpSocket> = Arc::default();
    let mut buf = vec![0u8; UDP_BUFFER];
    loop {
        let (n, client) = local.recv_from(&mut buf).await?;
        let (ygg, activity) = match session(&sessions, client, || {
            let ygg = Arc::new(stack.udp_bind(0)?);
            let activity = Arc::new(Activity::new());
            tokio::spawn(local_udp_replies(
                ygg.clone(),
                local.clone(),
                client,
                remote,
                activity.clone(),
                sessions.clone(),
            ));
            Ok((ygg, activity))
        }) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("forward udp {} -> {}: {}", client, target, e);
                continue;
            }
        };
        activity.touch();
        if let Err(e) = ygg.send_to(&buf[..n], remote).await {
            tracing::debug!("forward udp {} -> {}: {}", client, target, e);
        }
    }
}

/// Yggdrasil -> host direction of a [`forward_local_udp`] session.
async fn local_udp_replies(
    ygg: Arc<YggUdpSocket>,
    local: Arc<tokio::net::UdpSocket>,
    client: SocketAddr,
    remote: SocketAddrV6,
    activity: Arc<Activity>,
    sessions: Sessions<SocketAddr, YggUdpSocket>,
) {
    let mut buf = vec![0u8; UDP_BUFFER];
    while let Some(idle_in) = activity.remaining() {
        tokio::select! {
            r = ygg.recv_from(&mut buf) => match r {
                Ok((n, from)) if from == remote => {
                    activity.touch();
                    let _ = local.send_to(&buf[..n], client).await;
                }
                Ok(_) => {}
                Err(_) => break,
            },
            _ = tokio::time::sleep(idle_in) => {}
        }
    }
    sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&client);
}

/// Receive UDP datagrams on Yggdrasil `port` and forward them to `target` on
/// the host network. Each Yggdrasil peer gets its own host socket, and replies
/// from `target` are sent back to that peer.
pub async fn forward_remote_udp(stack: YggStack, port: u16, target: SocketAddr) -> io::Result<()> {
    let ygg = Arc::new(stack.udp_bind(port)?);
    let sessions: Sessions<SocketAddrV6, tokio::net::UdpSocket> = Arc::default();
    let bind_addr: SocketAddr = if target.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut buf = vec![0u8; UDP_BUFFER];
    loop {
        let (n, peer) = ygg.recv_from(&mut buf).await?;
        let (local, activity) = match session(&sessions, peer, || {
            let std_socket = std::net::UdpSocket::bind(bind_addr)?;
            std_socket.connect(target)?;
            std_socket.set_nonblocking(true)?;
            let local = Arc::new(tokio::net::UdpSocket::from_std(std_socket)?);
            let activity = Arc::new(Activity::new());
            tokio::spawn(remote_udp_replies(
                local.clone(),
                ygg.clone(),
                peer,
                activity.clone(),
                sessions.clone(),
            ));
            Ok((local, activity))
        }) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("forward udp {} -> {}: {}", peer, target, e);
                continue;
            }
        };
        activity.touch();
        if let Err(e) = local.send(&buf[..n]).await {
            tracing::debug!("forward udp {} -> {}: {}", peer, target, e);
        }
    }
}

/// Host -> Yggdrasil direction of a [`forward_remote_udp`] session.
async fn remote_udp_replies(
    local: Arc<tokio::net::UdpSocket>,
    ygg: Arc<YggUdpSocket>,
    peer: SocketAddrV6,
    activity: Arc<Activity>,
    sessions: Sessions<SocketAddrV6, tokio::net::UdpSocket>,
) {
    let mut buf = vec![0u8; UDP_BUFFER];
    while let Some(idle_in) = activity.remaining() {
        tokio::select! {
            r = local.recv(&mut buf) => match r {
                Ok(n) => {
                    activity.touch();
                    let _ = ygg.send_to(&buf[..n], peer).await;
                }
                // ICMP port unreachable from the target surfaces here; the
                // session stays up in case the service comes back.
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(_) => break,
            },
            _ = tokio::time::sleep(idle_in) => {}
        }
    }
    sessions.lock().unwrap_or_else(|e| e.into_inner()).remove(&peer);
}

/// Look up the session for `key`, creating it with `create` if needed.
fn session<K: Eq + Hash, S>(
    sessions: &Sessions<K, S>,
    key: K,
    create: impl FnOnce() -> io::Result<(Arc<S>, Arc<Activity>)>,
) -> io::Result<(Arc<S>, Arc<Activity>)> {
    let mut map = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = map.get(&key) {
        return Ok((s.socket.clone(), s.activity.clone()));
    }
    let (socket, activity) = create()?;
    activity.touch();
    map.insert(key, Session { socket: socket.clone(), activity: activity.clone() });
    Ok((socket, activity))
}
