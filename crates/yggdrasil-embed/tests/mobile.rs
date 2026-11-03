//! Network-change hooks and non-blocking connects.
#![cfg(unix)]

use std::io::{Read, Write};
use std::net::Ipv6Addr;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use yggdrasil_embed::{
    CSocket, EmbeddedNode, Host, NetworkInterface, StartOptions, Target, ERR_CLOSED,
    ERR_CONNECTION_REFUSED, ERR_NOT_FOUND, ERR_WOULD_BLOCK,
};

const COMMON: &str = "admin_listen = \"none\"\nmulticast_interfaces = []\n";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn start(extra: &str) -> Arc<EmbeddedNode> {
    Arc::new(EmbeddedNode::start_toml(Some(&format!("{extra}\n{COMMON}")), StartOptions::default()).unwrap())
}

fn reachable(from: &EmbeddedNode, to: Ipv6Addr) -> bool {
    from.ping(&Host::Addr(to), Some(Duration::from_millis(500))).is_ok()
}

/// Whether the node's configured peer link is up (admin getPeers).
fn peer_up(node: &EmbeddedNode) -> bool {
    let reply: serde_json::Value = serde_json::from_str(&node.admin(r#"{"request":"getPeers"}"#).unwrap()).unwrap();
    reply["response"]["peers"]
        .as_array()
        .is_some_and(|peers| peers.iter().any(|p| p["up"] == true))
}

fn pair() -> (Arc<EmbeddedNode>, Arc<EmbeddedNode>) {
    let port = free_port();
    let a = start(&format!("listen = [\"tcp://127.0.0.1:{port}\"]"));
    let b = start(&format!("peers = [\"tcp://127.0.0.1:{port}\"]"));
    let deadline = Instant::now() + Duration::from_secs(20);
    while !reachable(&a, b.address()) {
        assert!(Instant::now() < deadline, "nodes did not connect");
    }
    (a, b)
}

/// Echo one message per connection on `port` until the listener closes.
fn echo_server(node: &Arc<EmbeddedNode>, port: u16) -> CSocket {
    let listener = node.tcp_listen(port).unwrap();
    let node = node.clone();
    std::thread::spawn(move || {
        while let Ok((fd, _)) = node.tcp_accept(listener, None) {
            let mut s = unsafe { UnixStream::from_raw_fd(fd) };
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).unwrap_or(0);
            let _ = s.write_all(&buf[..n]);
        }
    });
    listener
}

fn roundtrip(fd: CSocket, msg: &[u8]) {
    let mut s = unsafe { UnixStream::from_raw_fd(fd) };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(msg).unwrap();
    let mut back = vec![0u8; msg.len()];
    s.read_exact(&mut back).unwrap();
    assert_eq!(back, msg);
}

fn readable(fd: CSocket, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) == 1 }
}

fn open_fd(fd: CSocket) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

#[test]
fn pending_connect_handle() {
    let (a, b) = pair();
    let listener = echo_server(&b, 7000);
    let target = Target { host: Host::Addr(b.address()), port: 7000 };

    // Success: the handle turns readable, finish yields the stream and
    // closes the handle.
    let pending = a.tcp_connect_start(target, None).unwrap();
    assert!(readable(pending, Duration::from_secs(20)), "connect never completed");
    let fd = a.tcp_connect_finish(pending).unwrap();
    assert!(!open_fd(pending), "pending handle should be closed after finish");
    roundtrip(fd, b"pending");

    // Refused: the error comes out of finish.
    let pending = a.tcp_connect_start(Target { port: 7999, ..target }, None).unwrap();
    assert!(readable(pending, Duration::from_secs(20)));
    let err = a.tcp_connect_finish(pending).unwrap_err();
    assert_eq!(err.code, ERR_CONNECTION_REFUSED);
    assert_eq!(a.tcp_connect_finish(pending).unwrap_err().code, ERR_NOT_FOUND);

    // In progress, then cancelled: an unreachable address never completes.
    let nowhere = Target { host: "200:dead:beef::1".parse().unwrap(), port: 80 };
    let pending = a.tcp_connect_start(nowhere, None).unwrap();
    assert_eq!(a.tcp_connect_finish(pending).unwrap_err().code, ERR_WOULD_BLOCK);
    a.tcp_connect_cancel(pending).unwrap();
    assert!(!open_fd(pending), "pending handle should be closed after cancel");
    assert_eq!(a.tcp_connect_cancel(pending).unwrap_err().code, ERR_NOT_FOUND);

    b.tcp_listener_close(listener).unwrap();
    a.shutdown();
    b.shutdown();
}

#[test]
fn async_connect_on_foreign_executor() {
    let (a, b) = pair();
    let listener = echo_server(&b, 7001);
    let target = Target { host: Host::Key(b.public_key().unwrap()), port: 7001 };

    // Awaited on an executor that is not the node's runtime.
    let other = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let fd = other.block_on(a.tcp_connect_async(target, None)).unwrap();
    roundtrip(fd, b"async");
    let err = other
        .block_on(a.tcp_connect_async(Target { port: 7999, ..target }, Some(Duration::from_secs(20))))
        .unwrap_err();
    assert_eq!(err.code, ERR_CONNECTION_REFUSED);

    // Dropping the future cancels the connect.
    let nowhere = Target { host: "200:dead:beef::1".parse().unwrap(), port: 80 };
    let r = other.block_on(async {
        tokio::time::timeout(Duration::from_millis(200), a.tcp_connect_async(nowhere, None)).await
    });
    assert!(r.is_err(), "unreachable connect should still be running");

    b.tcp_listener_close(listener).unwrap();
    a.shutdown();
    let err = other.block_on(a.tcp_connect_async(target, None)).unwrap_err();
    assert_eq!(err.code, ERR_CLOSED);
    b.shutdown();
}

/// `network_changed` redials a peer that is down right away instead of after
/// its backoff. b's dials fail at ~0 s and ~2 s; the next would be at ~6 s.
#[test]
fn network_changed_redials_now() {
    let port = free_port();
    let b = start(&format!("peers = [\"tcp://127.0.0.1:{port}\"]"));
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(3500));

    let a = start(&format!("listen = [\"tcp://127.0.0.1:{port}\"]"));
    b.network_changed().unwrap();
    // Watch the link itself (not an end-to-end ping, whose session setup
    // adds variable delay).
    let mut connected = None;
    while started.elapsed() < Duration::from_millis(5500) {
        if peer_up(&b) {
            connected = Some(started.elapsed());
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let at = connected.expect("peer was not redialled after network_changed");
    assert!(at < Duration::from_millis(5500), "connected at {at:?}, i.e. only by the backoff timer");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !reachable(&b, a.address()) {
        assert!(Instant::now() < deadline, "peer link up but node unreachable");
    }

    // Interfaces from the app are accepted (multicast is off in this config).
    b.set_network_interfaces(vec![NetworkInterface {
        name: "wlan0".into(),
        index: 3,
        addrs: vec!["fe80::1".parse().unwrap()],
    }])
    .unwrap();
    a.shutdown();
    b.shutdown();
    assert_eq!(b.network_changed().unwrap_err().code, ERR_CLOSED);
}

#[test]
fn start_with_network_interfaces() {
    let options = StartOptions {
        network_interfaces: Some(vec![NetworkInterface {
            name: "lo".into(),
            index: 1,
            addrs: vec![Ipv6Addr::LOCALHOST],
        }]),
        ..Default::default()
    };
    let node = EmbeddedNode::start_toml(Some(COMMON), options).unwrap();
    node.network_changed().unwrap();
    node.stop();
}
