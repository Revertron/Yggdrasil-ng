//! Drives the C ABI with two in-process nodes, using the returned sockets as
//! ordinary file descriptors.
#![cfg(unix)]

use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::time::{Duration, Instant};

use ygg::*;

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn last_error() -> (i32, String) {
    let msg = unsafe { CStr::from_ptr(ygg_last_error_message()) }.to_string_lossy().into_owned();
    (ygg_last_error(), msg)
}

fn read_string(f: impl Fn(*mut std::ffi::c_char, usize) -> i32) -> String {
    let mut buf = vec![0u8; 128];
    let n = f(buf.as_mut_ptr().cast(), buf.len());
    assert!(n > 0 && (n as usize) < buf.len(), "{:?}", last_error());
    String::from_utf8(buf[..n as usize].to_vec()).unwrap()
}

fn start(config: &str) -> *mut YggNode {
    let c = cstr(config);
    let node = ygg_node_start(c.as_ptr(), 0);
    assert!(!node.is_null(), "{:?}", last_error());
    node
}

fn admin(node: *const YggNode, request: &str) -> serde_json::Value {
    let r = cstr(request);
    let out = ygg_node_admin(node, r.as_ptr());
    assert!(!out.is_null());
    let json = unsafe { CStr::from_ptr(out) }.to_string_lossy().into_owned();
    unsafe { ygg_free_string(out) };
    serde_json::from_str(&json).unwrap()
}

/// Ping until the nodes reach each other (first packets set up the session).
fn wait_reachable(from: *const YggNode, host: &str) {
    let host = cstr(host);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let rtt = ygg_ping(from, host.as_ptr(), 1000);
        if rtt >= 0 {
            return;
        }
        assert!(Instant::now() < deadline, "unreachable: {:?}", last_error());
    }
}

struct Nodes {
    a: *mut YggNode,
    b: *mut YggNode,
    b_key: String,
    b_addr: String,
}

fn nodes() -> Nodes {
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let common = "admin_listen = \"none\"\nmulticast_interfaces = []\n";
    let a = start(&format!("listen = [\"tcp://127.0.0.1:{port}\"]\n{common}"));
    let b = start(&format!("peers = [\"tcp://127.0.0.1:{port}\"]\n{common}"));
    let b_key = read_string(|p, l| ygg_node_public_key(b, p, l));
    let b_addr = read_string(|p, l| ygg_node_address(b, p, l));
    wait_reachable(a, &b_addr);
    Nodes { a, b, b_key, b_addr }
}

#[test]
fn tcp_udp_ping_admin() {
    let n = nodes();
    assert_eq!(n.b_key.len(), 64);
    assert!(n.b_addr.starts_with("20"));
    let subnet = read_string(|p, l| ygg_node_subnet(n.b, p, l));
    assert!(subnet.starts_with("30") && subnet.ends_with("/64"));

    // snprintf semantics: short buffer gets a truncated, terminated string.
    let mut small = [0x7fu8; 5];
    let full = ygg_node_address(n.b, small.as_mut_ptr().cast(), small.len());
    assert_eq!(full as usize, n.b_addr.len());
    assert_eq!(&small, &[n.b_addr.as_bytes()[0], n.b_addr.as_bytes()[1], n.b_addr.as_bytes()[2], n.b_addr.as_bytes()[3], 0]);

    // ---- TCP: listener on B, client on A dialing by key
    let listener = ygg_tcp_listen(n.b, 7000);
    assert_ne!(listener, INVALID_SOCKET, "{:?}", last_error());
    assert_eq!(ygg_tcp_accept(n.b, listener, std::ptr::null_mut(), 0, 0), INVALID_SOCKET);
    assert_eq!(ygg_last_error(), YGG_ERR_WOULD_BLOCK);

    let b = n.b as usize;
    let server = std::thread::spawn(move || {
        let b = b as *const YggNode;
        let mut peer = [0u8; 64];
        let fd = ygg_tcp_accept(b, listener, peer.as_mut_ptr().cast(), peer.len(), -1);
        assert_ne!(fd, INVALID_SOCKET);
        let peer = unsafe { CStr::from_ptr(peer.as_ptr().cast()) }.to_string_lossy().into_owned();
        let mut s = unsafe { UnixStream::from_raw_fd(fd) };
        let mut data = Vec::new();
        s.read_to_end(&mut data).unwrap();
        s.write_all(&data).unwrap();
        (peer, data.len())
    });

    let host = cstr(&format!("{}.pk.ygg", n.b_key));
    let fd = ygg_tcp_connect(n.a, host.as_ptr(), 7000, 0);
    assert_ne!(fd, INVALID_SOCKET, "{:?}", last_error());
    let mut s = unsafe { UnixStream::from_raw_fd(fd) };
    let payload: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
    s.write_all(&payload).unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut echoed = Vec::new();
    s.read_to_end(&mut echoed).unwrap();
    assert!(echoed == payload);
    let (peer, len) = server.join().unwrap();
    assert_eq!(len, payload.len());
    let a_addr = read_string(|p, l| ygg_node_address(n.a, p, l));
    assert!(peer.starts_with(&format!("[{a_addr}]:")), "{peer}");
    assert_eq!(ygg_tcp_listener_close(n.b, listener), 0);
    assert_eq!(ygg_tcp_listener_close(n.b, listener), -YGG_ERR_NOT_FOUND);

    // Refused port.
    let addr = cstr(&n.b_addr);
    assert_eq!(ygg_tcp_connect(n.a, addr.as_ptr(), 7999, 5000), INVALID_SOCKET);
    assert_eq!(ygg_last_error(), YGG_ERR_CONNECTION_REFUSED);

    // ---- UDP with the address header
    let mut b_port = 0u16;
    let ub = ygg_udp_bind(n.b, 9000, &mut b_port);
    assert_ne!(ub, INVALID_SOCKET);
    assert_eq!(b_port, 9000);
    let mut a_port = 0u16;
    let ua = ygg_udp_bind(n.a, 0, &mut a_port);
    assert_ne!(a_port, 0);
    let ub_sock = unsafe { UnixDatagram::from_raw_fd(ub) };
    let ua_sock = unsafe { UnixDatagram::from_raw_fd(ua) };
    ub_sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    ua_sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();

    let b_ip: std::net::Ipv6Addr = n.b_addr.parse().unwrap();
    let mut msg = b_ip.octets().to_vec();
    msg.extend_from_slice(&9000u16.to_be_bytes());
    msg.extend_from_slice(b"datagram");
    ua_sock.send(&msg).unwrap();
    let mut buf = [0u8; 2048];
    let len = ub_sock.recv(&mut buf).unwrap();
    assert_eq!(&buf[YGG_UDP_HEADER_LEN..len], b"datagram");
    let from_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
    assert_eq!(from_ip.to_string(), a_addr);
    assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), a_port);

    // Reply to the sender by echoing the header back.
    buf[YGG_UDP_HEADER_LEN..YGG_UDP_HEADER_LEN + 5].copy_from_slice(b"reply");
    ub_sock.send(&buf[..YGG_UDP_HEADER_LEN + 5]).unwrap();
    let len = ua_sock.recv(&mut buf).unwrap();
    assert_eq!(&buf[YGG_UDP_HEADER_LEN..len], b"reply");
    std::mem::forget(ub_sock);
    std::mem::forget(ua_sock);
    assert_eq!(ygg_udp_close(n.b, ub), 0);
    assert_eq!(ygg_udp_close(n.a, ua), 0);

    // ---- admin API and ping
    let me = admin(n.b, r#"{"request":"getSelf"}"#);
    assert_eq!(me["status"], "success");
    assert_eq!(me["response"]["address"], n.b_addr.as_str());
    let bad = admin(n.b, "not json");
    assert_eq!(bad["status"], "error");
    let a_addr_c = cstr(&a_addr);
    assert!(ygg_ping(n.b, a_addr_c.as_ptr(), 5000) >= 0);

    // ---- an open connection sees EOF when its node stops
    let listener = ygg_tcp_listen(n.b, 7001);
    let fd = ygg_tcp_connect(n.a, addr.as_ptr(), 7001, 0);
    assert_ne!(fd, INVALID_SOCKET, "{:?}", last_error());
    let accepted = ygg_tcp_accept(n.b, listener, std::ptr::null_mut(), 0, 5000);
    assert_ne!(accepted, INVALID_SOCKET);
    unsafe {
        ygg_node_stop(n.a);
    }
    let mut s = unsafe { UnixStream::from_raw_fd(fd) };
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut rest = Vec::new();
    assert_eq!(s.read_to_end(&mut rest).unwrap(), 0);
    drop(unsafe { UnixStream::from_raw_fd(accepted) });
    unsafe {
        ygg_node_stop(n.b);
    }
}

#[test]
fn services_and_errors() {
    let n = nodes();

    // Expose a host echo server on B:80, reach it via a SOCKS5 proxy on A.
    let echo = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_addr = cstr(&echo.local_addr().unwrap().to_string());
    std::thread::spawn(move || {
        for s in echo.incoming() {
            let mut s = s.unwrap();
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 || s.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let fwd = ygg_forward_remote_tcp(n.b, 80, echo_addr.as_ptr());
    assert!(fwd > 0, "{:?}", last_error());
    assert_eq!(ygg_forward_remote_tcp(n.b, 80, echo_addr.as_ptr()), -YGG_ERR_ADDR_IN_USE);

    let socks_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let listen = cstr(&format!("127.0.0.1:{socks_port}"));
    let socks = ygg_socks5_start(n.a, listen.as_ptr(), std::ptr::null(), std::ptr::null());
    assert!(socks > 0, "{:?}", last_error());

    let mut s = std::net::TcpStream::connect(("127.0.0.1", socks_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).unwrap();
    let name = format!("{}.pk.ygg", n.b_key);
    let mut req = vec![5, 1, 0, 3, name.len() as u8];
    req.extend_from_slice(name.as_bytes());
    req.extend_from_slice(&80u16.to_be_bytes());
    s.write_all(&req).unwrap();
    let mut rep = [0u8; 22];
    s.read_exact(&mut rep).unwrap();
    assert_eq!(rep[1], 0);
    s.write_all(b"through socks").unwrap();
    let mut back = [0u8; 13];
    s.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"through socks");

    assert_eq!(ygg_service_stop(n.a, socks), 0);
    assert_eq!(ygg_service_stop(n.a, socks), -YGG_ERR_NOT_FOUND);
    assert_eq!(ygg_service_stop(n.b, fwd), 0);

    // Argument and config errors.
    let bad = cstr("this is = not [toml");
    assert!(ygg_node_start(bad.as_ptr(), 0).is_null());
    assert_eq!(ygg_last_error(), YGG_ERR_CONFIG);
    let host = cstr("example.com");
    assert_eq!(ygg_tcp_connect(n.a, host.as_ptr(), 80, 0), INVALID_SOCKET);
    assert_eq!(last_error().0, YGG_ERR_INVALID_ARGUMENT);
    assert!(!last_error().1.is_empty());
    assert_eq!(ygg_tcp_connect(std::ptr::null(), host.as_ptr(), 80, 0), INVALID_SOCKET);
    assert_eq!(ygg_node_add_peer(n.a, std::ptr::null()), -YGG_ERR_INVALID_ARGUMENT);
    assert_eq!(ygg_tcp_listener_close(n.a, 12345), -YGG_ERR_NOT_FOUND);
    assert!(!ygg_version().is_null());
    let conf = ygg_generate_config();
    assert!(unsafe { CStr::from_ptr(conf) }.to_string_lossy().contains("private_key"));
    unsafe { ygg_free_string(conf) };

    unsafe {
        ygg_node_stop(n.a);
        ygg_node_stop(n.b);
    }
}

#[test]
fn pending_connect_and_network_hooks() {
    let n = nodes();
    let listener = ygg_tcp_listen(n.b, 7100);
    assert_ne!(listener, INVALID_SOCKET);

    // Non-blocking connect: wait for readability with poll(2), then finish.
    let host = cstr(&format!("{}.pk.ygg", n.b_key));
    let pending = ygg_tcp_connect_start(n.a, host.as_ptr(), 7100, 0);
    assert_ne!(pending, INVALID_SOCKET, "{:?}", last_error());
    let mut pfd = libc::pollfd { fd: pending, events: libc::POLLIN, revents: 0 };
    assert_eq!(unsafe { libc::poll(&mut pfd, 1, 20_000) }, 1, "connect did not complete");
    let fd = ygg_tcp_connect_finish(n.a, pending);
    assert_ne!(fd, INVALID_SOCKET, "{:?}", last_error());
    let accepted = ygg_tcp_accept(n.b, listener, std::ptr::null_mut(), 0, 10_000);
    assert_ne!(accepted, INVALID_SOCKET);
    let mut client = unsafe { UnixStream::from_raw_fd(fd) };
    let mut server = unsafe { UnixStream::from_raw_fd(accepted) };
    client.write_all(b"nb").unwrap();
    let mut got = [0u8; 2];
    server.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"nb");

    // Still running -> WOULD_BLOCK; cancel closes the handle.
    let nowhere = cstr("200:dead:beef::1");
    let pending = ygg_tcp_connect_start(n.a, nowhere.as_ptr(), 80, 0);
    assert_eq!(ygg_tcp_connect_finish(n.a, pending), INVALID_SOCKET);
    assert_eq!(ygg_last_error(), YGG_ERR_WOULD_BLOCK);
    assert_eq!(ygg_tcp_connect_cancel(n.a, pending), 0);
    assert_eq!(ygg_tcp_connect_cancel(n.a, pending), -YGG_ERR_NOT_FOUND);

    // Network hooks.
    assert_eq!(ygg_node_network_changed(n.a), 0);
    let ifaces = cstr(r#"[{"name":"wlan0","index":3,"addrs":["fe80::1"]}]"#);
    assert_eq!(ygg_node_set_network_interfaces(n.a, ifaces.as_ptr()), 0);
    let bad = cstr(r#"[{"name":"wlan0","addrs":["not an address"]}]"#);
    assert_eq!(ygg_node_set_network_interfaces(n.a, bad.as_ptr()), -YGG_ERR_INVALID_ARGUMENT);
    assert!(last_error().1.contains("interfaces JSON"));

    let conf = cstr("admin_listen = \"none\"\nmulticast_interfaces = []\n");
    let started = ygg_node_start_ex(conf.as_ptr(), 0, ifaces.as_ptr());
    assert!(!started.is_null(), "{:?}", last_error());
    assert!(ygg_node_start_ex(conf.as_ptr(), 0, bad.as_ptr()).is_null());
    assert_eq!(ygg_last_error(), YGG_ERR_INVALID_ARGUMENT);

    drop((client, server));
    assert_eq!(ygg_tcp_listener_close(n.b, listener), 0);
    unsafe {
        ygg_node_stop(started);
        ygg_node_stop(n.a);
        ygg_node_stop(n.b);
    }
}
