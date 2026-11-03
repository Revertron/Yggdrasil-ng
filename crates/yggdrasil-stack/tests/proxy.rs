//! SOCKS5 and port forwarding between host sockets and the Yggdrasil network.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::{within, Pair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use yggdrasil_stack::proxy::{
    forward_local_tcp, forward_local_udp, forward_remote_tcp, forward_remote_udp, Socks5Server,
};
use yggdrasil_stack::{Host, Target, YggStack};

/// TCP echo service on the Yggdrasil side.
fn ygg_echo(stack: &YggStack, port: u16) {
    let listener = stack.tcp_listen(port).unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
}

async fn start_socks(server: Socks5Server) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve(listener));
    addr
}

/// Run a SOCKS5 CONNECT; returns the reply code and the stream.
async fn socks_connect(
    proxy: SocketAddr,
    auth: Option<(&str, &str)>,
    dst: &[u8],
    port: u16,
) -> (u8, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    let method = if auth.is_some() { 0x02 } else { 0x00 };
    s.write_all(&[5, 1, method]).await.unwrap();
    let mut choice = [0u8; 2];
    s.read_exact(&mut choice).await.unwrap();
    if choice[1] == 0xff {
        return (0xff, s);
    }
    if let Some((u, p)) = auth {
        let mut msg = vec![1, u.len() as u8];
        msg.extend_from_slice(u.as_bytes());
        msg.push(p.len() as u8);
        msg.extend_from_slice(p.as_bytes());
        s.write_all(&msg).await.unwrap();
        let mut status = [0u8; 2];
        s.read_exact(&mut status).await.unwrap();
        if status[1] != 0 {
            return (0xfe, s);
        }
    }
    let mut req = vec![5, 1, 0];
    req.extend_from_slice(dst);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 22];
    s.read_exact(&mut rep).await.unwrap();
    (rep[1], s)
}

fn atyp_ipv6(addr: std::net::Ipv6Addr) -> Vec<u8> {
    let mut v = vec![4];
    v.extend_from_slice(&addr.octets());
    v
}

fn atyp_domain(name: &str) -> Vec<u8> {
    let mut v = vec![3, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v
}

async fn echo_check(s: &mut TcpStream, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut back = vec![0u8; msg.len()];
    within(s.read_exact(&mut back)).await.unwrap();
    assert_eq!(back, msg);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_connect() {
    let pair = Pair::new().await;
    ygg_echo(&pair.sb, 7000);
    let proxy = start_socks(Socks5Server::new(pair.sa.clone())).await;

    let (code, mut s) = within(socks_connect(proxy, None, &atyp_ipv6(pair.sb.address()), 7000)).await;
    assert_eq!(code, 0);
    echo_check(&mut s, b"via address").await;

    let name = Host::Key(*pair.b.public_key()).to_string();
    let (code, mut s) = within(socks_connect(proxy, None, &atyp_domain(&name), 7000)).await;
    assert_eq!(code, 0);
    echo_check(&mut s, b"via key").await;

    // Refused port, IPv4 and unknown names.
    let (code, _) = within(socks_connect(proxy, None, &atyp_ipv6(pair.sb.address()), 7999)).await;
    assert_eq!(code, 5);
    let (code, _) = within(socks_connect(proxy, None, &[1, 10, 0, 0, 1], 80)).await;
    assert_eq!(code, 8);
    let (code, _) = within(socks_connect(proxy, None, &atyp_domain("example.com"), 80)).await;
    assert_eq!(code, 4);
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_auth_and_resolver() {
    let pair = Pair::new().await;
    ygg_echo(&pair.sb, 7001);
    let b = Host::Addr(pair.sb.address());
    let server = Socks5Server::new(pair.sa.clone())
        .with_credentials("user", "secret")
        .with_resolver(move |name| (name == "b.example").then_some(b));
    let proxy = start_socks(server).await;

    let (code, _) = within(socks_connect(proxy, None, &atyp_domain("b.example"), 7001)).await;
    assert_eq!(code, 0xff, "no-auth must be rejected");
    let (code, _) = within(socks_connect(proxy, Some(("user", "wrong")), &atyp_domain("b.example"), 7001)).await;
    assert_eq!(code, 0xfe, "bad password must be rejected");
    let (code, mut s) =
        within(socks_connect(proxy, Some(("user", "secret")), &atyp_domain("b.example"), 7001)).await;
    assert_eq!(code, 0);
    echo_check(&mut s, b"authenticated").await;
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_forward_chain() {
    // host client -> A local forward -> Yggdrasil -> B remote forward -> host echo
    let pair = Pair::new().await;
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    tokio::spawn(forward_remote_tcp(pair.sb.clone(), 80, echo_addr));

    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let target = Target { host: Host::Key(*pair.b.public_key()), port: 80 };
    tokio::spawn(forward_local_tcp(pair.sa.clone(), front, target));

    for i in 0..3 {
        let mut s = TcpStream::connect(front_addr).await.unwrap();
        echo_check(&mut s, format!("hello {i}").as_bytes()).await;
    }
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_forward_chain() {
    let pair = Pair::new().await;
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = echo.recv_from(&mut buf).await.unwrap();
            echo.send_to(&buf[..n], from).await.unwrap();
        }
    });
    tokio::spawn(forward_remote_udp(pair.sb.clone(), 53, echo_addr));

    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let front_addr = front.local_addr().unwrap();
    let target = Target { host: Host::Addr(pair.sb.address()), port: 53 };
    tokio::spawn(forward_local_udp(pair.sa.clone(), front, target));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0u8; 2048];
    // Datagrams sent before the session is set up may be lost; retry.
    let n = within(async {
        loop {
            client.send_to(b"dgram", front_addr).await.unwrap();
            if let Ok(r) = tokio::time::timeout(Duration::from_millis(300), client.recv(&mut buf)).await {
                break r.unwrap();
            }
        }
    })
    .await;
    assert_eq!(&buf[..n], b"dgram");
    client.send_to(b"again", front_addr).await.unwrap();
    let n = within(client.recv(&mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"again");
    pair.close().await;
}
