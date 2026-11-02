//! Two embedded nodes peered over loopback, each running a userspace stack.

mod common;

use std::io::ErrorKind;
use std::time::Duration;

use common::{within, Pair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_echo_bulk() {
    let pair = Pair::new().await;
    let listener = pair.sb.tcp_listen(7000).unwrap();

    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        tokio::io::copy(&mut r, &mut w).await.unwrap();
        w.shutdown().await.unwrap();
        peer
    });

    let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let stream = within(pair.sa.tcp_connect(pair.b_addr(7000))).await.unwrap();
    assert_eq!(stream.peer_addr(), pair.b_addr(7000));
    let local = stream.local_addr();
    let (mut r, mut w) = tokio::io::split(stream);

    let to_send = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&to_send).await.unwrap();
        w.shutdown().await.unwrap();
        w
    });
    let mut echoed = Vec::new();
    within(r.read_to_end(&mut echoed)).await.unwrap();
    let _w = writer.await.unwrap();

    assert_eq!(echoed.len(), data.len());
    assert!(echoed == data, "echoed data differs");
    assert_eq!(within(server).await.unwrap(), local);
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_many_connections_and_key_dial() {
    let pair = Pair::new().await;
    let listener = pair.sb.tcp_listen(7001).unwrap();
    const N: usize = 40;

    let server = tokio::spawn(async move {
        let mut handlers = Vec::new();
        for _ in 0..N {
            let (mut s, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let mut buf = [0u8; 8];
                s.read_exact(&mut buf).await.unwrap();
                s.write_all(&buf).await.unwrap();
            }));
        }
        for h in handlers {
            h.await.unwrap();
        }
    });

    let key = *pair.b.public_key();
    let mut clients = Vec::new();
    for i in 0..N as u64 {
        let stack = pair.sa.clone();
        clients.push(tokio::spawn(async move {
            let mut s = stack.tcp_connect_key(&key, 7001).await.unwrap();
            s.set_nodelay(true);
            s.write_all(&i.to_be_bytes()).await.unwrap();
            let mut buf = [0u8; 8];
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(u64::from_be_bytes(buf), i);
        }));
    }
    for c in clients {
        within(c).await.unwrap();
    }
    within(server).await.unwrap();
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_refused_and_eof() {
    let pair = Pair::new().await;

    let err = within(pair.sa.tcp_connect(pair.b_addr(7999))).await.err().unwrap();
    assert_eq!(err.kind(), ErrorKind::ConnectionRefused);

    let listener = pair.sb.tcp_listen(7002).unwrap();
    assert_eq!(pair.sb.tcp_listen(7002).err().unwrap().kind(), ErrorKind::AddrInUse);
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"bye").await.unwrap();
        // Dropping the stream closes it gracefully.
    });
    let mut s = within(pair.sa.tcp_connect(pair.b_addr(7002))).await.unwrap();
    let mut got = Vec::new();
    within(s.read_to_end(&mut got)).await.unwrap();
    assert_eq!(got, b"bye");

    let bad = "[fd00::1]:80".parse().unwrap();
    assert_eq!(pair.sa.tcp_connect(bad).await.err().unwrap().kind(), ErrorKind::InvalidInput);
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_roundtrip() {
    let pair = Pair::new().await;
    let server = pair.sb.udp_bind(9000).unwrap();
    assert_eq!(pair.sb.udp_bind(9000).err().unwrap().kind(), ErrorKind::AddrInUse);
    let client = pair.sa.udp_bind(0).unwrap();
    assert_ne!(client.local_addr().port(), 0);

    // The first datagrams may race the key lookup; retry until one lands.
    let mut buf = [0u8; 2048];
    let (n, from) = within(async {
        loop {
            client.send_to(b"ping", pair.b_addr(9000)).await.unwrap();
            if let Ok(r) =
                tokio::time::timeout(Duration::from_millis(300), server.recv_from(&mut buf)).await
            {
                break r.unwrap();
            }
        }
    })
    .await;
    assert_eq!(&buf[..n], b"ping");
    assert_eq!(from, client.local_addr());

    server.send_to(b"pong", from).await.unwrap();
    let (n, from) = within(client.recv_from(&mut buf)).await.unwrap();
    assert_eq!(&buf[..n], b"pong");
    assert_eq!(from, pair.b_addr(9000));

    let too_big = vec![0u8; client.max_datagram_size() + 1];
    assert_eq!(
        client.send_to(&too_big, pair.b_addr(9000)).await.err().unwrap().kind(),
        ErrorKind::InvalidInput
    );
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_both_ways() {
    let pair = Pair::new().await;
    let rtt = within(async {
        loop {
            match pair.sa.ping(pair.sb.address(), Duration::from_secs(1)).await {
                Ok(rtt) => break rtt,
                Err(e) if e.kind() == ErrorKind::TimedOut => continue,
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await;
    assert!(rtt < Duration::from_secs(1));
    let key = *pair.a.public_key();
    within(pair.sb.ping_key(&key, Duration::from_secs(5))).await.unwrap();
    pair.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_fails_sockets() {
    let pair = Pair::new().await;
    let listener = pair.sb.tcp_listen(7003).unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.err().map(|e| e.kind()) });
    tokio::time::sleep(Duration::from_millis(50)).await;
    pair.sb.close();
    assert_eq!(within(accept).await.unwrap(), Some(ErrorKind::NotConnected));
    assert_eq!(pair.sb.udp_bind(1).err().unwrap().kind(), ErrorKind::NotConnected);
    pair.close().await;
}

/// One-way bulk transfer; run with
/// `cargo test --release -p yggdrasil-stack --test stack throughput -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn throughput() {
    const TOTAL: usize = 256 * 1024 * 1024;
    let pair = Pair::new().await;
    let listener = pair.sb.tcp_listen(7100).unwrap();
    let sink = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 256 * 1024];
        let mut total = 0;
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break total;
            }
            total += n;
        }
    });
    let mut s = within(pair.sa.tcp_connect(pair.b_addr(7100))).await.unwrap();
    let chunk = vec![0x5au8; 256 * 1024];
    let start = std::time::Instant::now();
    for _ in 0..TOTAL / chunk.len() {
        s.write_all(&chunk).await.unwrap();
    }
    s.shutdown().await.unwrap();
    let received = tokio::time::timeout(Duration::from_secs(120), sink).await.unwrap().unwrap();
    let secs = start.elapsed().as_secs_f64();
    assert_eq!(received, TOTAL);
    eprintln!(
        "throughput: {} MiB in {:.2}s = {:.0} Mbit/s (mtu {})",
        TOTAL >> 20,
        secs,
        TOTAL as f64 * 8.0 / secs / 1e6,
        pair.sa.mtu()
    );
    drop(s);
    pair.close().await;
}
