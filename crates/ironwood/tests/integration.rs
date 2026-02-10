//! Integration tests for ironwood PacketConn types.
//!
//! These tests connect multiple nodes via in-memory duplex streams and verify
//! end-to-end packet delivery across plain, encrypted, and signed conn types.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::time::timeout;

use ironwood::{
    new_encrypted_packet_conn, new_packet_conn, new_signed_packet_conn, Addr, Config, PacketConn,
};

/// Connect two PacketConn nodes via a duplex stream.
/// Spawns `handle_conn` on both sides and returns the join handles.
async fn connect_nodes(
    a: &Arc<impl PacketConn + 'static>,
    b: &Arc<impl PacketConn + 'static>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let (stream_a, stream_b) = tokio::io::duplex(65536);

    let addr_a = a.local_addr();
    let addr_b = b.local_addr();

    let a2 = Arc::clone(a);
    let b2 = Arc::clone(b);

    let ha = tokio::spawn(async move {
        let _ = a2.handle_conn(addr_b, Box::new(stream_a), 0).await;
    });
    let hb = tokio::spawn(async move {
        let _ = b2.handle_conn(addr_a, Box::new(stream_b), 0).await;
    });

    (ha, hb)
}

/// Read the next non-empty packet from a PacketConn, with timeout.
/// Skips empty packets that result from path lookups.
async fn read_nonempty(
    conn: &(dyn PacketConn + Send + Sync),
    buf: &mut [u8],
    deadline: Duration,
) -> ironwood::Result<(usize, Addr)> {
    let start = tokio::time::Instant::now();
    loop {
        let remaining = deadline.checked_sub(start.elapsed()).unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            return Err(ironwood::Error::Timeout);
        }
        match timeout(remaining, conn.read_from(buf)).await {
            Ok(Ok((0, _))) => continue, // skip empty lookup packets
            Ok(Ok((n, addr))) => return Ok((n, addr)),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(ironwood::Error::Timeout),
        }
    }
}

/// Diagnostic test: just check basic connectivity and message exchange.
/// Uses the same pattern as Go: send in a loop, read with timeout.
#[tokio::test]
async fn two_node_plain() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);

    let node_a = new_packet_conn(key_a, Config::default());
    let node_b = new_packet_conn(key_b, Config::default());

    let (_ha, _hb) = connect_nodes(&node_a, &node_b).await;

    let addr_a = node_a.local_addr();
    let addr_b = node_b.local_addr();

    // Spawn reader on B
    let node_b2 = node_b.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_b2.read_from(&mut buf).await {
                Ok((n, from)) => {
                    if n > 0 && from == addr_a {
                        return buf[..n].to_vec();
                    }
                    // Skip empty packets or wrong sender
                }
                Err(_) => return Vec::new(),
            }
        }
    });

    // Spawn sender on A: send every second (matches Go test pattern)
    let msg = b"test".to_vec();
    let node_a2 = node_a.clone();
    let sender = tokio::spawn(async move {
        loop {
            let _ = node_a2.write_to(&msg, &addr_b).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Wait for reader with 30s timeout (matching Go)
    let result = timeout(Duration::from_secs(30), reader).await;
    sender.abort();

    match result {
        Ok(Ok(data)) => {
            assert_eq!(data, b"test");
        }
        Ok(Err(e)) => panic!("reader task panicked: {:?}", e),
        Err(_) => panic!("timeout: packet never arrived after 30s"),
    }

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
}

#[tokio::test]
async fn two_node_bidirectional() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);

    let node_a = new_packet_conn(key_a, Config::default());
    let node_b = new_packet_conn(key_b, Config::default());

    let (_ha, _hb) = connect_nodes(&node_a, &node_b).await;

    let addr_a = node_a.local_addr();
    let addr_b = node_b.local_addr();

    let msg = b"test".to_vec();

    // Spawn readers on both sides
    let node_b2 = node_b.clone();
    let reader_b = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_b2.read_from(&mut buf).await {
                Ok((n, from)) if n > 0 && from == addr_a => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    });
    let node_a2 = node_a.clone();
    let reader_a = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_a2.read_from(&mut buf).await {
                Ok((n, from)) if n > 0 && from == addr_b => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    });

    // Spawn senders
    let node_a3 = node_a.clone();
    let msg2 = msg.clone();
    let sender_a = tokio::spawn(async move {
        loop {
            let _ = node_a3.write_to(&msg2, &addr_b).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    let node_b3 = node_b.clone();
    let sender_b = tokio::spawn(async move {
        loop {
            let _ = node_b3.write_to(&msg, &addr_a).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let rb = timeout(Duration::from_secs(30), reader_b).await;
    let ra = timeout(Duration::from_secs(30), reader_a).await;
    sender_a.abort();
    sender_b.abort();

    assert!(rb.expect("timeout B").expect("panic B"), "B never got msg from A");
    assert!(ra.expect("timeout A").expect("panic A"), "A never got msg from B");

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
}

#[tokio::test]
async fn three_node_chain() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let key_c = SigningKey::generate(&mut OsRng);

    let node_a = new_packet_conn(key_a, Config::default());
    let node_b = new_packet_conn(key_b, Config::default());
    let node_c = new_packet_conn(key_c, Config::default());

    // A ↔ B
    let (_h1, _h2) = connect_nodes(&node_a, &node_b).await;
    // B ↔ C
    let (_h3, _h4) = connect_nodes(&node_b, &node_c).await;

    let addr_a = node_a.local_addr();
    let addr_c = node_c.local_addr();

    let msg = b"test".to_vec();

    // Reader on C
    let node_c2 = node_c.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_c2.read_from(&mut buf).await {
                Ok((n, from)) if n > 0 && from == addr_a => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    });

    // Sender on A
    let node_a2 = node_a.clone();
    let sender = tokio::spawn(async move {
        loop {
            let _ = node_a2.write_to(&msg, &addr_c).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let result = timeout(Duration::from_secs(30), reader).await;
    sender.abort();

    assert!(result.expect("timeout").expect("panic"), "C never got msg from A");

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
    node_c.close().await.unwrap();
}

#[tokio::test]
async fn two_node_encrypted() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);

    let node_a = new_encrypted_packet_conn(key_a, Config::default());
    let node_b = new_encrypted_packet_conn(key_b, Config::default());

    let (_ha, _hb) = connect_nodes(&node_a, &node_b).await;

    let addr_a = node_a.local_addr();
    let addr_b = node_b.local_addr();

    let msg = b"encrypted hello".to_vec();

    // Reader on B
    let node_b2 = node_b.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_b2.read_from(&mut buf).await {
                Ok((n, from)) if n > 0 && from == addr_a => {
                    return buf[..n].to_vec();
                }
                Ok(_) => continue,
                Err(_) => return Vec::new(),
            }
        }
    });

    // Sender on A
    let node_a2 = node_a.clone();
    let sender = tokio::spawn(async move {
        loop {
            let _ = node_a2.write_to(&msg, &addr_b).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let result = timeout(Duration::from_secs(30), reader).await;
    sender.abort();

    match result {
        Ok(Ok(data)) => assert_eq!(data, b"encrypted hello"),
        Ok(Err(e)) => panic!("panic: {:?}", e),
        Err(_) => panic!("timeout"),
    }

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
}

#[tokio::test]
async fn two_node_signed() {
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);

    let node_a = new_signed_packet_conn(key_a, Config::default());
    let node_b = new_signed_packet_conn(key_b, Config::default());

    let (_ha, _hb) = connect_nodes(&node_a, &node_b).await;

    let addr_a = node_a.local_addr();
    let addr_b = node_b.local_addr();

    let msg = b"signed hello".to_vec();

    // Reader on B
    let node_b2 = node_b.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            match node_b2.read_from(&mut buf).await {
                Ok((n, from)) if n > 0 && from == addr_a => {
                    return buf[..n].to_vec();
                }
                Ok(_) => continue,
                Err(_) => return Vec::new(),
            }
        }
    });

    // Sender on A
    let node_a2 = node_a.clone();
    let sender = tokio::spawn(async move {
        loop {
            let _ = node_a2.write_to(&msg, &addr_b).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let result = timeout(Duration::from_secs(30), reader).await;
    sender.abort();

    match result {
        Ok(Ok(data)) => assert_eq!(data, b"signed hello"),
        Ok(Err(e)) => panic!("panic: {:?}", e),
        Err(_) => panic!("timeout"),
    }

    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
}
