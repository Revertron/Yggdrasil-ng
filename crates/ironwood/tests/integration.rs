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
    new_encrypted_packet_conn, new_packet_conn, new_signed_packet_conn, AdaptiveTimeoutConfig,
    Config, PacketConn, PacketConnImpl,
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

async fn connect_plain(a: &Arc<PacketConnImpl>, b: &Arc<PacketConnImpl>) {
    let (sa, sb) = tokio::io::duplex(1 << 16);
    let addr_a = a.local_addr();
    let addr_b = b.local_addr();
    let a2 = Arc::clone(a);
    let b2 = Arc::clone(b);
    tokio::spawn(async move { let _ = a2.handle_conn(addr_b, Box::new(sa), 0).await; });
    tokio::spawn(async move { let _ = b2.handle_conn(addr_a, Box::new(sb), 0).await; });
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

/// Verifies that a PathLookup lost during tree/bloom convergence is retried by
/// the periodic maintenance tick. A sends ONE packet to D (no reply from D).
/// We settle for only 500ms so the first lookup races convergence; the retry
/// in `do_maintenance` must be what delivers it. Without the retry loop this
/// wedges; with it, every trial delivers.
///
/// Topology: A — H1 — H2 — D  (forward direction only; return path not tested here).
///
/// Ignored by default: each trial spins up four in-memory nodes and waits on real
/// ~1s maintenance ticks, so it runs for seconds. The retry logic itself is covered
/// by fast unit tests in `pathfinder` (`rumor_retry_throttles_without_extending_lifetime`);
/// run this end-to-end check manually:
///   cargo test -p ironwood --test integration cross_hub_forward_discovery_retry -- --ignored
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow E2E: multi-node network with real maintenance ticks; run with --ignored"]
async fn cross_hub_forward_discovery_retry() {
    // Each trial needs several 1s retries to deliver (the first lookup often races
    // convergence and is lost), so this is inherently multi-second per trial.
    let trials = 10;
    for trial in 0..trials {
        let a  = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h1 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h2 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let d  = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

        connect_plain(&a, &h1).await;
        connect_plain(&h1, &h2).await;
        connect_plain(&h2, &d).await;

        let addr_a = a.local_addr();
        let addr_d = d.local_addr();

        // Short settle: forces a lookup race with convergence so the retry is exercised.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // A sends exactly one packet to D.
        a.write_to(b"PING", &addr_d).await.ok();

        // D must receive it (the retry closes the window; without it this wedges).
        let d2 = d.clone();
        let received = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match d2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_a => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let ok = matches!(
            timeout(Duration::from_secs(8), received).await,
            Ok(Ok(true))
        );

        for n in [&a, &h1, &h2, &d] {
            let _ = n.close().await;
        }

        assert!(ok, "trial {}: D did not receive the packet within 8s", trial);
    }
}

/// A peer that stops answering must be probed rather than dropped on the first
/// missed interval — a lossy path can stall for seconds while TCP backs off its
/// retransmits, and tearing the link down loses more than waiting does. The
/// link still has to die once the probe budget is spent.
#[tokio::test]
async fn silent_peer_is_probed_before_disconnect() {
    const INTERVAL: Duration = Duration::from_millis(150);

    /// How long the node takes to give up on a peer that reads everything we
    /// send it and never answers.
    async fn time_to_disconnect(probes: u32) -> Duration {
        let config = Config::default()
            .with_peer_timeout(INTERVAL)
            .with_peer_probe_count(probes);
        let node = new_packet_conn(SigningKey::generate(&mut OsRng), config);
        let peer_addr = ironwood::Addr::from(
            SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
        );

        let (ours, theirs) = tokio::io::duplex(65536);
        // Drain the silent end so the node's writes never block: the only thing
        // allowed to end this connection is the liveness deadline.
        tokio::spawn(async move {
            let mut theirs = theirs;
            let mut buf = [0u8; 4096];
            while tokio::io::AsyncReadExt::read(&mut theirs, &mut buf)
                .await
                .unwrap_or(0)
                > 0
            {}
        });

        let start = tokio::time::Instant::now();
        timeout(
            Duration::from_secs(5),
            node.handle_conn(peer_addr, Box::new(ours), 0),
        )
        .await
        .expect("peer outlived its probe budget entirely")
        .ok();
        start.elapsed()
    }

    let with_retry = time_to_disconnect(3).await;
    let no_retry = time_to_disconnect(1).await;

    assert!(
        with_retry >= INTERVAL * 2,
        "gave up after {with_retry:?}; three probes should outlast {:?}",
        INTERVAL * 2
    );
    assert!(
        with_retry < INTERVAL * 8,
        "took {with_retry:?}, far beyond the {:?} budget",
        INTERVAL * 3
    );
    assert!(
        no_retry < INTERVAL * 2,
        "single-probe peer survived {no_retry:?}, expected a prompt drop"
    );
}

/// Adaptive sticky floor still multiplies by `peer_probe_count` for total silence.
/// Cold floor = interval; three probes must outlast two intervals and die before
/// a generous upper bound (scheduler slack).
#[tokio::test]
async fn adaptive_interval_times_probe_count_wall_time() {
    const INTERVAL: Duration = Duration::from_millis(120);
    const PROBES: u32 = 3;

    let adaptive = AdaptiveTimeoutConfig {
        fixed_or_initial: INTERVAL,
        adaptive: true,
        min: INTERVAL,
        problem_min: INTERVAL,
        max: Duration::from_secs(2),
        base: Duration::ZERO,
        rtt_mult: 1,
        penalty_step: Duration::ZERO,
        penalty_decay: Duration::ZERO,
    };
    adaptive.validate().expect("test adaptive cfg");

    let config = Config::default()
        .with_peer_timeout_cfg(adaptive)
        .with_peer_probe_count(PROBES);
    let node = new_packet_conn(SigningKey::generate(&mut OsRng), config);
    let peer_addr = ironwood::Addr::from(
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
    );

    let (ours, theirs) = tokio::io::duplex(65536);
    tokio::spawn(async move {
        let mut theirs = theirs;
        let mut buf = [0u8; 4096];
        while tokio::io::AsyncReadExt::read(&mut theirs, &mut buf)
            .await
            .unwrap_or(0)
            > 0
        {}
    });

    let start = tokio::time::Instant::now();
    timeout(
        Duration::from_secs(5),
        node.handle_conn(peer_addr, Box::new(ours), 0),
    )
    .await
    .expect("adaptive peer outlived probe budget")
    .ok();
    let elapsed = start.elapsed();

    let nominal = INTERVAL * PROBES;
    assert!(
        elapsed >= INTERVAL * 2,
        "adaptive gave up after {elapsed:?}; expected at least 2×{INTERVAL:?}"
    );
    assert!(
        elapsed < nominal + INTERVAL * 3,
        "adaptive took {elapsed:?}, far beyond nominal {nominal:?}"
    );
}
