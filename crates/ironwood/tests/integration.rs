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
    new_encrypted_packet_conn, new_packet_conn, new_signed_packet_conn, Config, PacketConn,
    PacketConnImpl, PeerOptions,
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
        let _ = a2.handle_conn(addr_b, Box::new(stream_a), PeerOptions::default()).await;
    });
    let hb = tokio::spawn(async move {
        let _ = b2.handle_conn(addr_a, Box::new(stream_b), PeerOptions::default()).await;
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
    tokio::spawn(async move { let _ = a2.handle_conn(addr_b, Box::new(sa), PeerOptions::default()).await; });
    tokio::spawn(async move { let _ = b2.handle_conn(addr_a, Box::new(sb), PeerOptions::default()).await; });
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
            node.handle_conn(peer_addr, Box::new(ours), PeerOptions::default()),
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

// ---------------------------------------------------------------------------
// Isolated links
// ---------------------------------------------------------------------------

/// Connect two nodes with an explicit `PeerOptions` on both ends, returning a
/// handle that drops the link when cancelled.
fn connect_with(
    a: &Arc<PacketConnImpl>,
    b: &Arc<PacketConnImpl>,
    opts: PeerOptions,
) -> Vec<tokio::task::JoinHandle<()>> {
    let (sa, sb) = tokio::io::duplex(1 << 16);
    let addr_a = a.local_addr();
    let addr_b = b.local_addr();
    let a2 = Arc::clone(a);
    let b2 = Arc::clone(b);
    vec![
        tokio::spawn(async move {
            let _ = a2.handle_conn(addr_b, Box::new(sa), opts).await;
        }),
        tokio::spawn(async move {
            let _ = b2.handle_conn(addr_a, Box::new(sb), opts).await;
        }),
    ]
}

/// True if `node`'s view of the tree contains an edge between `x` and `y` in
/// either direction.
async fn has_tree_edge(node: &Arc<PacketConnImpl>, x: [u8; 32], y: [u8; 32]) -> bool {
    node.get_tree()
        .await
        .iter()
        .any(|e| (e.key == x && e.parent == y) || (e.key == y && e.parent == x))
}

/// Topology: `hub` peers normally with `a`, `c1` and `c2`; `a` additionally has
/// isolated links to `c1` and `c2`. The isolated links must never become tree
/// edges, must not perturb `a`'s coordinates when they flap, and must still
/// carry traffic.
#[tokio::test(flavor = "multi_thread")]
async fn isolated_links_never_join_the_tree() {
    let hub = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let a = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let c1 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let c2 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

    let (ka, kc1, kc2) = (a.local_addr().0, c1.local_addr().0, c2.local_addr().0);

    // Normal backbone: everyone reaches the network through the hub.
    let _b1 = connect_with(&hub, &a, PeerOptions::default());
    let _b2 = connect_with(&hub, &c1, PeerOptions::default());
    let _b3 = connect_with(&hub, &c2, PeerOptions::default());

    tokio::time::sleep(Duration::from_secs(4)).await;
    let baseline_coords = a.tree_coordinates().await;

    let isolated = PeerOptions {
        prio: 0,
        isolated: true,
    };

    // Flap the isolated links a few times; none of it may reach the tree.
    for round in 0..3 {
        let l1 = connect_with(&a, &c1, isolated);
        let l2 = connect_with(&a, &c2, isolated);
        tokio::time::sleep(Duration::from_secs(3)).await;

        for (label, node) in [("a", &a), ("hub", &hub), ("c1", &c1), ("c2", &c2)] {
            assert!(
                !has_tree_edge(node, ka, kc1).await,
                "round {round}: {label} sees a tree edge a<->c1"
            );
            assert!(
                !has_tree_edge(node, ka, kc2).await,
                "round {round}: {label} sees a tree edge a<->c2"
            );
        }

        assert_eq!(
            a.tree_coordinates().await,
            baseline_coords,
            "round {round}: isolated links moved a's coordinates"
        );

        // Traffic over the isolated link still flows (both nodes reach the
        // network through the hub, so a path to c1 exists; the direct link is
        // then preferred because it is zero hops from the destination).
        if round == 0 {
            let c1_reader = {
                let c1 = c1.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match c1.read_from(&mut buf).await {
                            Ok((n, from)) if n > 0 && from.0 == ka => return buf[..n].to_vec(),
                            Ok(_) => continue,
                            Err(_) => return Vec::new(),
                        }
                    }
                })
            };
            let sender = {
                let a = a.clone();
                let dest = c1.local_addr();
                tokio::spawn(async move {
                    loop {
                        let _ = a.write_to(b"isolated-hello", &dest).await;
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                })
            };
            let got = timeout(Duration::from_secs(20), c1_reader).await;
            sender.abort();
            assert_eq!(
                got.expect("timed out delivering over the isolated link")
                    .expect("reader panicked"),
                b"isolated-hello".to_vec()
            );
        }

        for h in l1.into_iter().chain(l2) {
            h.abort();
        }
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(
            a.tree_coordinates().await,
            baseline_coords,
            "round {round}: dropping the isolated links moved a's coordinates"
        );
    }

    for n in [&hub, &a, &c1, &c2] {
        n.close().await.unwrap();
    }
}

/// Deterministic control: `c1` and `c2` each have exactly one peer, `a`. The
/// normal link must produce a tree edge; the isolated one must not, leaving
/// `c1` the root of its own one-node tree.
#[tokio::test(flavor = "multi_thread")]
async fn isolated_link_is_the_only_link_without_a_tree_edge() {
    let a = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let c1 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let c2 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

    let (ka, kc1, kc2) = (a.local_addr().0, c1.local_addr().0, c2.local_addr().0);

    let _isolated = connect_with(
        &a,
        &c1,
        PeerOptions {
            prio: 0,
            isolated: true,
        },
    );
    let _normal = connect_with(&a, &c2, PeerOptions::default());

    tokio::time::sleep(Duration::from_secs(5)).await;

    // Control: the ordinary link is a tree edge in one direction or the other.
    assert!(
        has_tree_edge(&a, ka, kc2).await,
        "the ordinary a<->c2 link never became a tree edge"
    );

    // The isolated link is not, from either end.
    assert!(
        !has_tree_edge(&a, ka, kc1).await,
        "a sees a tree edge over the isolated link"
    );
    assert!(
        !has_tree_edge(&c1, ka, kc1).await,
        "c1 sees a tree edge over the isolated link"
    );

    // With no tree parent available, c1 roots its own tree.
    assert!(
        c1.tree_coordinates().await.is_empty(),
        "c1 acquired coordinates through an isolated link"
    );
    assert!(
        c1.get_tree()
            .await
            .iter()
            .any(|e| e.key == kc1 && e.parent == kc1),
        "c1 did not become its own root"
    );

    for n in [&a, &c1, &c2] {
        n.close().await.unwrap();
    }
}
