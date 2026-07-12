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
    PacketConnImpl,
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

// ---------------------------------------------------------------------------
// Diagnostic: instrument a cross-hub wedge at the plain ironwood layer.
// Uses unencrypted PacketConnImpl so diagnostic APIs are directly accessible.
// The routing/bloom/pathfinder bug is beneath encryption.
//
//   cargo test -p ironwood --test integration cross_hub_wedge_diagnostic -- --ignored --nocapture
// ---------------------------------------------------------------------------

async fn connect_plain(a: &Arc<PacketConnImpl>, b: &Arc<PacketConnImpl>) {
    let (sa, sb) = tokio::io::duplex(1 << 16);
    let addr_a = a.local_addr();
    let addr_b = b.local_addr();
    let a2 = Arc::clone(a);
    let b2 = Arc::clone(b);
    tokio::spawn(async move { let _ = a2.handle_conn(addr_b, Box::new(sa), 0).await; });
    tokio::spawn(async move { let _ = b2.handle_conn(addr_a, Box::new(sb), 0).await; });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic: instruments the cross-hub wedge; run with --ignored --nocapture"]
async fn cross_hub_wedge_diagnostic() {
    let trials = 30;
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

        // Settle
        tokio::time::sleep(Duration::from_secs(3)).await;

        let a2 = a.clone();
        let sender = tokio::spawn(async move {
            loop {
                let _ = a2.write_to(b"PING", &addr_d).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let d2 = d.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match d2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_a => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let result = tokio::time::timeout(Duration::from_secs(8), reader).await;
        sender.abort();

        let wedged = !matches!(result, Ok(Ok(true)));
        if wedged {
            eprintln!("\n=== WEDGE on trial {} ===", trial);

            let snap_a = a.get_debug_snapshot().await;
            eprintln!("A: tree_nodes={} routing_peers={} coords={:?} root={}",
                snap_a.tree_node_count, snap_a.routing_peer_count,
                snap_a.our_coords, hex::encode(&snap_a.tree_root[..8]));
            eprintln!("A: path_cache={} broken_paths={} pending_lookups={}",
                snap_a.path_cache_count, snap_a.broken_path_count,
                snap_a.pending_lookups.len());
            for pl in &snap_a.pending_lookups {
                eprintln!("  pending: dest={} xformed={} age={:.2}s sent={} targets={}",
                    pl.dest_key.map_or("none".into(), |k| hex::encode(&k[..8])),
                    hex::encode(&pl.xformed_key[..8]),
                    pl.age_secs, pl.sent, pl.multicast_count);
            }

            let (xd, targets) = a.count_lookup_targets(addr_d.0).await;
            eprintln!("A count_lookup_targets(D): xformed={} targets={}", hex::encode(&xd[..8]), targets);

            let paths_a = a.get_paths().await;
            eprintln!("A cached paths ({}):", paths_a.len());
            for p in &paths_a {
                eprintln!("  dest={} path={:?} seq={}", hex::encode(&p.key[..8]), p.path, p.sequence);
            }

            let snap_d = d.get_debug_snapshot().await;
            eprintln!("D: tree_nodes={} coords={:?} root={}",
                snap_d.tree_node_count, snap_d.our_coords, hex::encode(&snap_d.tree_root[..8]));

            let snap_h1 = h1.get_debug_snapshot().await;
            eprintln!("H1: tree_nodes={} coords={:?}", snap_h1.tree_node_count, snap_h1.our_coords);

            let snap_h2 = h2.get_debug_snapshot().await;
            eprintln!("H2: tree_nodes={} coords={:?}", snap_h2.tree_node_count, snap_h2.our_coords);

            for n in [&a, &h1, &h2, &d] { let _ = n.close().await; }
            return; // stop after first wedge
        }

        for n in [&a, &h1, &h2, &d] { let _ = n.close().await; }
        eprintln!("trial {}: ok", trial);
    }
    eprintln!("no wedge observed in {} trials", trials);
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

    // A в†” B
    let (_h1, _h2) = connect_nodes(&node_a, &node_b).await;
    // B в†” C
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

/// Dump a plain node's routing state (diagnostic).
async fn dump_plain(label: &str, n: &Arc<PacketConnImpl>, peer: [u8; 32]) {
    let s = n.get_debug_snapshot().await;
    eprintln!(
        "{}: coords={:?} root={} tree_nodes={} routing_peers={} path_cache={} broken={} pending={}",
        label, s.our_coords, hex::encode(&s.tree_root[..8]), s.tree_node_count,
        s.routing_peer_count, s.path_cache_count, s.broken_path_count, s.pending_lookups.len()
    );
    for pl in &s.pending_lookups {
        eprintln!(
            "  {} pending: dest={} xformed={} age={:.2}s sent={} targets={}",
            label,
            pl.dest_key.map_or("none".to_string(), |k| hex::encode(&k[..8])),
            hex::encode(&pl.xformed_key[..8]), pl.age_secs, pl.sent, pl.multicast_count
        );
    }
    let (xk, targets) = n.count_lookup_targets(peer).await;
    eprintln!("  {} count_lookup_targets(peer)={} xformed={}", label, targets, hex::encode(&xk[..8]));
    for p in n.get_paths().await {
        eprintln!("  {} cached-path dest={} path={:?} seq={}", label, hex::encode(&p.key[..8]), p.path, p.sequence);
    }
}

/// Plain-transport bidirectional cross-hub diagnostic. A<->H1<->H2<->D, both
/// endpoints send to each other after settle. Reproduces the encrypted wedge at
/// the pure-routing layer (no encryption) so it is locally debuggable: the
/// encrypted handshake needs BOTH directions (A->D INIT, D->A ACK), and the
/// failing direction is root->leaf. Prints per-direction failure counts and
/// dumps both endpoints' routing state on the first few wedges.
///
///   cargo test -p ironwood --test integration cross_hub_plain_bidirectional_diagnostic -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic: plain bidirectional cross-hub; run with --ignored --nocapture"]
async fn cross_hub_plain_bidirectional_diagnostic() {
    let trials = 30;
    let mut fwd_fail = 0;
    let mut ret_fail = 0;
    let mut dumped = 0;
    for trial in 0..trials {
        let a = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h1 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h2 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let d = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

        connect_plain(&a, &h1).await;
        connect_plain(&h1, &h2).await;
        connect_plain(&h2, &d).await;

        let addr_a = a.local_addr();
        let addr_d = d.local_addr();

        tokio::time::sleep(Duration::from_secs(3)).await;

        let d2 = d.clone();
        let d_reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match d2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_a => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });
        let a2 = a.clone();
        let a_reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match a2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_d => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let a3 = a.clone();
        let a_snd = tokio::spawn(async move {
            loop {
                let _ = a3.write_to(b"A2D", &addr_d).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });
        let d3 = d.clone();
        let d_snd = tokio::spawn(async move {
            loop {
                let _ = d3.write_to(b"D2A", &addr_a).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let (fwd, ret) = tokio::join!(
            timeout(Duration::from_secs(8), d_reader),
            timeout(Duration::from_secs(8), a_reader),
        );
        a_snd.abort();
        d_snd.abort();

        let fwd_ok = matches!(fwd, Ok(Ok(true)));
        let ret_ok = matches!(ret, Ok(Ok(true)));
        if !fwd_ok { fwd_fail += 1; }
        if !ret_ok { ret_fail += 1; }

        if (!fwd_ok || !ret_ok) && dumped < 3 {
            dumped += 1;
            let sa = a.get_debug_snapshot().await;
            let sd = d.get_debug_snapshot().await;
            eprintln!(
                "\n=== trial {} wedge: A2D_ok={} D2A_ok={} (A_root={} D_root={}) ===",
                trial, fwd_ok, ret_ok, sa.our_coords.is_empty(), sd.our_coords.is_empty()
            );
            dump_plain("A", &a, addr_d.0).await;
            dump_plain("D", &d, addr_a.0).await;
        }

        for n in [&a, &h1, &h2, &d] {
            let _ = n.close().await;
        }
    }
    eprintln!(
        "\ncross_hub_plain_bidirectional: A2D_fail={}/{} D2A_fail={}/{}",
        fwd_fail, trials, ret_fail, trials
    );
}

/// Faithful plain repro of the ENCRYPTED wedge: A keeps sending to D (like the
/// session INIT retry), and D replies EXACTLY ONCE the first time it hears from A
/// (like the reactive session ACK — no retry). Without the return-path fix, D's
/// one-shot lookup of A fails ~40% during convergence and the reply never arrives.
/// With `learn_path_from_traffic`, D already knows A's coords from the inbound
/// packet, so the reply routes immediately and the reply arrives every time.
///
///   cargo test -p ironwood --test integration cross_hub_plain_reactive_reply_diagnostic -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "repro of the reactive one-shot return-path wedge; run with --ignored --nocapture"]
async fn cross_hub_plain_reactive_reply_diagnostic() {
    let trials = 30;
    let mut fail = 0;
    for trial in 0..trials {
        let a = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h1 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h2 = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let d = new_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

        connect_plain(&a, &h1).await;
        connect_plain(&h1, &h2).await;
        connect_plain(&h2, &d).await;

        let addr_a = a.local_addr();
        let addr_d = d.local_addr();

        tokio::time::sleep(Duration::from_secs(3)).await;

        // D: on the FIRST packet from A, reply exactly once, then just drain.
        let d2 = d.clone();
        let d_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut replied = false;
            loop {
                match d2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_a && !replied => {
                        replied = true;
                        let _ = d2.write_to(b"PONG", &addr_a).await;
                    }
                    Ok(_) => continue,
                    Err(_) => return,
                }
            }
        });

        // A: keep sending PING to D (like the INIT retry cadence).
        let a3 = a.clone();
        let a_snd = tokio::spawn(async move {
            loop {
                let _ = a3.write_to(b"PING", &addr_d).await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        // A: wait for D's single PONG.
        let a2 = a.clone();
        let a_reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match a2.read_from(&mut buf).await {
                    Ok((n, from)) if n > 0 && from == addr_d => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let got = timeout(Duration::from_secs(8), a_reader).await;
        a_snd.abort();
        d_task.abort();

        if !matches!(got, Ok(Ok(true))) {
            fail += 1;
            eprintln!("trial {}: WEDGE (A never got the one-shot reply)", trial);
        }

        for n in [&a, &h1, &h2, &d] {
            let _ = n.close().await;
        }
    }
    eprintln!("\ncross_hub_plain_reactive_reply: {}/{} wedged", fail, trials);
}

/// Verifies that a PathLookup lost during tree/bloom convergence is retried by
/// the periodic maintenance tick. A sends ONE packet to D (no reply from D).
/// We settle for only 500ms so the first lookup races convergence; the retry
/// in `do_maintenance` must be what delivers it. Without the retry loop this
/// wedges; with it, every trial delivers.
///
/// Topology: A — H1 — H2 — D  (forward direction only; return path not tested here).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_hub_forward_discovery_retry() {
    // ponytail: 8 trials keeps the suite ~45s, not 2min. Each trial legitimately
    // needs several 1s retries to deliver (first lookup is often lost racing
    // convergence), so without the retry loop several would wedge — enough to
    // fail. Bump back toward 20 only if you want tighter statistical confidence.
    let trials = 20;
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
