//! A node with `debug_privacy` set doesn't answer other nodes' debug requests.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yggdrasil::config::Config;
use yggdrasil::core::Core;

async fn node(seed: u8, debug_privacy: bool) -> Arc<Core> {
    let config = Config {
        listen: Vec::new(),
        debug_privacy,
        ..Config::default()
    };
    let core = Core::new(SigningKey::from_bytes(&[seed; 32]), config);
    core.init_links().await;
    core.start().await;
    // Protocol messages are handled as traffic is read, which the TUN loop does
    // in the daemon.
    let reader = core.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while reader.read_from(&mut buf).await.is_ok() {}
    });
    core
}

/// Peers two nodes over loopback, then has one ask the other for its peers.
async fn ask_for_peers(debug_privacy: bool) -> (Result<Vec<[u8; 32]>, String>, [u8; 32]) {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let uri = format!("tcp://127.0.0.1:{port}");

    let asked = node(1, debug_privacy).await;
    asked.listen(&uri).await.unwrap();
    let asking = node(2, false).await;
    asking.add_peer(&uri).await.unwrap();

    for _ in 0..100 {
        if asking.get_peers().await.iter().any(|peer| peer.up) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let answer = asking
        .proto_handler()
        .send_get_peers_request(*asked.public_key())
        .await;
    (answer, *asking.public_key())
}

#[tokio::test]
async fn a_node_lists_its_peers_by_default() {
    let (answer, asking) = ask_for_peers(false).await;
    assert!(answer.unwrap().contains(&asking));
}

#[tokio::test]
async fn a_node_with_debug_privacy_does_not_answer() {
    let (answer, _) = ask_for_peers(true).await;
    assert!(answer.is_err(), "answered with {answer:?}");
}
