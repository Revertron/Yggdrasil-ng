//! End-to-end check of the embedded (TUN-less) node: two nodes peer over
//! loopback and exchange a raw IPv6 packet through `Node::rwc()`.

use std::time::Duration;

use yggdrasil::config::Config;
use yggdrasil::node::{Node, NodeBuilder};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn base_config() -> Config {
    let mut config = Config::default();
    config.multicast_interfaces.clear();
    config.admin_listen = "none".to_string();
    config.if_name = "none".to_string();
    config
}

async fn wait_for_peer(node: &Node) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while node.core().get_peer_keys().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("nodes did not peer");
}

/// Minimal IPv6 packet (no next header) carrying `payload`.
fn ipv6_packet(src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 40];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = 59; // No Next Header
    p[7] = 64;
    p[8..24].copy_from_slice(&src);
    p[24..40].copy_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn embedded_nodes_exchange_packets() {
    let port = free_port();

    let mut config_a = base_config();
    config_a.listen = vec![format!("tcp://127.0.0.1:{port}")];
    let a = NodeBuilder::new(config_a).embedded().start().await.unwrap();

    let mut config_b = base_config();
    config_b.peers = vec![format!("tcp://127.0.0.1:{port}")];
    let b = NodeBuilder::new(config_b).embedded().start().await.unwrap();

    wait_for_peer(&a).await;
    wait_for_peer(&b).await;
    assert_ne!(a.address().0, b.address().0);

    let packet = ipv6_packet(b.address().0, a.address().0, b"hello ygg");

    // The first packet may be buffered on a key lookup; resend until it lands.
    let reader = a.rwc().clone();
    let recv = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        reader.read(&mut buf).await.map(|p| p.to_vec())
    });
    let received = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            b.rwc().write(&packet).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            if recv.is_finished() {
                break recv.await.unwrap().unwrap();
            }
        }
    })
    .await
    .expect("packet was not delivered");

    assert_eq!(received, packet);

    b.close().await;
    a.close().await;
}

#[tokio::test]
async fn invalid_firewall_config_fails_start() {
    let mut config = base_config();
    config.firewall.enable = true;
    config.firewall.open_all_for = vec!["not a subnet".to_string()];
    let err = NodeBuilder::new(config).embedded().start().await.err();
    assert!(matches!(err, Some(yggdrasil::node::NodeError::Firewall(_))));
}

#[tokio::test]
async fn configured_key_is_used() {
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let expected = yggdrasil::address::addr_for_key(&key.verifying_key().to_bytes());
    let node = NodeBuilder::new(base_config())
        .embedded()
        .signing_key(key)
        .start()
        .await
        .unwrap();
    assert_eq!(node.address().0, expected.0);
    node.close().await;
}
