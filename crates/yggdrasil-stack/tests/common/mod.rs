//! Shared fixture: two embedded nodes peered over loopback, each with a stack.
#![allow(dead_code)]

use std::net::SocketAddrV6;
use std::time::Duration;

use yggdrasil::config::Config;
use yggdrasil::node::{Node, NodeBuilder};
use yggdrasil_stack::YggStack;

pub const TIMEOUT: Duration = Duration::from_secs(20);

pub struct Pair {
    pub a: Node,
    pub b: Node,
    pub sa: YggStack,
    pub sb: YggStack,
}

impl Pair {
    pub async fn new() -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let base = || {
            let mut c = Config::default();
            c.multicast_interfaces.clear();
            c.admin_listen = "none".into();
            c.if_name = "none".into();
            c
        };
        let mut ca = base();
        ca.listen = vec![format!("tcp://127.0.0.1:{port}")];
        let mut cb = base();
        cb.peers = vec![format!("tcp://127.0.0.1:{port}")];

        let a = NodeBuilder::new(ca).embedded().start().await.unwrap();
        let b = NodeBuilder::new(cb).embedded().start().await.unwrap();
        tokio::time::timeout(TIMEOUT, async {
            while a.core().get_peer_keys().await.is_empty()
                || b.core().get_peer_keys().await.is_empty()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("nodes did not peer");

        let sa = YggStack::new(&a).unwrap();
        let sb = YggStack::new(&b).unwrap();
        Pair { a, b, sa, sb }
    }

    pub fn b_addr(&self, port: u16) -> SocketAddrV6 {
        SocketAddrV6::new(self.sb.address(), port, 0, 0)
    }

    pub async fn close(self) {
        self.sa.close();
        self.sb.close();
        self.a.close().await;
        self.b.close().await;
    }
}

pub async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(TIMEOUT, f).await.expect("timed out")
}

