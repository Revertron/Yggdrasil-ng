use std::sync::Arc;
use std::time::Duration;

use crate::crypto::PublicKey;

/// Configuration for an ironwood PacketConn.
pub struct Config {
    /// How often to refresh our own tree announcement. Default: 4 minutes.
    pub router_refresh: Duration,
    /// Timeout before expiring a peer's tree info. Default: 5 minutes.
    pub router_timeout: Duration,
    /// Delay before sending a keepalive to idle peer. Default: 1 second.
    pub peer_keepalive_delay: Duration,
    /// Timeout before considering a peer dead. Default: 3 seconds.
    pub peer_timeout: Duration,
    /// Maximum size of a single peer message. Default: 1 MB.
    pub peer_max_message_size: u64,
    /// Optional transform applied to keys before bloom filter insertion.
    pub bloom_transform: Option<Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    /// Callback invoked when a new path is discovered.
    pub path_notify: Option<Arc<dyn Fn(PublicKey) + Send + Sync>>,
    /// Timeout before expiring a cached path. Default: 1 minute.
    pub path_timeout: Duration,
    /// Minimum interval between path lookups to the same destination. Default: 1 second.
    pub path_throttle: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            router_refresh: Duration::from_secs(4 * 60),
            router_timeout: Duration::from_secs(5 * 60),
            peer_keepalive_delay: Duration::from_secs(1),
            peer_timeout: Duration::from_secs(3),
            peer_max_message_size: 1024 * 1024,
            bloom_transform: None,
            path_notify: None,
            path_timeout: Duration::from_secs(60),
            path_throttle: Duration::from_secs(1),
        }
    }
}

impl Config {
    pub fn with_router_refresh(mut self, d: Duration) -> Self {
        self.router_refresh = d;
        self
    }

    pub fn with_router_timeout(mut self, d: Duration) -> Self {
        self.router_timeout = d;
        self
    }

    pub fn with_peer_keepalive_delay(mut self, d: Duration) -> Self {
        self.peer_keepalive_delay = d;
        self
    }

    pub fn with_peer_timeout(mut self, d: Duration) -> Self {
        self.peer_timeout = d;
        self
    }

    pub fn with_peer_max_message_size(mut self, size: u64) -> Self {
        self.peer_max_message_size = size;
        self
    }

    pub fn with_bloom_transform(
        mut self,
        f: impl Fn(PublicKey) -> PublicKey + Send + Sync + 'static,
    ) -> Self {
        self.bloom_transform = Some(Arc::new(f));
        self
    }

    pub fn with_path_notify(
        mut self,
        f: impl Fn(PublicKey) + Send + Sync + 'static,
    ) -> Self {
        self.path_notify = Some(Arc::new(f));
        self
    }

    pub fn with_path_timeout(mut self, d: Duration) -> Self {
        self.path_timeout = d;
        self
    }

    pub fn with_path_throttle(mut self, d: Duration) -> Self {
        self.path_throttle = d;
        self
    }
}
