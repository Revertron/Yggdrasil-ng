//! Node lifecycle: builds and wires a running Yggdrasil node.
//!
//! This is the single place that assembles the pieces of a node (`Core`, the
//! IPv6 `ReadWriteCloser`, firewall, TUN, admin socket, multicast discovery)
//! and tears them down in the right order. The daemon binary and embedders
//! (mobile apps, the userspace network stack, FFI) all go through it.
//!
//! ```no_run
//! # async fn demo() -> Result<(), yggdrasil::node::NodeError> {
//! use yggdrasil::config::Config;
//! use yggdrasil::node::NodeBuilder;
//!
//! // Embedded node: no TUN, no admin socket. Packets are exchanged with the
//! // network through `node.rwc()`.
//! let node = NodeBuilder::new(Config::default()).embedded().start().await?;
//! println!("address: {}", node.address());
//! node.close().await;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::task::JoinHandle;

use crate::address::{Address, Subnet};
use crate::admin::AdminSocket;
use crate::config::Config;
use crate::core::Core;
use crate::firewall::Firewall;
use crate::ipv6rwc::ReadWriteCloser;
#[cfg(feature = "tun")]
use crate::tun::TunAdapter;

/// How often directly-connected peer keys are pushed into the RWC key store.
const PEER_KEY_SEED_INTERVAL: Duration = Duration::from_secs(2);

/// Errors that can prevent a node from starting.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("invalid private key: {0}")]
    InvalidKey(String),
    #[error("firewall configuration error: {0}")]
    Firewall(String),
    #[error("failed to create TUN adapter: {0}")]
    Tun(String),
    #[error("failed to start admin socket: {0}")]
    Admin(String),
}

/// Configures and starts a [`Node`].
///
/// By default the optional components follow the config: TUN is created
/// unless `if_name` is `"none"`, the admin socket listens on `admin_listen`
/// (unless empty or `"none"`), and multicast discovery runs on the configured
/// `multicast_interfaces`. Each can be overridden with the setters.
pub struct NodeBuilder {
    config: Config,
    signing_key: Option<SigningKey>,
    #[cfg(feature = "tun")]
    tun: bool,
    admin: bool,
    admin_required: bool,
    multicast: bool,
}

impl NodeBuilder {
    pub fn new(config: Config) -> Self {
        Self {
            #[cfg(feature = "tun")]
            tun: config.if_name != "none",
            admin: true,
            admin_required: false,
            multicast: true,
            signing_key: None,
            config,
        }
    }

    /// Use this key instead of the one in `config.private_key`.
    ///
    /// Without it, the config key is used, and when the config has none an
    /// ephemeral key is generated.
    pub fn signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Enable or disable the TUN adapter.
    #[cfg(feature = "tun")]
    pub fn tun(mut self, enable: bool) -> Self {
        self.tun = enable;
        self
    }

    /// Enable or disable the admin socket.
    pub fn admin(mut self, enable: bool) -> Self {
        self.admin = enable;
        self
    }

    /// Fail [`start`](Self::start) when the admin socket cannot be bound,
    /// instead of logging a warning and carrying on without it.
    pub fn admin_required(mut self, required: bool) -> Self {
        self.admin_required = required;
        self
    }

    /// Enable or disable multicast peer discovery.
    pub fn multicast(mut self, enable: bool) -> Self {
        self.multicast = enable;
        self
    }

    /// Preset for embedding: no TUN and no admin socket.
    ///
    /// Traffic is exchanged as raw IPv6 packets through [`Node::rwc`].
    /// Multicast discovery still follows the config.
    pub fn embedded(self) -> Self {
        #[cfg(feature = "tun")]
        let this = self.tun(false);
        #[cfg(not(feature = "tun"))]
        let this = self;
        this.admin(false)
    }

    /// Start the node: bring up links and peers, then the optional components.
    ///
    /// On error everything started so far is shut down again.
    pub async fn start(self) -> Result<Node, NodeError> {
        let config = self.config;

        let signing_key = match self.signing_key {
            Some(key) => {
                if !ironwood::is_public_key_valid(&key.verifying_key().to_bytes()) {
                    return Err(NodeError::InvalidKey(
                        "public key is a low-order point".to_string(),
                    ));
                }
                key
            }
            None if !config.private_key.is_empty() => {
                config.signing_key().map_err(NodeError::InvalidKey)?
            }
            None => {
                tracing::warn!("No private key configured, generating ephemeral key");
                SigningKey::generate(&mut rand::rngs::OsRng)
            }
        };

        // Validate the firewall before anything is started, so a bad config
        // leaves nothing to tear down.
        let firewall = if config.firewall.enable {
            let fw = Firewall::new(&config.firewall).map_err(NodeError::Firewall)?;
            Some(Arc::new(fw))
        } else {
            None
        };

        let core = Core::new(signing_key, config.clone());
        tracing::info!("Your IPv6 address is {}", core.address());
        tracing::info!("Your IPv6 subnet is {}", core.subnet());
        tracing::info!("Your public key is {}", hex::encode(core.public_key()));
        tracing::info!("Salsa20 backend: {}", salsa20::active_backend());

        // Initialize links with core reference, then start listeners and
        // connect to peers.
        core.init_links().await;
        core.start().await;

        if let Some(fw) = &firewall {
            fw.spawn_gc();
            tracing::info!(
                "Firewall enabled: {} TCP open, {} UDP open, {} bypass subnets, icmp_echo={}",
                config.firewall.open_tcp.len(),
                config.firewall.open_udp.len(),
                config.firewall.open_all_for.len(),
                config.firewall.allow_icmp_echo
            );
        }

        // Create IPv6 RWC bridge
        let rwc = ReadWriteCloser::new(
            core.clone(),
            core.mtu(),
            #[cfg(feature = "ckr")]
            Some(&config.tunnel_routing),
            firewall,
        );

        // Wire up path_notify: when ironwood discovers a new path, update the key store
        core.set_path_notify(rwc.clone());

        let seed_task = spawn_peer_key_seeder(core.clone(), rwc.clone());

        let mut node = Node {
            core,
            rwc,
            config,
            seed_task,
            #[cfg(feature = "tun")]
            tun: None,
            admin: None,
        };

        #[cfg(feature = "tun")]
        if self.tun {
            if let Err(e) = node.start_tun().await {
                node.close().await;
                return Err(e);
            }
        } else {
            tracing::info!("TUN adapter disabled");
        }
        if let Err(e) = node.start_components(self.admin, self.admin_required, self.multicast).await {
            node.close().await;
            return Err(e);
        }

        tracing::info!("Yggdrasil NG started");
        Ok(node)
    }
}

/// Seed the key store with the keys of directly-connected peers. We authenticated
/// those keys during the link handshake, so their address/subnet mapping is already
/// derivable locally -- no reason to buffer the first packet and wait for a lookup
/// to tell us what we know. Combined with the router's direct-peer shortcut this
/// takes the first packet to a direct peer from three round trips down to two
/// (the remaining one being the session Init/Ack).
///
/// Re-run on a timer rather than hooking link setup: it picks up peers that connect
/// later, survives reconnects, and refreshes `last_seen` so entries can't age out
/// while the peer is up. `update_key` returns early for entries that are still
/// fresh, so a tick over an unchanged peer set is a couple of hashmap lookups.
fn spawn_peer_key_seeder(core: Arc<Core>, rwc: Arc<ReadWriteCloser>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PEER_KEY_SEED_INTERVAL);
        loop {
            ticker.tick().await;
            for key in core.get_peer_keys().await {
                rwc.update_key(key).await;
            }
        }
    })
}

/// A running Yggdrasil node.
///
/// Call [`close`](Self::close) to shut it down. Dropping a `Node` without
/// closing it stops only the background key seeding; links, listeners and
/// the TUN keep running until the tokio runtime goes away.
pub struct Node {
    core: Arc<Core>,
    rwc: Arc<ReadWriteCloser>,
    config: Config,
    seed_task: JoinHandle<()>,
    #[cfg(feature = "tun")]
    tun: Option<TunAdapter>,
    admin: Option<AdminSocket>,
}

impl Node {
    async fn start_components(
        &mut self,
        admin: bool,
        admin_required: bool,
        multicast: bool,
    ) -> Result<(), NodeError> {
        if admin {
            match AdminSocket::new(&self.config.admin_listen, self.core.clone()).await {
                Ok(socket) => self.admin = Some(socket),
                Err(e) if admin_required => return Err(NodeError::Admin(e)),
                Err(e) => tracing::warn!("Failed to start admin socket: {}", e),
            }
        }

        if multicast {
            if let Err(e) = self.core.start_multicast().await {
                tracing::warn!("Multicast peer discovery disabled: {}", e);
            }
        }
        Ok(())
    }

    #[cfg(feature = "tun")]
    async fn start_tun(&mut self) -> Result<(), NodeError> {
        let config = &self.config;
        let core = &self.core;
        let addr_str = core.address().to_string();
        let subnet_str = core.subnet().to_string();
        let tun_mtu = config.if_mtu.min(core.mtu()).min(65535) as u16;

        // A TUN that was requested but could not be created is an error rather
        // than a silently degraded, TUN-less node: under systemd Type=notify
        // this surfaces as a failed start (then Restart=always retries).
        let tun = TunAdapter::new(
            &config.if_name,
            self.rwc.clone(),
            &addr_str,
            &subnet_str,
            tun_mtu,
            #[cfg(windows)]
            &config.if_dns_servers,
            #[cfg(feature = "ckr")]
            Some(&config.tunnel_routing),
            #[cfg(feature = "ckr")]
            core.public_key(),
        )
        .await
        .map_err(NodeError::Tun)?;

        tracing::info!("TUN adapter started");
        core.set_tun_info(tun.name(), tun.mtu() as u64);
        self.tun = Some(tun);
        Ok(())
    }

    /// The node's core: peers, routing, sessions, admin-level queries.
    pub fn core(&self) -> &Arc<Core> {
        &self.core
    }

    /// IPv6 packet interface to the network.
    ///
    /// When the TUN adapter is running it owns the read side; embedders that
    /// pump packets themselves should start the node without TUN.
    pub fn rwc(&self) -> &Arc<ReadWriteCloser> {
        &self.rwc
    }

    /// The configuration the node was started with.
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn address(&self) -> &Address {
        self.core.address()
    }

    pub fn subnet(&self) -> &Subnet {
        self.core.subnet()
    }

    pub fn public_key(&self) -> &[u8; 32] {
        self.core.public_key()
    }

    /// Name of the TUN interface, if one is running.
    #[cfg(feature = "tun")]
    pub fn tun_name(&self) -> Option<&str> {
        self.tun.as_ref().map(|t| t.name())
    }

    /// Shut the node down and wait for its components to stop.
    #[cfg_attr(not(feature = "tun"), allow(unused_mut))]
    pub async fn close(mut self) {
        self.seed_task.abort();

        // Remove CKR routes before TUN is destroyed (critical on Windows where
        // routes don't auto-dissolve when the interface goes away).
        // Use the name the adapter got, not a second derivation of if_name.
        #[cfg(all(feature = "ckr", feature = "tun"))]
        if self.config.tunnel_routing.enable {
            if let Some(adapter) = self.tun.as_ref() {
                crate::ckr::remove_routes(
                    &self.config.tunnel_routing,
                    adapter.name(),
                    self.core.public_key(),
                );
            }
        }

        // Tear down TUN explicitly so the OS interface is removed before this
        // function returns. Dropping TunAdapter alone is not enough: its tokio
        // tasks each hold an Arc<AsyncDevice>, and dropping a JoinHandle does
        // not abort the task — it only detaches it. Without an explicit close
        // we'd rely on the runtime drop to abort the tasks, which is too late
        // in Windows service mode (the SCM may kill the process after we report
        // Stopped, leaving an orphaned Wintun adapter).
        //
        // This happens before core.close() on purpose: the TUN write loop parks
        // in rwc.read(), so closing the core first pulls the RWC out from under
        // it and every clean shutdown logs a spurious "RWC read error".
        #[cfg(feature = "tun")]
        if let Some(t) = self.tun.take() {
            t.close().await;
        }

        self.core.close_multicast().await;
        if let Some(admin) = self.admin.take() {
            admin.close();
        }
        self.core.close().await.ok();
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.seed_task.abort();
    }
}
