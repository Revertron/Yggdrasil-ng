//! Spanning tree CRDT router.
//!
//! Implements greedy routing over a spanning tree embedding using ed25519 keys.
//! The tree is maintained as a soft-state CRDT with gossip protocol.
//!
//! Key algorithms:
//! - Root election: lexicographically smallest ed25519 key
//! - Parent selection: minimize (tree_distance_to_root × link_latency)
//! - Greedy routing: forward to neighbor closest in tree-space to destination
//! - Announcements: gossip ancestry info to peers

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::bloom::Blooms;
use crate::crypto::{Crypto, PublicKey, Sig};
use crate::pathfinder::Pathfinder;
use crate::wire::{self, PeerPort};

/// Unknown latency sentinel (high but won't overflow in multiplication).
const UNKNOWN_LATENCY: Duration = Duration::from_millis(u32::MAX as u64);

// ---------------------------------------------------------------------------
// Router-level types
// ---------------------------------------------------------------------------

/// Unique identifier for a peer connection.
pub(crate) type PeerId = u64;

/// Stored tree state for a known node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouterInfo {
    pub parent: PublicKey,
    pub seq: u64,
    pub nonce: u64,
    pub port: PeerPort,
    pub psig: Sig,
    pub sig: Sig,
}

impl RouterInfo {
    /// Reconstruct announcement from stored info.
    pub fn get_announce(&self, key: PublicKey) -> RouterAnnounce {
        RouterAnnounce {
            key,
            parent: self.parent,
            seq: self.seq,
            nonce: self.nonce,
            port: self.port,
            psig: self.psig,
            sig: self.sig,
        }
    }
}

/// A tree announcement message (internal representation).
#[derive(Clone, Debug)]
pub(crate) struct RouterAnnounce {
    pub key: PublicKey,
    pub parent: PublicKey,
    pub seq: u64,
    pub nonce: u64,
    pub port: PeerPort,
    pub psig: Sig,
    pub sig: Sig,
}

impl RouterAnnounce {
    /// Compute bytes for the signature: node || parent || seq || nonce || port
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 20);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.parent);
        wire::encode_uvarint(&mut out, self.seq);
        wire::encode_uvarint(&mut out, self.nonce);
        wire::encode_uvarint(&mut out, self.port);
        out
    }

    /// Verify signatures on the announcement.
    pub fn check(&self) -> bool {
        if self.port == 0 && self.key != self.parent {
            return false;
        }
        let bs = self.bytes_for_sig();
        Crypto::verify(&self.key, &bs, &self.sig)
            && Crypto::verify(&self.parent, &bs, &self.psig)
    }

    /// Convert to wire format.
    pub fn to_wire(&self) -> wire::Announce {
        wire::Announce {
            key: self.key,
            parent: self.parent,
            sig_res: wire::SigRes {
                seq: self.seq,
                nonce: self.nonce,
                port: self.port,
                psig: self.psig,
            },
            sig: self.sig,
        }
    }

    /// Convert from wire format.
    pub fn from_wire(ann: &wire::Announce) -> Self {
        Self {
            key: ann.key,
            parent: ann.parent,
            seq: ann.sig_res.seq,
            nonce: ann.sig_res.nonce,
            port: ann.sig_res.port,
            psig: ann.sig_res.psig,
            sig: ann.sig,
        }
    }
}

/// Minimal peer info needed by the router for routing decisions.
#[derive(Clone, Debug)]
pub(crate) struct PeerEntry {
    pub id: PeerId,
    pub key: PublicKey,
    pub port: PeerPort,
    pub prio: u8,
    pub order: u64,
}

/// Signature request (seq + nonce).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigReqState {
    pub seq: u64,
    pub nonce: u64,
}

/// Signature response state.
#[derive(Clone, Debug)]
pub(crate) struct SigResState {
    pub seq: u64,
    pub nonce: u64,
    pub port: PeerPort,
    pub psig: Sig,
}

// ---------------------------------------------------------------------------
// Outbound actions: things the router wants the networking layer to do
// ---------------------------------------------------------------------------

/// Actions the router produces that the networking layer must execute.
#[derive(Debug)]
pub(crate) enum RouterAction {
    /// Send a signature request to a specific peer.
    SendSigReq {
        peer_id: PeerId,
        req: wire::SigReq,
    },
    /// Send a signature response to a specific peer.
    SendSigRes {
        peer_id: PeerId,
        res: wire::SigRes,
    },
    /// Send an announcement to a specific peer.
    SendAnnounce {
        peer_id: PeerId,
        ann: wire::Announce,
    },
    /// Send a bloom filter to a specific peer.
    SendBloom {
        peer_id: PeerId,
        bloom: crate::bloom::BloomFilter,
    },
    /// Send traffic to a specific peer.
    SendTraffic {
        peer_id: PeerId,
        traffic: crate::traffic::TrafficPacket,
    },
    /// Send a path notify to a specific peer.
    SendPathNotify {
        peer_id: PeerId,
        notify: wire::PathNotify,
    },
    /// Send a path lookup to a specific peer.
    SendPathLookup {
        peer_id: PeerId,
        lookup: wire::PathLookup,
    },
    /// Send a path broken to a specific peer.
    SendPathBroken {
        peer_id: PeerId,
        broken: wire::PathBroken,
    },
    /// Deliver traffic to the local application.
    DeliverTraffic {
        traffic: crate::traffic::TrafficPacket,
    },
    /// Notify application of new path.
    PathNotifyCallback {
        key: PublicKey,
    },
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// The spanning tree CRDT router.
///
/// Maintains tree state, handles announcements, performs greedy routing,
/// and coordinates bloom filters and path discovery.
pub(crate) struct Router {
    // Identity
    pub crypto: Crypto,

    // Sub-components
    pub pathfinder: Pathfinder,
    pub blooms: Blooms,

    // Peer tracking
    /// All peer connections grouped by public key.
    pub peers: HashMap<PublicKey, HashMap<PeerId, PeerEntry>>,
    /// What info we've sent to each peer (by their key).
    pub sent: HashMap<PublicKey, HashSet<PublicKey>>,
    /// Port -> public key mapping (for tree lookups).
    pub ports: HashMap<PeerPort, PublicKey>,

    // Tree state
    /// Known tree info for each node.
    pub infos: HashMap<PublicKey, RouterInfo>,
    /// When each node's info was last refreshed.
    pub info_times: HashMap<PublicKey, Instant>,
    /// Ancestry info per peer.
    pub ancs: HashMap<PublicKey, Vec<PublicKey>>,
    /// Cached path (coords) for each peer.
    pub cache: HashMap<PublicKey, Vec<PeerPort>>,

    // Latency tracking
    pub lags: HashMap<PeerId, Duration>,

    // Signature protocol
    pub requests: HashMap<PublicKey, SigReqState>,
    pub responses: HashMap<PublicKey, SigResState>,
    pub responded: HashSet<PeerId>,
    pub res_seqs: HashMap<PublicKey, u64>,
    pub res_seq_ctr: u64,

    // Flags
    pub refresh: bool,
    pub do_root1: bool,
    pub do_root2: bool,
    pub last_refresh: Instant,

    // Config
    pub router_refresh: Duration,
    pub router_timeout: Duration,
    pub path_timeout: Duration,
    pub path_throttle: Duration,
    pub bloom_transform: Option<std::sync::Arc<dyn Fn(PublicKey) -> PublicKey + Send + Sync>>,
    pub path_notify_cb: Option<std::sync::Arc<dyn Fn(PublicKey) + Send + Sync>>,
}

impl Router {
    pub fn new(crypto: Crypto, config: &crate::config::Config) -> Self {
        let pathfinder = Pathfinder::new(&crypto);
        Self {
            crypto,
            pathfinder,
            blooms: Blooms::new(),
            peers: HashMap::new(),
            sent: HashMap::new(),
            ports: HashMap::new(),
            infos: HashMap::new(),
            info_times: HashMap::new(),
            ancs: HashMap::new(),
            cache: HashMap::new(),
            lags: HashMap::new(),
            requests: HashMap::new(),
            responses: HashMap::new(),
            responded: HashSet::new(),
            res_seqs: HashMap::new(),
            res_seq_ctr: 0,
            refresh: false,
            do_root1: false,
            do_root2: true,
            last_refresh: Instant::now(),
            router_refresh: config.router_refresh,
            router_timeout: config.router_timeout,
            path_timeout: config.path_timeout,
            path_throttle: config.path_throttle,
            bloom_transform: config.bloom_transform.clone(),
            path_notify_cb: config.path_notify.clone(),
        }
    }

    // -----------------------------------------------------------------------
    // Maintenance
    // -----------------------------------------------------------------------

    /// Periodic maintenance (called every ~1 second).
    /// Returns a list of actions to execute.
    pub fn do_maintenance(&mut self) -> Vec<RouterAction> {
        let mut actions = Vec::new();

        // Check if it's time to refresh (send periodic SigReq to all peers)
        // This triggers keepalive timers on Go peers and refreshes routing info
        if self.last_refresh.elapsed() >= self.router_refresh {
            tracing::debug!("Router refresh timer expired, triggering refresh");
            self.refresh = true;
            self.last_refresh = Instant::now();
        }

        self.do_root2 = self.do_root2 || self.do_root1;
        self.reset_cache();
        self.update_ancestries();
        actions.extend(self.fix());
        actions.extend(self.send_announces());
        actions.extend(self.blooms_maintenance());
        self.pathfinder.cleanup_expired(self.path_timeout);
        actions
    }

    fn reset_cache(&mut self) {
        self.cache.clear();
    }

    fn update_ancestries(&mut self) {
        let peer_keys: Vec<PublicKey> = self.peers.keys().copied().collect();
        for pkey in peer_keys {
            let anc = self.get_ancestry(&pkey);
            let old = self.ancs.get(&pkey);
            let diff = old.map_or(true, |o| o != &anc);
            if diff {
                self.ancs.insert(pkey, anc);
            }
        }
    }

    fn blooms_maintenance(&mut self) -> Vec<RouterAction> {
        let self_key = self.crypto.public_key;
        let self_parent = self
            .infos
            .get(&self_key)
            .map(|i| i.parent)
            .unwrap_or(self_key);

        // Build parent map for fix_on_tree
        let parent_map: HashMap<PublicKey, PublicKey> = self
            .infos
            .iter()
            .map(|(k, v)| (*k, v.parent))
            .collect();

        let to_send = self.blooms.do_maintenance(
            &self_key,
            &self_parent,
            &parent_map,
            &self.bloom_transform,
        );

        let mut actions = Vec::new();
        for (peer_key, bloom) in to_send {
            if let Some(peers) = self.peers.get(&peer_key) {
                for (_, entry) in peers {
                    actions.push(RouterAction::SendBloom {
                        peer_id: entry.id,
                        bloom: bloom.clone(),
                    });
                }
            }
        }
        actions
    }

    // -----------------------------------------------------------------------
    // Peer management
    // -----------------------------------------------------------------------

    /// Add a peer connection. Returns actions to execute.
    pub fn add_peer(&mut self, entry: PeerEntry) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        let key = entry.key;
        let peer_id = entry.id;

        if !self.peers.contains_key(&key) {
            self.peers.insert(key, HashMap::new());
            self.sent.insert(key, HashSet::new());
            self.ports.insert(entry.port, key);
            self.blooms.add_info(key);
        } else {
            // Send already-sent announcements to new connection
            if let Some(sent_keys) = self.sent.get(&key) {
                let sent_keys: Vec<PublicKey> = sent_keys.iter().copied().collect();
                for k in sent_keys {
                    if let Some(info) = self.infos.get(&k) {
                        actions.push(RouterAction::SendAnnounce {
                            peer_id,
                            ann: info.get_announce(k).to_wire(),
                        });
                    }
                }
            }
        }

        self.peers
            .get_mut(&key)
            .unwrap()
            .insert(entry.id, entry);
        self.lags.insert(peer_id, UNKNOWN_LATENCY);

        // Send sig request
        if !self.requests.contains_key(&key) {
            self.requests.insert(key, self.new_req());
        }
        let req = self.requests[&key].clone();
        self.responded.remove(&peer_id);
        actions.push(RouterAction::SendSigReq {
            peer_id,
            req: wire::SigReq {
                seq: req.seq,
                nonce: req.nonce,
            },
        });

        // Send bloom
        if let Some(bloom) = self.blooms.get_send_bloom(&key) {
            actions.push(RouterAction::SendBloom {
                peer_id,
                bloom,
            });
        }

        actions
    }

    /// Remove a peer connection. Returns actions to execute.
    pub fn remove_peer(&mut self, peer_id: PeerId, key: PublicKey, port: PeerPort) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        self.lags.remove(&peer_id);
        self.responded.remove(&peer_id);

        if let Some(peers) = self.peers.get_mut(&key) {
            peers.remove(&peer_id);
            if peers.is_empty() {
                self.peers.remove(&key);
                self.sent.remove(&key);
                self.ports.remove(&port);
                self.requests.remove(&key);
                self.responses.remove(&key);
                self.res_seqs.remove(&key);
                self.ancs.remove(&key);
                self.cache.remove(&key);
                self.blooms.remove_info(&key);
            } else {
                // Resend bloom to remaining peers
                if let Some(bloom) = self.blooms.get_send_bloom(&key) {
                    for (_, entry) in peers.iter() {
                        actions.push(RouterAction::SendBloom {
                            peer_id: entry.id,
                            bloom: bloom.clone(),
                        });
                    }
                }
            }
        }

        actions
    }

    // -----------------------------------------------------------------------
    // Signature protocol
    // -----------------------------------------------------------------------

    fn new_req(&self) -> SigReqState {
        let nonce = rand::random::<u64>();
        let seq = self
            .infos
            .get(&self.crypto.public_key)
            .map_or(0, |i| i.seq)
            + 1;
        SigReqState { seq, nonce }
    }

    /// Handle an incoming signature request from a peer.
    pub fn handle_request(&self, peer: &PeerEntry) -> RouterAction {
        // We always respond with a signature for the requesting peer
        let req = self.requests.get(&peer.key);
        let (seq, nonce) = req.map_or((0, 0), |r| (r.seq, r.nonce));

        let res_bytes = Self::sig_res_bytes_for_sig(&peer.key, &self.crypto.public_key, seq, nonce, peer.port);
        let psig = self.crypto.sign(&res_bytes);

        RouterAction::SendSigRes {
            peer_id: peer.id,
            res: wire::SigRes {
                seq,
                nonce,
                port: peer.port,
                psig,
            },
        }
    }

    /// Handle an incoming signature request with explicit req data.
    pub fn handle_request_with_data(&self,peer: &PeerEntry, req: &wire::SigReq) -> RouterAction {
        let res_bytes = Self::sig_res_bytes_for_sig(&peer.key, &self.crypto.public_key, req.seq, req.nonce, peer.port);
        let psig = self.crypto.sign(&res_bytes);

        RouterAction::SendSigRes {
            peer_id: peer.id,
            res: wire::SigRes {
                seq: req.seq,
                nonce: req.nonce,
                port: peer.port,
                psig,
            },
        }
    }

    fn sig_res_bytes_for_sig(node: &PublicKey, parent: &PublicKey, seq: u64, nonce: u64, port: PeerPort) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 20);
        out.extend_from_slice(node);
        out.extend_from_slice(parent);
        wire::encode_uvarint(&mut out, seq);
        wire::encode_uvarint(&mut out, nonce);
        wire::encode_uvarint(&mut out, port);
        out
    }

    /// Handle a signature response from a peer.
    pub fn handle_response(&mut self,peer_id: PeerId, key: &PublicKey, res: &wire::SigRes, rtt: Duration) {
        let req_match = self
            .requests
            .get(key)
            .map_or(false, |r| r.seq == res.seq && r.nonce == res.nonce);

        if !self.responses.contains_key(key) && req_match {
            tracing::debug!("SigRes accepted from {:?}, rtt={:?}", hex::encode(&key[..4]), rtt);
            self.res_seq_ctr += 1;
            self.res_seqs.insert(*key, self.res_seq_ctr);
            self.responses.insert(
                *key,
                SigResState {
                    seq: res.seq,
                    nonce: res.nonce,
                    port: res.port,
                    psig: res.psig,
                },
            );
        }

        if !self.responded.contains(&peer_id) && req_match {
            self.responded.insert(peer_id);
            let lag = self.lags.get(&peer_id).copied().unwrap_or(UNKNOWN_LATENCY);
            let new_lag = if lag == UNKNOWN_LATENCY {
                rtt * 2 // penalty for new links
            } else {
                let prev = lag;
                let mut l = lag * 7 / 8;
                l += rtt.min(prev * 2) / 8;
                l
            };
            self.lags.insert(peer_id, new_lag);
        }
    }

    // -----------------------------------------------------------------------
    // Tree update & fix
    // -----------------------------------------------------------------------

    /// Process a tree announcement. Returns true if accepted.
    pub fn update(&mut self, ann: &RouterAnnounce) -> bool {
        if let Some(info) = self.infos.get(&ann.key) {
            // CRDT ordering: same logic as Go — DO NOT CHANGE
            match () {
                _ if info.seq > ann.seq => return false,
                _ if info.seq < ann.seq => {}
                _ if info.parent < ann.parent => return false,
                _ if ann.parent < info.parent => {}
                _ if ann.nonce < info.nonce => {}
                _ => return false,
            }
        }

        // Clean up sent info
        for sent in self.sent.values_mut() {
            sent.remove(&ann.key);
        }
        self.reset_cache();

        // Save info
        let info = RouterInfo {
            parent: ann.parent,
            seq: ann.seq,
            nonce: ann.nonce,
            port: ann.port,
            psig: ann.psig,
            sig: ann.sig,
        };
        self.infos.insert(ann.key, info);
        self.info_times.insert(ann.key, Instant::now());

        true
    }

    /// Handle an announcement from a peer.
    pub fn handle_announce(&mut self,peer_id: PeerId, peer_key: &PublicKey, ann: &RouterAnnounce) -> Vec<RouterAction> {
        let mut actions = Vec::new();

        if self.update(ann) {
            tracing::debug!("Announce accepted: key={:?} parent={:?} seq={}", hex::encode(&ann.key[..8]), hex::encode(&ann.parent[..8]), ann.seq);
            if ann.key == self.crypto.public_key {
                tracing::debug!("Announce for self accepted, setting refresh=true (from peer {:?}, seq={})", hex::encode(&ann.parent[..8]), ann.seq);
                self.refresh = true;
            }
            if let Some(sent) = self.sent.get_mut(peer_key) {
                sent.insert(ann.key);
            }
        } else {
            // We didn't accept — send back what we know if it's different
            let info = RouterInfo {
                parent: ann.parent,
                seq: ann.seq,
                nonce: ann.nonce,
                port: ann.port,
                psig: ann.psig,
                sig: ann.sig,
            };
            if let Some(old_info) = self.infos.get(&ann.key) {
                if *old_info != info {
                    if let Some(sent) = self.sent.get_mut(peer_key) {
                        sent.insert(ann.key);
                    }
                    actions.push(RouterAction::SendAnnounce {
                        peer_id,
                        ann: old_info.get_announce(ann.key).to_wire(),
                    });
                } else {
                    if let Some(sent) = self.sent.get_mut(peer_key) {
                        sent.insert(ann.key);
                    }
                }
            }
        }

        actions
    }

    /// Become root: create self-signed announcement.
    fn become_root(&mut self) -> bool {
        let req = self.new_req();
        let self_key = self.crypto.public_key;

        // Sign as parent (self-rooted: node == parent)
        let res_bytes = Self::sig_res_bytes_for_sig(&self_key, &self_key, req.seq, req.nonce, 0);
        let psig = self.crypto.sign(&res_bytes);

        let ann = RouterAnnounce {
            key: self_key,
            parent: self_key,
            seq: req.seq,
            nonce: req.nonce,
            port: 0,
            psig,
            sig: psig, // self-signed: sig == psig
        };

        debug_assert!(ann.check());
        self.update(&ann)
    }

    /// Use a signature response to set a new parent.
    fn use_response(&mut self, peer_key: &PublicKey, res: &SigResState) -> bool {
        let self_key = self.crypto.public_key;
        let bs = Self::sig_res_bytes_for_sig(&self_key, peer_key, res.seq, res.nonce, res.port);
        let sig = self.crypto.sign(&bs);

        let ann = RouterAnnounce {
            key: self_key,
            parent: *peer_key,
            seq: res.seq,
            nonce: res.nonce,
            port: res.port,
            psig: res.psig,
            sig,
        };

        self.update(&ann)
    }

    /// Parent selection: choose the best root and parent.
    fn fix(&mut self) -> Vec<RouterAction> {
        let self_key = self.crypto.public_key;
        let mut best_root = self_key;
        let mut best_parent = self_key;
        let mut best_cost = u64::MAX;

        let self_info_parent = self.infos.get(&self_key).map(|i| i.parent).unwrap_or(self_key);

        // Check current parent
        if self.peers.contains_key(&self_info_parent) {
            let (root, dists) = self.get_root_and_dists(&self_key);
            if root < best_root {
                let mut cost = u64::MAX;
                if let Some(peers) = self.peers.get(&self_info_parent) {
                    for (_, entry) in peers {
                        let dist_to_root = dists.get(&root).copied().unwrap_or(u64::MAX);
                        let c = dist_to_root.saturating_mul(self.get_cost(entry.id));
                        if c < cost {
                            cost = c;
                        }
                    }
                }
                best_root = root;
                best_parent = self_info_parent;
                best_cost = cost;
            }
        }

        // Check all peers with responses
        let response_keys: Vec<PublicKey> = self.responses.keys().copied().collect();
        for pk in response_keys {
            if !self.infos.contains_key(&pk) {
                continue;
            }
            let (p_root, p_dists) = self.get_root_and_dists(&pk);
            if p_dists.contains_key(&self_key) {
                continue; // would loop
            }
            let mut cost = u64::MAX;
            if let Some(peers) = self.peers.get(&pk) {
                for (_, entry) in peers {
                    let dist_to_root = p_dists.get(&p_root).copied().unwrap_or(u64::MAX);
                    let c = dist_to_root.saturating_mul(self.get_cost(entry.id));
                    if c < cost {
                        cost = c;
                    }
                }
            }
            if p_root < best_root {
                best_root = p_root;
                best_parent = pk;
                best_cost = cost;
            } else if p_root != best_root {
                continue;
            }
            if (self.refresh && cost * 2 < best_cost)
                || (best_parent != self_info_parent && cost < best_cost)
            {
                best_root = p_root;
                best_parent = pk;
                best_cost = cost;
            }
        }

        let mut actions = Vec::new();

        if self.refresh || self.do_root1 || self.do_root2 || self_info_parent != best_parent {
            tracing::debug!(
                "fix: entering change block: refresh={} do_root1={} do_root2={} parent_changed={} best_parent={:?} best_root={:?}",
                self.refresh, self.do_root1, self.do_root2,
                self_info_parent != best_parent,
                hex::encode(&best_parent[..8]), hex::encode(&best_root[..8]),
            );
            let res = self.responses.get(&best_parent).cloned();
            if let Some(res) = res {
                if best_root != self_key && self.use_response(&best_parent, &res) {
                    tracing::debug!("Tree: adopted parent {:?}, root {:?}", hex::encode(&best_parent[..8]), hex::encode(&best_root[..8]));
                    self.refresh = false;
                    self.do_root1 = false;
                    self.do_root2 = false;
                    actions.extend(self.send_reqs());
                    return actions;
                }
                tracing::debug!("fix: use_response failed for {:?}", hex::encode(&best_parent[..8]));
            } else {
                tracing::debug!("fix: no response for best_parent {:?}", hex::encode(&best_parent[..8]));
            }

            if self.do_root2 {
                tracing::debug!("Tree: becoming root (self-rooted)");
                self.become_root();
                self.refresh = false;
                self.do_root1 = false;
                self.do_root2 = false;
                actions.extend(self.send_reqs());
            } else if !self.do_root1 {
                tracing::debug!("fix: setting do_root1=true");
                self.do_root1 = true;
            }
        }

        actions
    }

    fn send_reqs(&mut self) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        self.clear_reqs();
        let peer_keys: Vec<(PublicKey, Vec<PeerId>)> = self
            .peers
            .iter()
            .map(|(k, ps)| (*k, ps.keys().copied().collect()))
            .collect();

        for (pk, peer_ids) in peer_keys {
            let req = self.new_req();
            self.requests.insert(pk, req.clone());
            for peer_id in peer_ids {
                self.responded.remove(&peer_id);
                actions.push(RouterAction::SendSigReq {
                    peer_id,
                    req: wire::SigReq {
                        seq: req.seq,
                        nonce: req.nonce,
                    },
                });
            }
        }
        actions
    }

    fn clear_reqs(&mut self) {
        self.requests.clear();
        self.responses.clear();
        self.res_seqs.clear();
        self.res_seq_ctr = 0;
    }

    // -----------------------------------------------------------------------
    // Announcements
    // -----------------------------------------------------------------------

    fn send_announces(&mut self) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        let self_key = self.crypto.public_key;
        let self_anc = self.get_ancestry(&self_key);

        let peer_keys: Vec<PublicKey> = self.sent.keys().copied().collect();
        for peer_key in peer_keys {
            let peer_anc = self.get_ancestry(&peer_key);

            let mut to_send = Vec::new();
            let sent = self.sent.get_mut(&peer_key).unwrap();

            for k in &self_anc {
                if !sent.contains(k) {
                    to_send.push(*k);
                    sent.insert(*k);
                }
            }
            for k in &peer_anc {
                if !sent.contains(k) {
                    to_send.push(*k);
                    sent.insert(*k);
                }
            }

            // Prepare announcements
            let anns: Vec<wire::Announce> = to_send
                .iter()
                .filter_map(|k| self.infos.get(k).map(|info| info.get_announce(*k).to_wire()))
                .collect();

            // Send to all peer connections
            if let Some(peers) = self.peers.get(&peer_key) {
                for (_, entry) in peers {
                    for ann in &anns {
                        tracing::debug!(
                            "Sending announce to peer {:?}: key={:?} parent={:?} seq={}",
                            hex::encode(&peer_key[..4]),
                            hex::encode(&ann.key[..4]),
                            hex::encode(&ann.parent[..4]),
                            ann.sig_res.seq
                        );
                        actions.push(RouterAction::SendAnnounce {
                            peer_id: entry.id,
                            ann: ann.clone(),
                        });
                    }
                }
            }
        }

        actions
    }

    // -----------------------------------------------------------------------
    // Tree traversal
    // -----------------------------------------------------------------------

    /// Get root and distances from a starting node.
    pub fn get_root_and_dists(&self, dest: &PublicKey) -> (PublicKey, HashMap<PublicKey, u64>) {
        let mut dists = HashMap::new();
        let mut next = *dest;
        let mut root = [0u8; 32];
        let mut dist = 0u64;

        loop {
            if dists.contains_key(&next) {
                break;
            }
            if let Some(info) = self.infos.get(&next) {
                root = next;
                dists.insert(next, dist);
                dist += 1;
                next = info.parent;
            } else {
                break;
            }
        }

        (root, dists)
    }

    /// Get root and path (coordinates) from root to destination.
    pub fn get_root_and_path(&self, dest: &PublicKey) -> (PublicKey, Vec<PeerPort>) {
        let mut ports = Vec::new();
        let mut visited = HashSet::new();
        let mut root;
        let mut next = *dest;

        loop {
            if visited.contains(&next) {
                return (*dest, Vec::new()); // loop detected
            }
            if let Some(info) = self.infos.get(&next) {
                root = next;
                visited.insert(next);
                if next == info.parent {
                    break; // reached root
                }
                ports.push(info.port);
                next = info.parent;
            } else {
                return (*dest, Vec::new()); // dead end
            }
        }

        ports.reverse();
        (root, ports)
    }

    /// Get distance between a path and a key in tree-space.
    fn get_dist(&mut self, dest_path: &[PeerPort], key: &PublicKey) -> u64 {
        let key_path = if let Some(cached) = self.cache.get(key) {
            cached.clone()
        } else {
            let (_, path) = self.get_root_and_path(key);
            self.cache.insert(*key, path.clone());
            path
        };

        let end = dest_path.len().min(key_path.len());
        let mut dist = (key_path.len() + dest_path.len()) as u64;
        for idx in 0..end {
            if key_path[idx] == dest_path[idx] {
                dist -= 2;
            } else {
                break;
            }
        }
        dist
    }

    fn get_cost(&self, peer_id: PeerId) -> u64 {
        let lag = self.lags.get(&peer_id).copied().unwrap_or(UNKNOWN_LATENCY);
        let c = lag.as_millis() as u64;
        if c == 0 { 1 } else { c }
    }

    /// Greedy routing lookup: find the best next-hop peer.
    pub fn lookup(&mut self, path: &[PeerPort], watermark: &mut u64) -> Option<PeerId> {
        let self_key = self.crypto.public_key;
        let self_dist = self.get_dist(path, &self_key);
        if self_dist >= *watermark {
            return None;
        }
        let mut best_dist = self_dist;
        *watermark = self_dist;

        tracing::debug!("Lookup path {:?}", path);

        // Collect candidates: peers closer than us
        let mut candidates: Vec<PeerEntry> = Vec::new();
        let peer_keys: Vec<PublicKey> = self.peers.keys().copied().collect();
        for k in &peer_keys {
            let dist = self.get_dist(path, k);
            if dist < best_dist {
                if let Some(peers) = self.peers.get(k) {
                    for (_, entry) in peers {
                        candidates.push(entry.clone());
                    }
                }
            }
        }

        // Find best candidate
        let mut best_peer: Option<PeerEntry> = None;
        let mut best_cost = u64::MAX;
        best_dist = u64::MAX;

        for p in &candidates {
            let dist = self.get_dist(path, &p.key);
            let cost = self.get_cost(p.id);

            let accept = |bp: &mut Option<PeerEntry>, bc: &mut u64, bd: &mut u64| {
                *bp = Some(p.clone());
                *bc = cost;
                *bd = dist;
            };

            match best_peer {
                None => accept(&mut best_peer, &mut best_cost, &mut best_dist),
                Some(ref bp) => {
                    if p.key == bp.key && p.prio < bp.prio {
                        accept(&mut best_peer, &mut best_cost, &mut best_dist);
                    } else if p.key == bp.key && p.prio > bp.prio {
                        continue;
                    } else if cost.saturating_mul(dist) < best_cost.saturating_mul(best_dist) {
                        accept(&mut best_peer, &mut best_cost, &mut best_dist);
                    } else if cost.saturating_mul(dist) > best_cost.saturating_mul(best_dist) {
                        continue;
                    } else if dist < best_dist {
                        accept(&mut best_peer, &mut best_cost, &mut best_dist);
                    } else if dist > best_dist {
                        continue;
                    } else if cost < best_cost {
                        accept(&mut best_peer, &mut best_cost, &mut best_dist);
                    } else if cost > best_cost {
                        continue;
                    } else if p.order < bp.order {
                        accept(&mut best_peer, &mut best_cost, &mut best_dist);
                    }
                }
            }
        }

        best_peer.map(|p| p.id)
    }

    // -----------------------------------------------------------------------
    // Ancestry
    // -----------------------------------------------------------------------

    fn get_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
        let mut anc = self.backwards_ancestry(key);
        anc.reverse();
        anc
    }

    fn backwards_ancestry(&self, key: &PublicKey) -> Vec<PublicKey> {
        let mut anc = Vec::new();
        let mut here = *key;
        loop {
            if anc.contains(&here) {
                return anc;
            }
            if let Some(info) = self.infos.get(&here) {
                anc.push(here);
                here = info.parent;
            } else {
                return anc;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Traffic handling
    // -----------------------------------------------------------------------

    /// Handle outbound traffic (from local application).
    pub fn send_traffic(&mut self, mut tr: crate::traffic::TrafficPacket) -> Vec<RouterAction> {
        // Use pathfinder to find path
        if let Some(path) = self.pathfinder.get_path(&tr.dest) {
            tr.path = path.to_vec();
            let (_, from) = self.get_root_and_path(&self.crypto.public_key);
            tr.from = from;

            // Cache a copy in pathfinder
            let cached = tr.clone();
            self.pathfinder.cache_traffic(&tr.dest, cached);

            return self.route_traffic(tr);
        }

        // No path — initiate lookup
        tracing::debug!("No path to {:?}, initiating lookup", hex::encode(&tr.dest[..8]));
        let dest = tr.dest;
        let xform = self.blooms.x_key(&dest, &self.bloom_transform);
        self.pathfinder.ensure_rumor(xform);
        self.pathfinder.cache_rumor_traffic(&xform, tr);

        if !self.pathfinder.should_throttle_lookup(&dest, self.path_throttle) {
            return self.do_send_lookup(&dest);
        }

        Vec::new()
    }

    /// Route traffic to next hop or deliver locally.
    pub fn route_traffic(&mut self, tr: crate::traffic::TrafficPacket) -> Vec<RouterAction> {
        let mut watermark = tr.watermark;
        let path = tr.path.clone();

        tracing::debug!("Route traffic {:?}, for: {}", path, hex::encode(&tr.dest[..8]));
        if let Some(peer_id) = self.lookup(&path, &mut watermark) {
            tracing::debug!("Routing traffic for other peer {peer_id}");
            let mut tr = tr;
            tr.watermark = watermark;
            vec![RouterAction::SendTraffic {
                peer_id,
                traffic: tr,
            }]
        } else if tr.dest == self.crypto.public_key {
            tracing::debug!("Traffic arrived for us: {} bytes from {:?}", tr.payload.len(), hex::encode(&tr.source[..4]));
            self.pathfinder.reset_timeout(&tr.source);
            vec![RouterAction::DeliverTraffic { traffic: tr }]
        } else {
            tracing::debug!("Broken path for traffic");
            // Path broken
            self.do_broken(&tr)
        }
    }

    /// Handle incoming traffic from a peer.
    pub fn handle_traffic(&mut self, tr: crate::traffic::TrafficPacket) -> Vec<RouterAction> {
        self.route_traffic(tr)
    }

    // -----------------------------------------------------------------------
    // Path discovery (delegating to pathfinder)
    // -----------------------------------------------------------------------

    fn do_send_lookup(&mut self, dest: &PublicKey) -> Vec<RouterAction> {
        if self.pathfinder.should_throttle_lookup(dest, self.path_throttle) {
            tracing::debug!("Lookup throttled for {:?}", hex::encode(&dest[..8]));
            return Vec::new();
        }
        tracing::debug!("Sending lookup for {:?}", hex::encode(&dest[..8]));
        self.pathfinder.mark_lookup_sent(dest);

        let self_key = self.crypto.public_key;
        let (_, from) = self.get_root_and_path(&self_key);

        let lookup = wire::PathLookup {
            source: self_key,
            dest: *dest,
            from,
        };

        self.handle_lookup_internal(&self_key, &lookup)
    }

    fn handle_lookup_internal(&mut self,from_key: &PublicKey, lookup: &wire::PathLookup) -> Vec<RouterAction> {
        let mut actions = Vec::new();

        // Multicast to matching peers
        let targets = self.blooms.get_multicast_targets(from_key, &lookup.dest, &self.bloom_transform);
        tracing::debug!("Lookup multicast to {} targets", targets.len());
        for target_key in targets {
            if let Some(peer_id) = self.best_peer_for_key(&target_key) {
                actions.push(RouterAction::SendPathLookup {
                    peer_id,
                    lookup: lookup.clone(),
                });
            }
        }

        // Check if we match the destination
        let dx = self.blooms.x_key(&lookup.dest, &self.bloom_transform);
        let sx = self
            .blooms
            .x_key(&self.crypto.public_key, &self.bloom_transform);
        tracing::debug!("Lookup self-check: dx={:?} sx={:?} match={}", hex::encode(&dx[..4]), hex::encode(&sx[..4]), dx == sx);
        if dx == sx {
            let self_key = self.crypto.public_key;
            let (_, path) = self.get_root_and_path(&self_key);

            let mut notify_info = crate::pathfinder::OwnPathInfo {
                seq: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                path,
                sig: [0u8; 64],
            };

            if !self.pathfinder.info.content_equal(&notify_info) {
                notify_info.sign(&self.crypto);
                self.pathfinder.info = notify_info.clone();
            } else {
                notify_info = self.pathfinder.info.clone();
            }

            let notify = wire::PathNotify {
                path: lookup.from.clone(),
                watermark: u64::MAX,
                source: self_key,
                dest: lookup.source,
                info: wire::PathNotifyInfo {
                    seq: notify_info.seq,
                    path: notify_info.path,
                    sig: notify_info.sig,
                },
            };

            actions.extend(self.handle_notify_internal(&self_key, &notify));
        }

        actions
    }

    /// Handle incoming lookup from a peer.
    pub fn handle_lookup(&mut self,peer_key: &PublicKey, lookup: &wire::PathLookup) -> Vec<RouterAction> {
        tracing::debug!("Received lookup from {:?} for dest {:?} (source={:?})", hex::encode(&peer_key[..8]), hex::encode(&lookup.dest[..8]), hex::encode(&lookup.source[..8]));
        if !self.blooms.is_on_tree(peer_key) {
            tracing::debug!("Dropping lookup from {:?}: peer not on tree", hex::encode(&peer_key[..8]));
            return Vec::new();
        }
        self.handle_lookup_internal(peer_key, lookup)
    }

    fn handle_notify_internal(&mut self,_from_key: &PublicKey, notify: &wire::PathNotify) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        tracing::debug!("PathNotify: src={:?} dest={:?} path_len={}", hex::encode(&notify.source[..8]), hex::encode(&notify.dest[..8]), notify.path.len());

        // Try to route towards destination
        let mut watermark = notify.watermark;
        if let Some(peer_id) = self.lookup(&notify.path, &mut watermark) {
            let mut fwd = notify.clone();
            fwd.watermark = watermark;
            actions.push(RouterAction::SendPathNotify {
                peer_id,
                notify: fwd,
            });
            return actions;
        }

        // Check if it's for us
        if notify.dest != self.crypto.public_key {
            tracing::debug!("PathNotify not for us, discarding");
            return actions;
        }
        tracing::debug!("PathNotify received for us from {:?}", hex::encode(&notify.source[..4]));

        // Verify signature
        let info_bytes = {
            let mut out = Vec::new();
            wire::encode_uvarint(&mut out, notify.info.seq);
            wire::encode_path(&mut out, &notify.info.path);
            out
        };
        if !Crypto::verify(&notify.source, &info_bytes, &notify.info.sig) {
            tracing::warn!("PathNotify signature verification failed for source {:?}", hex::encode(&notify.source[..4]));
            return actions;
        }

        let xformed_source =
            self.blooms
                .x_key(&notify.source, &self.bloom_transform);

        if let Some(traffic) = self.pathfinder.accept_notify(
            notify.source,
            xformed_source,
            notify.info.seq,
            notify.info.path.clone(),
            self.path_timeout,
        ) {
            // Send the cached traffic
            actions.extend(self.route_traffic(traffic));
        }

        // Notify callback
        if let Some(ref cb) = self.path_notify_cb {
            cb(notify.source);
        }

        actions
    }

    /// Handle incoming path notify from a peer.
    pub fn handle_notify(&mut self,peer_key: &PublicKey, notify: &wire::PathNotify) -> Vec<RouterAction> {
        self.handle_notify_internal(peer_key, notify)
    }

    fn do_broken(&mut self, tr: &crate::traffic::TrafficPacket) -> Vec<RouterAction> {
        let broken = wire::PathBroken {
            path: tr.from.clone(),
            watermark: u64::MAX,
            source: tr.source,
            dest: tr.dest,
        };
        self.handle_broken_internal(&broken)
    }

    fn handle_broken_internal(&mut self, broken: &wire::PathBroken) -> Vec<RouterAction> {
        let mut actions = Vec::new();
        let mut watermark = broken.watermark;

        if let Some(peer_id) = self.lookup(&broken.path, &mut watermark) {
            let mut fwd = broken.clone();
            fwd.watermark = watermark;
            actions.push(RouterAction::SendPathBroken { peer_id, broken: fwd, });
            return actions;
        }

        if broken.source != self.crypto.public_key {
            return actions;
        }

        self.pathfinder.handle_broken(&broken.dest);
        // Try to re-lookup
        if !self.pathfinder.should_throttle_lookup(&broken.dest, self.path_throttle) {
            actions.extend(self.do_send_lookup(&broken.dest));
        }

        actions
    }

    /// Handle incoming path broken from a peer.
    pub fn handle_broken(&mut self, broken: &wire::PathBroken) -> Vec<RouterAction> {
        self.handle_broken_internal(broken)
    }

    // -----------------------------------------------------------------------
    // Helper: best peer for a key
    // -----------------------------------------------------------------------

    fn best_peer_for_key(&self, key: &PublicKey) -> Option<PeerId> {
        self.peers.get(key).and_then(|peers| {
            peers
                .values()
                .min_by_key(|e| e.prio)
                .map(|e| e.id)
        })
    }

    /// Expire old router infos.
    pub fn expire_infos(&mut self) {
        let now = Instant::now();
        let self_key = self.crypto.public_key;
        let timeout = self.router_timeout;
        let refresh = self.router_refresh;

        let expired: Vec<PublicKey> = self
            .info_times
            .iter()
            .filter(|(k, t)| {
                if **k == self_key {
                    now.duration_since(**t) >= refresh
                } else {
                    now.duration_since(**t) >= timeout
                }
            })
            .map(|(k, _)| *k)
            .collect();

        for key in expired {
            if key == self_key {
                self.refresh = true;
            } else {
                self.infos.remove(&key);
                self.info_times.remove(&key);
                for sent in self.sent.values_mut() {
                    sent.remove(&key);
                }
                self.reset_cache();
            }
        }
    }

    /// Handle incoming bloom filter from a peer.
    pub fn handle_bloom(&mut self,peer_key: &PublicKey, filter: crate::bloom::BloomFilter) {
        self.blooms.handle_bloom(peer_key, filter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_router() -> Router {
        let key = SigningKey::generate(&mut OsRng);
        let crypto = Crypto::new(key);
        let config = crate::config::Config::default();
        Router::new(crypto, &config)
    }

    #[test]
    fn become_root_on_first_maintenance() {
        let mut router = make_router();
        let self_key = router.crypto.public_key;

        let _actions = router.do_maintenance();

        // After maintenance with do_root2=true, we should have our own info
        assert!(router.infos.contains_key(&self_key));
        let info = &router.infos[&self_key];
        assert_eq!(info.parent, self_key); // self-rooted
    }

    #[test]
    fn update_accepts_newer_seq() {
        let mut router = make_router();
        router.become_root();
        let self_key = router.crypto.public_key;

        let old_seq = router.infos[&self_key].seq;

        // Create a new announcement with higher seq
        let key2 = SigningKey::generate(&mut OsRng);
        let crypto2 = Crypto::new(key2);
        let ann = RouterAnnounce {
            key: crypto2.public_key,
            parent: crypto2.public_key,
            seq: 1,
            nonce: 42,
            port: 0,
            psig: crypto2.sign(&{
                let mut out = Vec::new();
                out.extend_from_slice(&crypto2.public_key);
                out.extend_from_slice(&crypto2.public_key);
                wire::encode_uvarint(&mut out, 1);
                wire::encode_uvarint(&mut out, 42);
                wire::encode_uvarint(&mut out, 0);
                out
            }),
            sig: [0u8; 64], // will be set properly
        };
        // Self-sign
        let bs = ann.bytes_for_sig();
        let mut ann = ann;
        ann.sig = crypto2.sign(&bs);

        assert!(ann.check());
        assert!(router.update(&ann));
        assert!(router.infos.contains_key(&crypto2.public_key));
    }

    #[test]
    fn get_root_and_path_self_root() {
        let mut router = make_router();
        router.become_root();
        let self_key = router.crypto.public_key;

        let (root, path) = router.get_root_and_path(&self_key);
        assert_eq!(root, self_key);
        assert!(path.is_empty()); // root has empty path
    }

    #[test]
    fn get_dist_same_path() {
        let mut router = make_router();
        router.become_root();
        let self_key = router.crypto.public_key;

        let dist = router.get_dist(&[], &self_key);
        assert_eq!(dist, 0); // same node, same (empty) path
    }

    #[test]
    fn announce_check_valid() {
        let key = SigningKey::generate(&mut OsRng);
        let crypto = Crypto::new(key);

        let mut out = Vec::new();
        out.extend_from_slice(&crypto.public_key);
        out.extend_from_slice(&crypto.public_key);
        wire::encode_uvarint(&mut out, 1);
        wire::encode_uvarint(&mut out, 42);
        wire::encode_uvarint(&mut out, 0);

        let sig = crypto.sign(&out);

        let ann = RouterAnnounce {
            key: crypto.public_key,
            parent: crypto.public_key,
            seq: 1,
            nonce: 42,
            port: 0,
            psig: sig,
            sig,
        };

        assert!(ann.check());
    }
}
