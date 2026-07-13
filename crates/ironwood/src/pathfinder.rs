//! Path discovery state machine.
//!
//! Handles PathLookup, PathNotify, and PathBroken messages.
//! Maintains a cache of known paths to destinations with timeouts.
//! Throttles lookups to prevent flooding.

use rustc_hash::FxHashMap as HashMap;
use std::time::{Duration, Instant};

use crate::crypto::{Crypto, PublicKey, Sig};
use crate::wire::{self, PeerPort};

// ---------------------------------------------------------------------------
// Path info: cached path to a destination
// ---------------------------------------------------------------------------

/// Cached path information for a known destination.
pub(crate) struct PathInfo {
    /// Tree coordinates to destination (not zero-terminated).
    pub path: Vec<PeerPort>,
    /// Sequence number from the destination.
    pub seq: u64,
    /// When we last sent a lookup request.
    pub req_time: Instant,
    /// When this path entry was last refreshed.
    pub last_refresh: Instant,
    /// Cached traffic packet waiting for path.
    pub cached_traffic: Option<super::traffic::TrafficPacket>,
    /// Path broken flag (must get new notify to clear).
    pub broken: bool,
}

// ---------------------------------------------------------------------------
// Path rumor: pending lookup for unknown destination
// ---------------------------------------------------------------------------

/// A pending lookup for a destination we don't have a path to yet.
pub(crate) struct PathRumor {
    /// Cached traffic packet.
    pub traffic: Option<super::traffic::TrafficPacket>,
    /// When we last sent a lookup on the application-write path (None = never sent).
    /// Also the expiry base in `cleanup_expired`, so it bounds the rumor's lifetime.
    pub send_time: Option<Instant>,
    /// When `do_maintenance` last *retried* a lookup (None = never retried). Kept
    /// separate from `send_time` on purpose: retries must be throttled but must NOT
    /// extend the rumor's lifetime, or a permanently-unreachable peer would be looked
    /// up forever instead of expiring `path_timeout` after the last application write.
    pub retry_time: Option<Instant>,
    /// When this rumor was created (used as expiry fallback if never sent).
    pub created: Instant,
}

// ---------------------------------------------------------------------------
// Signed path notification info
// ---------------------------------------------------------------------------

/// Our own signed path info (advertised to lookup requesters).
#[derive(Clone)]
pub(crate) struct OwnPathInfo {
    pub seq: u64,
    pub path: Vec<PeerPort>,
    pub sig: Sig,
}

impl OwnPathInfo {
    pub fn new() -> Self {
        Self {
            seq: 0,
            path: Vec::new(),
            sig: [0u8; 64],
        }
    }

    /// Compute bytes that are signed.
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut out = Vec::new();
        wire::encode_uvarint(&mut out, self.seq);
        wire::encode_path(&mut out, &self.path);
        out
    }

    /// Sign with our private key.
    pub fn sign(&mut self, crypto: &Crypto) {
        let bytes = self.bytes_for_sig();
        self.sig = crypto.sign(&bytes);
    }

    /// Check equality ignoring the signature.
    pub fn content_equal(&self, other: &OwnPathInfo) -> bool {
        self.seq == other.seq && self.path == other.path
    }
}

// ---------------------------------------------------------------------------
// Pathfinder
// ---------------------------------------------------------------------------

/// Path discovery and caching state machine.
///
/// Maintains known paths to destinations and handles the lookup protocol.
/// Must be used from within the router's lock — not independently thread-safe.
pub(crate) struct Pathfinder {
    /// Our own signed path info.
    pub info: OwnPathInfo,
    /// Known paths to destinations.
    pub paths: HashMap<PublicKey, PathInfo>,
    /// Pending lookups (indexed by transformed key).
    pub rumors: HashMap<PublicKey, PathRumor>,
}

impl Pathfinder {
    pub fn new(crypto: &Crypto) -> Self {
        let mut info = OwnPathInfo::new();
        info.sign(crypto);
        Self {
            info,
            paths: HashMap::default(),
            rumors: HashMap::default(),
        }
    }

    /// Check if we should throttle a lookup to this destination.
    pub fn should_throttle_lookup(&self, dest: &PublicKey, throttle: Duration) -> bool {
        if let Some(info) = self.paths.get(dest) {
            info.req_time.elapsed() < throttle
        } else {
            false
        }
    }

    /// Record that we sent a lookup at this time.
    pub fn mark_lookup_sent(&mut self, dest: &PublicKey) {
        if let Some(info) = self.paths.get_mut(dest) {
            info.req_time = Instant::now();
        }
    }

    /// Check if a rumor lookup should be throttled.
    /// Returns false if never sent (new rumor always eligible for first send).
    pub fn should_throttle_rumor(
        &self,
        xformed_dest: &PublicKey,
        throttle: Duration,
    ) -> bool {
        if let Some(rumor) = self.rumors.get(xformed_dest) {
            rumor.send_time.map_or(false, |t| t.elapsed() < throttle)
        } else {
            false
        }
    }

    /// Get or create a rumor for a destination.
    /// Returns true if the rumor was just created.
    /// Does NOT update send_time for existing rumors — use mark_rumor_sent().
    pub fn ensure_rumor(&mut self, xformed_dest: PublicKey) -> bool {
        if self.rumors.contains_key(&xformed_dest) {
            false
        } else {
            self.rumors.insert(
                xformed_dest,
                PathRumor {
                    traffic: None,
                    send_time: None,
                    retry_time: None,
                    created: Instant::now(),
                },
            );
            true
        }
    }

    /// Record that a rumor lookup was sent now (resets expiry timer, like Go's timer.Reset).
    pub fn mark_rumor_sent(&mut self, xformed_dest: &PublicKey) {
        if let Some(rumor) = self.rumors.get_mut(xformed_dest) {
            rumor.send_time = Some(Instant::now());
        }
    }

    /// Throttle a `do_maintenance` *retry*: skip if either the last application-write
    /// lookup (`send_time`) or the last retry (`retry_time`) was within `throttle`.
    pub fn should_throttle_rumor_retry(
        &self,
        xformed_dest: &PublicKey,
        throttle: Duration,
    ) -> bool {
        if let Some(rumor) = self.rumors.get(xformed_dest) {
            let recent = |t: Option<Instant>| t.map_or(false, |t| t.elapsed() < throttle);
            recent(rumor.send_time) || recent(rumor.retry_time)
        } else {
            false
        }
    }

    /// Record a maintenance retry. Unlike `mark_rumor_sent` this leaves `send_time`
    /// untouched, so `cleanup_expired` still bounds the rumor to `path_timeout` after
    /// the last application write — our own retries do not keep a dead peer alive.
    pub fn mark_rumor_retry(&mut self, xformed_dest: &PublicKey) {
        if let Some(rumor) = self.rumors.get_mut(xformed_dest) {
            rumor.retry_time = Some(Instant::now());
        }
    }

    /// Cache a traffic packet in a rumor (for sending when path is found).
    pub fn cache_rumor_traffic(
        &mut self,
        xformed_dest: &PublicKey,
        traffic: super::traffic::TrafficPacket,
    ) {
        if let Some(rumor) = self.rumors.get_mut(xformed_dest) {
            rumor.traffic = Some(traffic);
        }
    }

    /// Process a path notification response.
    ///
    /// Returns `(accepted, traffic)` where:
    /// - `accepted` is true if the path was updated (matches Go: callback only fires on accept).
    /// - `traffic` is a cached packet to re-send, if any.
    pub fn accept_notify(
        &mut self,
        source: PublicKey,
        xformed_source: PublicKey,
        notify_seq: u64,
        notify_path: Vec<PeerPort>,
        _path_timeout: Duration,
    ) -> (bool, Option<super::traffic::TrafficPacket>) {
        if let Some(info) = self.paths.get_mut(&source) {
            if notify_seq <= info.seq {
                return (false, None); // seq not strictly greater
            }
            // Storm prevention: for a *working* path, don't reset if coords are unchanged.
            // This avoids: working → lookup → same-path notify → reset timer → working …
            // For a *broken* path we DO accept same coords with higher seq: the destination
            // is at the same tree position, but routing might now succeed through different
            // (non-zombie) intermediate peers.
            if !info.broken && info.path == notify_path {
                return (false, None); // working path, coords unchanged — nothing to update
            }
            let was_broken = info.broken;
            info.path = notify_path;
            info.seq = notify_seq;
            info.broken = false;
            info.last_refresh = Instant::now();
            if was_broken {
                tracing::debug!(
                    "PathNotify: un-broke path to {:02x?} seq={} path={:?}",
                    &source[..8], notify_seq, &info.path
                );
            }
            return (true, info.cached_traffic.take());
        }

        // New path — must have a rumor for this xformed key
        if !self.rumors.contains_key(&xformed_source) {
            tracing::debug!(
                "PathNotify REJECTED (no rumor): source={:02x?} xformed={:02x?}",
                &source[..8],
                &xformed_source[..8]
            );
            return (false, None);
        }
        tracing::debug!(
            "PathNotify ACCEPTED (rumor exists): source={:02x?} seq={} path={:?}",
            &source[..8],
            notify_seq,
            notify_path
        );

        let traffic = self
            .rumors
            .get_mut(&xformed_source)
            .and_then(|rumor| {
                if rumor
                    .traffic
                    .as_ref()
                    .map_or(false, |t| t.dest == source)
                {
                    rumor.traffic.take()
                } else {
                    None
                }
            });

        self.paths.insert(
            source,
            PathInfo {
                path: notify_path,
                seq: notify_seq,
                req_time: Instant::now(),
                last_refresh: Instant::now(),
                cached_traffic: None,
                broken: false,
            },
        );

        (true, traffic)
    }

    /// Handle a path broken notification for a destination.
    pub fn handle_broken(&mut self, dest: &PublicKey) {
        if let Some(info) = self.paths.get_mut(dest) {
            info.broken = true;
        }
    }

    /// Adopt the sender's coordinates from a received packet (`tr.from`) as a path
    /// back to them, so a node can reply to traffic it never looked up itself (e.g.
    /// an encrypted-session ACK) without a fresh lookup that may not resolve.
    ///
    /// `tr.from` is an *unsigned*, attacker-forgeable routing header, so this must
    /// never overwrite or resurrect an existing entry — otherwise any node that can
    /// get a packet delivered to us could replace a signed PathNotify path or
    /// un-break a broken one (path-cache poisoning). We therefore only fill an empty
    /// slot, with `seq = 0` so any signed PathNotify (`seq > 0`) supersedes it. A live
    /// learned entry is kept fresh by `reset_timeout` (non-broken only); a broken or
    /// expired one is dropped by `cleanup_expired` and re-learned from the next packet.
    /// An empty path (sender is the tree root) is cached too, as `send_traffic` has no
    /// special case for the root.
    pub fn learn_path_from_traffic(&mut self, source: &PublicKey, path: &[PeerPort]) {
        self.paths.entry(*source).or_insert_with(|| PathInfo {
            path: path.to_vec(),
            seq: 0,
            req_time: Instant::now(),
            last_refresh: Instant::now(),
            cached_traffic: None,
            broken: false,
        });
    }

    /// Reset the timeout for a destination (called when we receive traffic from them).
    pub fn reset_timeout(&mut self, key: &PublicKey) {
        if let Some(info) = self.paths.get_mut(key) {
            if !info.broken {
                info.last_refresh = Instant::now();
            }
        }
    }

    /// Get the cached path for a destination.
    pub fn get_path(&self, dest: &PublicKey) -> Option<&[PeerPort]> {
        let result = self.paths
            .get(dest)
            .filter(|info| !info.broken)
            .map(|info| info.path.as_slice());
        if let Some(path) = result {
            tracing::debug!("get_path for {:02x?}: {:?}", &dest[..8], path);
        }
        result
    }

    /// Returns true if the path-notify cache slot for `dest` is empty.
    /// Used to avoid cloning a full packet on every send when the cache is
    /// already populated (path is stable, no path-notify has consumed it).
    pub fn needs_traffic_cache(&self, dest: &PublicKey) -> bool {
        self.paths
            .get(dest)
            .map(|info| info.cached_traffic.is_none())
            .unwrap_or(false)
    }

    /// Cache a traffic packet for a destination (sent when path is found or refreshed).
    pub fn cache_traffic(
        &mut self,
        dest: &PublicKey,
        traffic: super::traffic::TrafficPacket,
    ) {
        if let Some(info) = self.paths.get_mut(dest) {
            info.cached_traffic = Some(traffic);
        }
    }

    /// Clean up expired paths and rumors.
    pub fn cleanup_expired(&mut self, path_timeout: Duration) {
        let now = Instant::now();
        self.paths.retain(|_, info| {
            now.duration_since(info.last_refresh) < path_timeout
        });
        self.rumors.retain(|_, rumor| {
            // Use send_time if set (matches Go's timer.Reset on each send),
            // otherwise fall back to created time.
            let expiry_base = rumor.send_time.unwrap_or(rumor.created);
            now.duration_since(expiry_base) < path_timeout
        });
    }

    /// Real destination keys of rumors still waiting on a path: they have
    /// buffered traffic but no live (non-broken) path yet. `do_maintenance`
    /// re-issues a throttled lookup for each, so a `PathLookup`/`PathNotify`
    /// lost during tree/bloom convergence is retried instead of wedging until
    /// the rumor expires.
    ///
    /// This is a deliberate divergence from upstream Go ironwood: Go's
    /// `_doMaintenance` has no rumor retry — it re-sends a lookup only on the next
    /// application write (`_handleTraffic` → `_rumorSendLookup`) or an explicit
    /// `SendLookup`. That is fine for TUN traffic (TCP retransmits force new writes)
    /// but a one-shot send (e.g. a single mail to a cold peer behind another hub)
    /// would otherwise wedge until the buffer expires.
    pub fn rumors_needing_retry(&self) -> Vec<PublicKey> {
        self.rumors
            .values()
            .filter_map(|rumor| rumor.traffic.as_ref().map(|t| t.dest))
            .filter(|dest| self.paths.get(dest).map_or(true, |info| info.broken))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_crypto() -> Crypto {
        Crypto::new(SigningKey::generate(&mut OsRng))
    }

    #[test]
    fn pathfinder_new() {
        let crypto = make_crypto();
        let pf = Pathfinder::new(&crypto);
        assert!(pf.paths.is_empty());
        assert!(pf.rumors.is_empty());
    }

    #[test]
    fn own_path_info_sign_and_verify() {
        let crypto = make_crypto();
        let mut info = OwnPathInfo::new();
        info.seq = 42;
        info.path = vec![1, 2, 3];
        info.sign(&crypto);

        let bytes = info.bytes_for_sig();
        assert!(Crypto::verify(&crypto.public_key, &bytes, &info.sig));
    }

    #[test]
    fn throttle_lookup() {
        let crypto = make_crypto();
        let mut pf = Pathfinder::new(&crypto);
        let dest = [1u8; 32];
        let throttle = Duration::from_secs(1);

        // No path yet, so no throttle
        assert!(!pf.should_throttle_lookup(&dest, throttle));

        // Create a path
        pf.paths.insert(
            dest,
            PathInfo {
                path: vec![1, 2],
                seq: 1,
                req_time: Instant::now(),
                last_refresh: Instant::now(),
                cached_traffic: None,
                broken: false,
            },
        );

        // Should throttle now
        assert!(pf.should_throttle_lookup(&dest, throttle));
    }

    #[test]
    fn accept_notify_new_path() {
        let crypto = make_crypto();
        let mut pf = Pathfinder::new(&crypto);
        let source = [1u8; 32];
        let xformed = [1u8; 32];

        // Must have a rumor first
        let (accepted, traffic) =
            pf.accept_notify(source, xformed, 1, vec![1, 2], Duration::from_secs(60));
        assert!(!accepted);
        assert!(traffic.is_none());

        // Create rumor
        pf.ensure_rumor(xformed);
        let (accepted, traffic) =
            pf.accept_notify(source, xformed, 1, vec![1, 2], Duration::from_secs(60));
        assert!(accepted);
        assert!(traffic.is_none()); // no cached traffic
        assert!(pf.paths.contains_key(&source));
        assert_eq!(pf.paths[&source].path, vec![1, 2]);
    }

    #[test]
    fn handle_broken() {
        let crypto = make_crypto();
        let mut pf = Pathfinder::new(&crypto);
        let dest = [1u8; 32];

        pf.paths.insert(
            dest,
            PathInfo {
                path: vec![1, 2],
                seq: 1,
                req_time: Instant::now(),
                last_refresh: Instant::now(),
                cached_traffic: None,
                broken: false,
            },
        );

        assert!(pf.get_path(&dest).is_some());
        pf.handle_broken(&dest);
        assert!(pf.get_path(&dest).is_none()); // broken paths not returned
    }

    // `tr.from` is unsigned, so learned paths must never overwrite or resurrect an
    // existing entry — otherwise any node that can reach us could poison our cache.
    #[test]
    fn learn_path_only_fills_empty_slot() {
        let crypto = make_crypto();
        let mut pf = Pathfinder::new(&crypto);
        let src = [7u8; 32];

        // Empty slot: adopt the coords, seq stays 0 so a signed notify supersedes.
        pf.learn_path_from_traffic(&src, &[1, 2, 3]);
        assert_eq!(pf.paths[&src].path, vec![1, 2, 3]);
        assert_eq!(pf.paths[&src].seq, 0);

        // Pretend a signed PathNotify has since set this path (seq > 0).
        pf.paths.get_mut(&src).unwrap().seq = 5;
        pf.learn_path_from_traffic(&src, &[9, 9, 9]);
        assert_eq!(pf.paths[&src].path, vec![1, 2, 3], "must not overwrite a known path");
        assert_eq!(pf.paths[&src].seq, 5);

        // A broken path must not be un-broken by unsigned traffic.
        pf.handle_broken(&src);
        pf.learn_path_from_traffic(&src, &[4, 4]);
        assert!(pf.paths[&src].broken, "must not un-break via unsigned traffic");
        assert_eq!(pf.paths[&src].path, vec![1, 2, 3]);
    }

    // A maintenance retry must be throttled by path_throttle, but must NOT reset the
    // rumor's expiry clock (send_time) — otherwise an unreachable peer is looked up
    // forever instead of expiring path_timeout after the last application write.
    #[test]
    fn rumor_retry_throttles_without_extending_lifetime() {
        let crypto = make_crypto();
        let mut pf = Pathfinder::new(&crypto);
        let xform = [3u8; 32];
        let throttle = Duration::from_secs(1);

        pf.ensure_rumor(xform);
        assert!(!pf.should_throttle_rumor_retry(&xform, throttle)); // never retried

        pf.mark_rumor_retry(&xform);
        assert!(pf.should_throttle_rumor_retry(&xform, throttle)); // just retried

        assert!(
            pf.rumors[&xform].send_time.is_none(),
            "maintenance retry must not extend rumor lifetime"
        );
    }
}
