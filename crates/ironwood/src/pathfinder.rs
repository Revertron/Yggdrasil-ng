//! Path discovery state machine.
//!
//! Handles PathLookup, PathNotify, and PathBroken messages.
//! Maintains a cache of known paths to destinations with timeouts.
//! Throttles lookups to prevent flooding.

use std::collections::HashMap;
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
    /// When we last sent a lookup.
    pub send_time: Instant,
    /// When this rumor was created.
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
            paths: HashMap::new(),
            rumors: HashMap::new(),
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
    pub fn should_throttle_rumor(
        &self,
        xformed_dest: &PublicKey,
        throttle: Duration,
    ) -> bool {
        if let Some(rumor) = self.rumors.get(xformed_dest) {
            rumor.send_time.elapsed() < throttle
        } else {
            false
        }
    }

    /// Get or create a rumor for a destination.
    /// Returns true if the rumor was just created.
    pub fn ensure_rumor(&mut self, xformed_dest: PublicKey) -> bool {
        if self.rumors.contains_key(&xformed_dest) {
            if let Some(rumor) = self.rumors.get_mut(&xformed_dest) {
                rumor.send_time = Instant::now();
            }
            false
        } else {
            self.rumors.insert(
                xformed_dest,
                PathRumor {
                    traffic: None,
                    send_time: Instant::now(),
                    created: Instant::now(),
                },
            );
            true
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
    /// Returns Some(traffic) if there's a cached packet to send.
    pub fn accept_notify(
        &mut self,
        source: PublicKey,
        xformed_source: PublicKey,
        notify_seq: u64,
        notify_path: Vec<PeerPort>,
        _path_timeout: Duration,
    ) -> Option<super::traffic::TrafficPacket> {
        if let Some(info) = self.paths.get_mut(&source) {
            // Existing path
            if notify_seq <= info.seq {
                return None; // old seq
            }
            // Check if path actually changed
            if info.seq == notify_seq && info.path == notify_path {
                return None; // same info
            }
            info.path = notify_path;
            info.seq = notify_seq;
            info.broken = false;
            info.last_refresh = Instant::now();
            return info.cached_traffic.take();
        }

        // New path — must have a rumor for this xformed key
        if !self.rumors.contains_key(&xformed_source) {
            return None;
        }

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

        traffic
    }

    /// Handle a path broken notification for a destination.
    pub fn handle_broken(&mut self, dest: &PublicKey) {
        if let Some(info) = self.paths.get_mut(dest) {
            info.broken = true;
        }
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
        self.paths
            .get(dest)
            .filter(|info| !info.broken)
            .map(|info| info.path.as_slice())
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
            now.duration_since(rumor.created) < path_timeout
        });
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
        assert!(pf
            .accept_notify(source, xformed, 1, vec![1, 2], Duration::from_secs(60))
            .is_none());

        // Create rumor
        pf.ensure_rumor(xformed);
        let result =
            pf.accept_notify(source, xformed, 1, vec![1, 2], Duration::from_secs(60));
        assert!(result.is_none()); // no cached traffic
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
}
