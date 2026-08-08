//! Adaptive peer liveness with a **sticky floor** (no mode thrash).
//!
//! After a non-keepalive send, the peer writer arms a read deadline. Silence is
//! tolerated for up to `peer_probe_count` intervals (see [`crate::Config`]); only
//! the final miss tears the link down and updates durable state.
//!
//! ## Adaptive (default)
//!
//! ```text
//! total_silence  is NOT owned here alone — peers.rs multiplies interval × probes.
//! interval T     = clamp(base + rtt_mult * ewma + penalty, sticky_floor, max)
//! sticky_floor   starts at `min`; on liveness timeout rises to max(floor, problem_min)
//!                and does not snap back (no Degraded↔Normal recover loop).
//! ```
//!
//! - Sample: arm→first inbound frame of the deadline epoch (not pure RTT).
//! - Re-arms while already armed do not reset the sample clock.
//! - Durable state (floor, ewma, penalty) is **per peer public key** and survives
//!   reconnects via [`PeerLivenessRegistry`].
//! - Slow samples only update EWMA / decay penalty; they never raise the floor.

use rustc_hash::FxHashMap as HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::PublicKey;

/// Soft cap on durable entries (evict arbitrary excess on insert).
const REGISTRY_SOFT_CAP: usize = 4096;

/// Configuration for peer liveness interval sizing.
#[derive(Clone, Debug)]
pub struct AdaptiveTimeoutConfig {
    /// Fixed interval when `adaptive` is false.
    pub fixed_or_initial: Duration,
    /// Enable adaptive sizing + sticky floor. Default: true.
    pub adaptive: bool,
    /// Initial / healthy floor for the interval. Default: 5s.
    /// With `peer_probe_count=3` cold total silence ≈ 15s.
    pub min: Duration,
    /// Floor after a real liveness timeout (sticky). Default: 15s.
    pub problem_min: Duration,
    /// Interval ceiling. Default: 30s.
    pub max: Duration,
    /// Added to RTT-based estimate. Default: 2s.
    pub base: Duration,
    /// Multiplier for EWMA(arm→reply). Default: 8.
    pub rtt_mult: u32,
    /// Penalty step after a final liveness timeout. Default: 5s.
    pub penalty_step: Duration,
    /// Penalty decay per healthy sample. Default: 500ms.
    pub penalty_decay: Duration,
}

impl Default for AdaptiveTimeoutConfig {
    fn default() -> Self {
        Self {
            fixed_or_initial: Duration::from_secs(15),
            adaptive: true,
            min: Duration::from_secs(5),
            problem_min: Duration::from_secs(15),
            max: Duration::from_secs(30),
            base: Duration::from_secs(2),
            rtt_mult: 8,
            penalty_step: Duration::from_secs(5),
            penalty_decay: Duration::from_millis(500),
        }
    }
}

impl AdaptiveTimeoutConfig {
    /// Validate invariants. Call at config load / PacketConn construction.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.rtt_mult == 0 {
            return Err("peer_timeout_rtt_mult must be >= 1".into());
        }
        if self.max < self.min {
            return Err(format!(
                "peer_timeout_max ({:?}) < peer_timeout_min ({:?})",
                self.max, self.min
            ));
        }
        if self.adaptive && self.max < self.problem_min {
            return Err(format!(
                "peer_timeout_max ({:?}) < problem_min/peer_timeout_secs ({:?})",
                self.max, self.problem_min
            ));
        }
        if self.adaptive && self.problem_min < self.min {
            return Err(format!(
                "problem_min/peer_timeout_secs ({:?}) < peer_timeout_min ({:?})",
                self.problem_min, self.min
            ));
        }
        if !self.adaptive && self.fixed_or_initial.is_zero() {
            return Err("peer_timeout_secs must be > 0 in fixed mode".into());
        }
        if self.min.is_zero() {
            return Err("peer_timeout_min must be > 0".into());
        }
        Ok(())
    }

    pub fn compute(&self, ewma_ms: u64, penalty_ms: u64, floor_ms: u64) -> Duration {
        if !self.adaptive {
            return self.fixed_or_initial;
        }

        let floor_ms = floor_ms
            .max(self.min.as_millis() as u64)
            .min(self.max.as_millis() as u64);
        let max_ms = self.max.as_millis() as u64;
        let base_ms = self.base.as_millis() as u64;
        let mult = self.rtt_mult as u64;
        let from_rtt = if ewma_ms == 0 {
            floor_ms
        } else {
            base_ms.saturating_add(mult.saturating_mul(ewma_ms))
        };
        let total = from_rtt.saturating_add(penalty_ms);
        Duration::from_millis(total.clamp(floor_ms, max_ms))
    }
}

/// Snapshot for admin / getPeers.
#[derive(Clone, Debug, Default)]
pub struct LivenessSnapshot {
    pub timeout_ms: u64,
    pub ewma_ms: u64,
    pub penalty_ms: u64,
    /// Sticky floor currently applied (ms).
    pub floor_ms: u64,
    /// True if sticky floor is at/above problem_min (post-timeout path).
    pub degraded: bool,
}

struct ArmEpoch {
    at: Instant,
    timeout: Duration,
}

/// Durable state shared across reconnects for one peer public key.
struct DurableLiveness {
    ewma_ms: AtomicU64,
    penalty_ms: AtomicU64,
    /// Sticky interval floor in ms (starts at cfg.min).
    floor_ms: AtomicU64,
}

impl DurableLiveness {
    fn new(initial_floor_ms: u64) -> Self {
        Self {
            ewma_ms: AtomicU64::new(0),
            penalty_ms: AtomicU64::new(0),
            floor_ms: AtomicU64::new(initial_floor_ms),
        }
    }
}

/// Process-wide (per PacketConn) registry of durable liveness state by peer key.
pub struct PeerLivenessRegistry {
    cfg: AdaptiveTimeoutConfig,
    map: Mutex<HashMap<PublicKey, Arc<DurableLiveness>>>,
}

impl PeerLivenessRegistry {
    pub fn new(cfg: AdaptiveTimeoutConfig) -> Self {
        Self {
            cfg,
            map: Mutex::new(HashMap::default()),
        }
    }

    pub fn config(&self) -> &AdaptiveTimeoutConfig {
        &self.cfg
    }

    /// Controller for a live connection; durable fields survive reconnect.
    pub fn ctrl_for(&self, key: PublicKey) -> Arc<PeerTimeoutCtrl> {
        let initial_floor = self.cfg.min.as_millis() as u64;
        let durable = {
            let mut map = self.map.lock().unwrap();
            if map.len() >= REGISTRY_SOFT_CAP && !map.contains_key(&key) {
                // Soft cap: drop an arbitrary entry (not the key we are inserting).
                if let Some(evict) = map.keys().next().copied() {
                    map.remove(&evict);
                }
            }
            map.entry(key)
                .or_insert_with(|| Arc::new(DurableLiveness::new(initial_floor)))
                .clone()
        };
        Arc::new(PeerTimeoutCtrl {
            cfg: self.cfg.clone(),
            key,
            durable,
            epoch: Mutex::new(None),
        })
    }

    pub fn snapshot(&self, key: PublicKey) -> Option<LivenessSnapshot> {
        let map = self.map.lock().unwrap();
        let d = map.get(&key)?;
        Some(snapshot_of(&self.cfg, d))
    }
}

fn snapshot_of(cfg: &AdaptiveTimeoutConfig, d: &DurableLiveness) -> LivenessSnapshot {
    let ewma = d.ewma_ms.load(Ordering::Relaxed);
    let pen = d.penalty_ms.load(Ordering::Relaxed);
    let floor = d.floor_ms.load(Ordering::Relaxed);
    let timeout = cfg.compute(ewma, pen, floor);
    let problem = cfg.problem_min.as_millis() as u64;
    LivenessSnapshot {
        timeout_ms: timeout.as_millis() as u64,
        ewma_ms: ewma,
        penalty_ms: pen,
        floor_ms: floor,
        degraded: cfg.adaptive && floor >= problem,
    }
}

/// Per-connection controller (session-local arm epoch + shared durable state).
pub struct PeerTimeoutCtrl {
    cfg: AdaptiveTimeoutConfig,
    key: PublicKey,
    durable: Arc<DurableLiveness>,
    epoch: Mutex<Option<ArmEpoch>>,
}

impl PeerTimeoutCtrl {
    /// True if sticky floor has ratcheted to problem_min or above.
    pub fn is_degraded(&self) -> bool {
        let floor = self.durable.floor_ms.load(Ordering::Relaxed);
        self.cfg.adaptive && floor >= self.cfg.problem_min.as_millis() as u64
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// Timeout used for the current armed epoch, if any.
    pub fn last_armed_timeout(&self) -> Option<Duration> {
        self.epoch.lock().unwrap().as_ref().map(|e| e.timeout)
    }

    pub fn current(&self) -> Duration {
        let ewma = self.durable.ewma_ms.load(Ordering::Relaxed);
        let pen = self.durable.penalty_ms.load(Ordering::Relaxed);
        let floor = self.durable.floor_ms.load(Ordering::Relaxed);
        self.cfg.compute(ewma, pen, floor)
    }

    /// Arm a deadline. If already armed, leave epoch unchanged (one-shot deadline).
    pub fn arm(&self, deadline_slot: &mut Option<Instant>) -> Instant {
        if let Some(existing) = *deadline_slot {
            return existing;
        }
        let now = Instant::now();
        let t = self.current();
        let expires = now + t;
        *deadline_slot = Some(expires);
        *self.epoch.lock().unwrap() = Some(ArmEpoch {
            at: now,
            timeout: t,
        });
        tracing::trace!(
            peer = %hex_prefix(&self.key),
            timeout_ms = t.as_millis() as u64,
            ewma_ms = self.durable.ewma_ms.load(Ordering::Relaxed),
            penalty_ms = self.durable.penalty_ms.load(Ordering::Relaxed),
            floor_ms = self.durable.floor_ms.load(Ordering::Relaxed),
            "peer liveness deadline armed"
        );
        expires
    }

    /// Clear deadline after any inbound frame; update EWMA only (no floor raise).
    pub fn clear_on_reply(&self, deadline_slot: &mut Option<Instant>) {
        *deadline_slot = None;
        let epoch = self.epoch.lock().unwrap().take();
        if let Some(e) = epoch {
            self.observe_sample(e.at.elapsed());
        }
    }

    /// Final liveness miss (after probe budget exhausted). Raises sticky floor.
    pub fn on_timeout(&self) {
        let armed_t = self.epoch.lock().unwrap().take().map(|e| e.timeout);

        if self.cfg.adaptive {
            let problem = self.cfg.problem_min.as_millis() as u64;
            let prev_floor = self.durable.floor_ms.load(Ordering::Relaxed);
            let new_floor = prev_floor.max(problem);
            self.durable.floor_ms.store(new_floor, Ordering::Relaxed);

            let step = self.cfg.penalty_step.as_millis() as u64;
            let max_ms = self.cfg.max.as_millis() as u64;
            let _ = self.durable.penalty_ms.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |p| Some(p.saturating_add(step).min(max_ms)),
            );

            if prev_floor < problem {
                tracing::info!(
                    peer = %hex_prefix(&self.key),
                    problem_min_ms = problem,
                    next_timeout_ms = self.current().as_millis() as u64,
                    "peer liveness sticky floor raised to problem_min"
                );
            }
        }

        tracing::debug!(
            peer = %hex_prefix(&self.key),
            armed_timeout_ms = armed_t.map(|d| d.as_millis() as u64).unwrap_or(0),
            penalty_ms = self.durable.penalty_ms.load(Ordering::Relaxed),
            floor_ms = self.durable.floor_ms.load(Ordering::Relaxed),
            next_timeout_ms = self.current().as_millis() as u64,
            "peer liveness timeout — sticky floor/penalty updated"
        );
    }

    fn observe_sample(&self, sample: Duration) {
        if !self.cfg.adaptive {
            return;
        }
        let sample_ms = sample.as_millis().min(self.cfg.max.as_millis()) as u64;
        if sample_ms == 0 {
            return;
        }

        let prev = self.durable.ewma_ms.load(Ordering::Relaxed);
        let new = if prev == 0 {
            sample_ms
        } else {
            (prev * 7 + sample_ms) / 8
        };
        self.durable.ewma_ms.store(new, Ordering::Relaxed);

        let decay = self.cfg.penalty_decay.as_millis() as u64;
        let _ = self.durable.penalty_ms.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |p| Some(p.saturating_sub(decay)),
        );
    }

    pub fn ewma_ms(&self) -> u64 {
        self.durable.ewma_ms.load(Ordering::Relaxed)
    }

    pub fn penalty_ms(&self) -> u64 {
        self.durable.penalty_ms.load(Ordering::Relaxed)
    }

    pub fn floor_ms(&self) -> u64 {
        self.durable.floor_ms.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> LivenessSnapshot {
        snapshot_of(&self.cfg, &self.durable)
    }

    #[cfg(test)]
    fn inject_sample(&self, sample: Duration) {
        self.observe_sample(sample);
    }
}

fn hex_prefix(key: &PublicKey) -> String {
    hex::encode(&key[..4])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        let mut k = [0u8; 32];
        k[0] = n;
        k
    }

    #[test]
    fn validate_rejects_inverted_bounds() {
        let mut cfg = AdaptiveTimeoutConfig::default();
        cfg.max = Duration::from_secs(3);
        cfg.min = Duration::from_secs(5);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_ok_defaults() {
        assert!(AdaptiveTimeoutConfig::default().validate().is_ok());
    }

    #[test]
    fn fixed_mode_exact() {
        let cfg = AdaptiveTimeoutConfig {
            adaptive: false,
            fixed_or_initial: Duration::from_secs(12),
            min: Duration::from_secs(5),
            max: Duration::from_secs(30),
            ..AdaptiveTimeoutConfig::default()
        };
        assert_eq!(cfg.compute(0, 0, 5_000), Duration::from_secs(12));
        assert_eq!(cfg.compute(9999, 0, 15_000), Duration::from_secs(12));
    }

    #[test]
    fn normal_stays_at_five_with_low_rtt() {
        let cfg = AdaptiveTimeoutConfig::default();
        assert_eq!(cfg.compute(0, 0, 5_000), Duration::from_secs(5));
        assert_eq!(cfg.compute(10, 0, 5_000), Duration::from_secs(5));
    }

    #[test]
    fn sticky_floor_fifteen_after_timeout() {
        let cfg = AdaptiveTimeoutConfig::default();
        assert_eq!(cfg.compute(10, 0, 15_000), Duration::from_secs(15));
        assert_eq!(cfg.compute(2000, 0, 15_000), Duration::from_secs(18));
    }

    #[test]
    fn timeout_raises_sticky_floor_and_penalizes() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(1));
        assert!(!ctrl.is_degraded());
        assert_eq!(ctrl.current(), Duration::from_secs(5));
        ctrl.on_timeout();
        assert!(ctrl.is_degraded());
        assert_eq!(ctrl.floor_ms(), 15_000);
        // floor 15 + penalty 5
        assert_eq!(ctrl.current(), Duration::from_secs(20));
    }

    #[test]
    fn sticky_floor_does_not_snap_back() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(2));
        ctrl.on_timeout();
        assert!(ctrl.is_degraded());
        // Many healthy samples decay penalty but must NOT lower sticky floor.
        for _ in 0..50 {
            ctrl.inject_sample(Duration::from_millis(10));
        }
        assert!(ctrl.penalty_ms() <= 500);
        assert_eq!(ctrl.floor_ms(), 15_000, "sticky floor must not recover to min");
        assert!(ctrl.is_degraded());
        assert_eq!(ctrl.current(), Duration::from_secs(15));
    }

    #[test]
    fn slow_sample_does_not_raise_floor() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(3));
        ctrl.inject_sample(Duration::from_secs(6));
        assert!(!ctrl.is_degraded());
        assert_eq!(ctrl.floor_ms(), 5_000);
        assert_eq!(ctrl.ewma_ms(), 6000);
        // from_rtt = 2s + 8*6s → max 30s
        assert_eq!(ctrl.current(), Duration::from_secs(30));
    }

    #[test]
    fn durable_state_survives_new_ctrl() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let k = key(7);
        {
            let c1 = reg.ctrl_for(k);
            c1.on_timeout();
            assert!(c1.is_degraded());
            assert!(c1.penalty_ms() >= 5000);
        }
        let c2 = reg.ctrl_for(k);
        assert!(c2.is_degraded(), "reconnect must keep sticky floor");
        assert!(c2.penalty_ms() >= 5000);
        assert_eq!(c2.current(), Duration::from_secs(20));
    }

    #[test]
    fn fixed_mode_no_sticky_side_effects() {
        let mut cfg = AdaptiveTimeoutConfig::default();
        cfg.adaptive = false;
        cfg.fixed_or_initial = Duration::from_secs(12);
        let reg = PeerLivenessRegistry::new(cfg);
        let ctrl = reg.ctrl_for(key(8));
        ctrl.on_timeout();
        assert!(!ctrl.is_degraded());
        assert_eq!(ctrl.current(), Duration::from_secs(12));
        assert_eq!(ctrl.penalty_ms(), 0);
    }

    #[test]
    fn arm_reentry_keeps_epoch() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(4));
        let mut slot = None;
        let e1 = ctrl.arm(&mut slot);
        let e2 = ctrl.arm(&mut slot);
        assert_eq!(e1, e2);
    }

    #[test]
    fn snapshot_from_registry() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let k = key(9);
        let ctrl = reg.ctrl_for(k);
        ctrl.on_timeout();
        let snap = reg.snapshot(k).unwrap();
        assert!(snap.degraded);
        assert_eq!(snap.timeout_ms, 20_000);
        assert_eq!(snap.floor_ms, 15_000);
    }
}
