//! Adaptive peer liveness timeout with Normal / Degraded modes.
//!
//! After a non-keepalive send, the peer writer arms a read deadline. If no
//! frame arrives in time, the reader tears down the link (`Error::Timeout`).
//!
//! ## Adaptive (default)
//!
//! ```text
//! raw = base + rtt_mult * ewma(arm→first_inbound_frame)  # or floor if no samples
//! T   = clamp(raw + penalty, floor(mode), max)
//! ```
//!
//! - **Normal** floor = `min` (default 5s).
//! - **Degraded** floor = `problem_min` (default 15s) — entered **only** on
//!   liveness timeout (not on slow samples; samples update EWMA only).
//! - Sample semantics: time from **first arm of this deadline epoch** until any
//!   inbound frame (not a pure RTT probe). Re-arms while already armed do not
//!   reset the sample clock (matches one-shot deadline policy).
//! - Durable state (mode, ewma, penalty) is **per peer public key** and survives
//!   reconnects via [`PeerLivenessRegistry`].
//! - Recovery to Normal after `recover` without timeouts, low penalty, modest ewma.
//! - Mode transitions log once at INFO with peer key prefix (no spam).

use rustc_hash::FxHashMap as HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::PublicKey;

const MODE_NORMAL: u8 = 0;
const MODE_DEGRADED: u8 = 1;

/// Configuration for peer liveness deadlines.
#[derive(Clone, Debug)]
pub struct AdaptiveTimeoutConfig {
    /// Fixed timeout when `adaptive` is false.
    pub fixed_or_initial: Duration,
    /// Enable adaptive sizing + Normal/Degraded. Default: true.
    pub adaptive: bool,
    /// Normal-mode floor. Default: 5s.
    pub min: Duration,
    /// Degraded-mode floor. Default: 15s.
    pub problem_min: Duration,
    /// Ceiling. Default: 30s.
    pub max: Duration,
    /// Added to RTT-based estimate. Default: 2s.
    pub base: Duration,
    /// Multiplier for EWMA(arm→reply). Default: 8.
    pub rtt_mult: u32,
    /// Penalty step after a liveness timeout. Default: 5s.
    pub penalty_step: Duration,
    /// Penalty decay per healthy sample. Default: 500ms.
    pub penalty_decay: Duration,
    /// Time without timeouts before leaving Degraded. Default: 10 minutes.
    pub recover: Duration,
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
            recover: Duration::from_secs(10 * 60),
        }
    }
}

impl AdaptiveTimeoutConfig {
    /// Validate invariants. Call at config load.
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
        if self.recover.is_zero() {
            return Err("peer_timeout_recover_secs must be > 0".into());
        }
        if !self.adaptive && self.fixed_or_initial.is_zero() {
            return Err("peer_timeout_secs must be > 0 in fixed mode".into());
        }
        Ok(())
    }

    pub fn floor(&self, degraded: bool) -> Duration {
        if degraded {
            self.problem_min.max(self.min)
        } else {
            self.min
        }
    }

    pub fn compute(&self, ewma_ms: u64, penalty_ms: u64, degraded: bool) -> Duration {
        if !self.adaptive {
            // Exact fixed value; do not silently clamp to min/max without docs.
            return self.fixed_or_initial;
        }

        let floor = self.floor(degraded);
        let min_ms = floor.as_millis() as u64;
        let max_ms = self.max.as_millis() as u64;
        let base_ms = self.base.as_millis() as u64;
        let mult = self.rtt_mult as u64;
        let from_rtt = if ewma_ms == 0 {
            min_ms
        } else {
            base_ms.saturating_add(mult.saturating_mul(ewma_ms))
        };
        let total = from_rtt.saturating_add(penalty_ms);
        Duration::from_millis(total.clamp(min_ms, max_ms))
    }
}

/// Snapshot for admin / getPeers.
#[derive(Clone, Debug, Default)]
pub struct LivenessSnapshot {
    pub timeout_ms: u64,
    pub ewma_ms: u64,
    pub penalty_ms: u64,
    pub degraded: bool,
}

/// Durable state shared across reconnects for one peer public key.
struct DurableLiveness {
    ewma_ms: AtomicU64,
    penalty_ms: AtomicU64,
    mode: AtomicU8,
    /// Updated **only** on liveness timeout (not on slow samples).
    last_timeout_at: Mutex<Option<Instant>>,
}

impl DurableLiveness {
    fn new() -> Self {
        Self {
            ewma_ms: AtomicU64::new(0),
            penalty_ms: AtomicU64::new(0),
            mode: AtomicU8::new(MODE_NORMAL),
            last_timeout_at: Mutex::new(None),
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
        let durable = {
            let mut map = self.map.lock().unwrap();
            map.entry(key)
                .or_insert_with(|| Arc::new(DurableLiveness::new()))
                .clone()
        };
        Arc::new(PeerTimeoutCtrl {
            cfg: self.cfg.clone(),
            key,
            durable,
            armed_at: Mutex::new(None),
            armed_timeout: Mutex::new(None),
        })
    }

    pub fn snapshot(&self, key: PublicKey) -> Option<LivenessSnapshot> {
        let map = self.map.lock().unwrap();
        let d = map.get(&key)?;
        let ewma = d.ewma_ms.load(Ordering::Relaxed);
        let pen = d.penalty_ms.load(Ordering::Relaxed);
        let degraded = d.mode.load(Ordering::Relaxed) == MODE_DEGRADED;
        let timeout = self.cfg.compute(ewma, pen, degraded);
        Some(LivenessSnapshot {
            timeout_ms: timeout.as_millis() as u64,
            ewma_ms: ewma,
            penalty_ms: pen,
            degraded,
        })
    }
}

/// Per-connection controller (session-local arm clock + shared durable state).
pub struct PeerTimeoutCtrl {
    cfg: AdaptiveTimeoutConfig,
    key: PublicKey,
    durable: Arc<DurableLiveness>,
    /// First arm of the current deadline epoch (sample clock).
    armed_at: Mutex<Option<Instant>>,
    /// Timeout duration used when this epoch was armed (for accurate logs).
    armed_timeout: Mutex<Option<Duration>>,
}

impl PeerTimeoutCtrl {
    pub fn is_degraded(&self) -> bool {
        self.durable.mode.load(Ordering::Relaxed) == MODE_DEGRADED
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// Timeout used for the current armed epoch, if any.
    pub fn last_armed_timeout(&self) -> Option<Duration> {
        *self.armed_timeout.lock().unwrap()
    }

    pub fn current(&self) -> Duration {
        let ewma = self.durable.ewma_ms.load(Ordering::Relaxed);
        let pen = self.durable.penalty_ms.load(Ordering::Relaxed);
        let degraded = self.is_degraded();
        self.cfg.compute(ewma, pen, degraded)
    }

    /// Arm a deadline. If already armed, leave epoch unchanged (one-shot deadline).
    pub fn arm(&self, deadline_slot: &mut Option<Instant>) -> Instant {
        self.maybe_recover();
        if let Some(existing) = *deadline_slot {
            return existing;
        }
        let now = Instant::now();
        let t = self.current();
        let expires = now + t;
        *deadline_slot = Some(expires);
        *self.armed_at.lock().unwrap() = Some(now);
        *self.armed_timeout.lock().unwrap() = Some(t);
        tracing::trace!(
            peer = %hex_prefix(&self.key),
            timeout_ms = t.as_millis() as u64,
            ewma_ms = self.durable.ewma_ms.load(Ordering::Relaxed),
            penalty_ms = self.durable.penalty_ms.load(Ordering::Relaxed),
            degraded = self.is_degraded(),
            "peer liveness deadline armed"
        );
        expires
    }

    /// Clear deadline after any inbound frame; update EWMA only (no Degraded from sample).
    pub fn clear_on_reply(&self, deadline_slot: &mut Option<Instant>) {
        *deadline_slot = None;
        let armed = self.armed_at.lock().unwrap().take();
        *self.armed_timeout.lock().unwrap() = None;
        if let Some(t0) = armed {
            self.observe_sample(t0.elapsed());
        }
        self.maybe_recover();
    }

    /// Liveness timeout fired. `armed_timeout` should be captured before this if logging.
    pub fn on_timeout(&self) {
        let armed_t = self.armed_timeout.lock().unwrap().take();
        // Penalty first so enter_degraded / logs see post-timeout budget.
        let step = self.cfg.penalty_step.as_millis() as u64;
        let max_ms = self.cfg.max.as_millis() as u64;
        let _ = self.durable.penalty_ms.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |p| Some(p.saturating_add(step).min(max_ms)),
        );
        *self.armed_at.lock().unwrap() = None;
        *self.durable.last_timeout_at.lock().unwrap() = Some(Instant::now());
        self.enter_degraded("liveness_timeout");
        tracing::debug!(
            peer = %hex_prefix(&self.key),
            armed_timeout_ms = armed_t.map(|d| d.as_millis() as u64).unwrap_or(0),
            penalty_ms = self.durable.penalty_ms.load(Ordering::Relaxed),
            next_timeout_ms = self.current().as_millis() as u64,
            "peer liveness timeout — penalty increased"
        );
    }

    fn enter_degraded(&self, reason: &'static str) {
        if !self.cfg.adaptive {
            return;
        }
        let prev = self.durable.mode.swap(MODE_DEGRADED, Ordering::Relaxed);
        if prev == MODE_NORMAL {
            let next = self.cfg.compute(
                self.durable.ewma_ms.load(Ordering::Relaxed),
                self.durable.penalty_ms.load(Ordering::Relaxed),
                true,
            );
            tracing::info!(
                peer = %hex_prefix(&self.key),
                reason,
                problem_min_ms = self.cfg.problem_min.as_millis() as u64,
                next_timeout_ms = next.as_millis() as u64,
                "peer liveness entered Degraded mode"
            );
        }
    }

    /// Recover only after `recover` since **last timeout**, low penalty, modest ewma.
    fn maybe_recover(&self) {
        if !self.cfg.adaptive || !self.is_degraded() {
            return;
        }
        let last = match *self.durable.last_timeout_at.lock().unwrap() {
            Some(t) => t,
            None => {
                // Degraded without timeout timestamp (shouldn't happen) — allow recover clock from now.
                return;
            }
        };
        if last.elapsed() < self.cfg.recover {
            return;
        }
        let pen = self.durable.penalty_ms.load(Ordering::Relaxed);
        let ewma = self.durable.ewma_ms.load(Ordering::Relaxed);
        let modest_rtt = ewma == 0 || ewma < self.cfg.min.as_millis() as u64;
        // penalty fully decayed (allow small residual)
        if pen > 500 || !modest_rtt {
            return;
        }
        let prev = self.durable.mode.swap(MODE_NORMAL, Ordering::Relaxed);
        if prev == MODE_DEGRADED {
            tracing::info!(
                peer = %hex_prefix(&self.key),
                normal_min_ms = self.cfg.min.as_millis() as u64,
                "peer liveness recovered to Normal mode"
            );
        }
    }

    fn observe_sample(&self, sample: Duration) {
        // Cap absurd samples (age since first arm of epoch).
        let sample_ms = sample.as_millis().min(self.cfg.max.as_millis()) as u64;
        if sample_ms == 0 {
            return;
        }

        // EWMA only — do NOT auto-Degrade on slow samples (avoids false positives
        // when "any frame" arrives near the deadline on busy links).
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

    pub fn snapshot(&self) -> LivenessSnapshot {
        let ewma = self.ewma_ms();
        let pen = self.penalty_ms();
        let degraded = self.is_degraded();
        LivenessSnapshot {
            timeout_ms: self.cfg.compute(ewma, pen, degraded).as_millis() as u64,
            ewma_ms: ewma,
            penalty_ms: pen,
            degraded,
        }
    }

    /// Test helpers — inject sample / age last_timeout without real wall-clock waits.
    #[cfg(test)]
    fn inject_sample(&self, sample: Duration) {
        self.observe_sample(sample);
    }

    #[cfg(test)]
    fn set_last_timeout_ago(&self, ago: Duration) {
        *self.durable.last_timeout_at.lock().unwrap() = Some(Instant::now() - ago);
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
        assert_eq!(cfg.compute(0, 0, false), Duration::from_secs(12));
        assert_eq!(cfg.compute(9999, 0, true), Duration::from_secs(12));
    }

    #[test]
    fn normal_stays_at_five_with_low_rtt() {
        let cfg = AdaptiveTimeoutConfig::default();
        assert_eq!(cfg.compute(0, 0, false), Duration::from_secs(5));
        assert_eq!(cfg.compute(10, 0, false), Duration::from_secs(5));
    }

    #[test]
    fn degraded_floor_fifteen() {
        let cfg = AdaptiveTimeoutConfig::default();
        assert_eq!(cfg.compute(10, 0, true), Duration::from_secs(15));
        assert_eq!(cfg.compute(2000, 0, true), Duration::from_secs(18));
    }

    #[test]
    fn timeout_degrades_and_penalizes() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(1));
        assert!(!ctrl.is_degraded());
        assert_eq!(ctrl.current(), Duration::from_secs(5));
        ctrl.on_timeout();
        assert!(ctrl.is_degraded());
        assert_eq!(ctrl.current(), Duration::from_secs(20));
    }

    #[test]
    fn slow_sample_does_not_degrade() {
        let reg = PeerLivenessRegistry::new(AdaptiveTimeoutConfig::default());
        let ctrl = reg.ctrl_for(key(2));
        assert!(!ctrl.is_degraded());
        // Sample ≥ Normal min (5s) used to force Degraded; must only update EWMA.
        ctrl.inject_sample(Duration::from_secs(6));
        assert!(!ctrl.is_degraded(), "slow sample must not enter Degraded");
        assert_eq!(ctrl.ewma_ms(), 6000);
        // from_rtt = 2s + 8*6s → clamped to max 30s; mode stays Normal.
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
        assert!(c2.is_degraded(), "reconnect must keep Degraded");
        assert!(c2.penalty_ms() >= 5000);
        assert_eq!(c2.current(), Duration::from_secs(20));
    }

    #[test]
    fn recovery_after_timeout_age_and_low_penalty() {
        let mut cfg = AdaptiveTimeoutConfig::default();
        cfg.recover = Duration::from_millis(50);
        let reg = PeerLivenessRegistry::new(cfg);
        let ctrl = reg.ctrl_for(key(3));
        ctrl.on_timeout();
        assert!(ctrl.is_degraded());
        assert_eq!(ctrl.penalty_ms(), 5000);

        // Decay penalty: 500ms per healthy sample → 10 samples clears 5s step.
        for _ in 0..12 {
            ctrl.inject_sample(Duration::from_millis(10));
        }
        assert!(ctrl.penalty_ms() <= 500, "penalty should decay on healthy samples");
        assert!(ctrl.ewma_ms() < 5000, "ewma stays under Normal min for recover");

        // Age last_timeout past recover window (no wall-clock sleep race).
        ctrl.set_last_timeout_ago(Duration::from_millis(100));

        // arm() / clear_on_reply() call maybe_recover.
        let mut slot = None;
        ctrl.arm(&mut slot);
        assert!(!ctrl.is_degraded(), "must recover to Normal after quiet + low penalty");
        // ewma ~10ms → from_rtt under Normal floor → 5s.
        assert_eq!(ctrl.current(), Duration::from_secs(5));
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
    }
}
