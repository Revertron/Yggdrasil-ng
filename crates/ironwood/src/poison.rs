//! Locking that never panics.
//!
//! A poisoned lock means some code panicked while holding it. Nothing in this
//! crate panics any more, so poison can only originate in a dependency — but
//! once a `std` lock is poisoned it stays poisoned for its lifetime, so the
//! failure is permanent and would otherwise repeat on every acquisition.
//!
//! That shapes the two halves of this module. [`PoisonLog`] logs at most once per
//! call site, because an unthrottled log would fire per packet. And there are two
//! macros per lock kind:
//!
//! - `lock!` / `read_lock!` / `write_lock!` yield a `Result`, for a caller that
//!   *can* act on half-updated state — drop the packet, deny the flow, skip the
//!   cycle. The `Err` arm is where that decision is written down.
//! - `lock_recover!` and friends hand the guard straight back, for a caller that
//!   cannot. There the once-only log is the whole handling.
//!
//! Recovering is a deliberate choice over propagating a `PoisonError` to the top:
//! the alternative is tearing down every session because one lock was touched by
//! an unrelated panic.
//!
//! The macro set is kept complete and identical in both crates even though each
//! uses only part of it, so a lock added in one place does not need a different
//! spelling from the same job in the other.

#![allow(unused_macros)]

use std::sync::atomic::{AtomicBool, Ordering};

/// Marker: the lock was poisoned, and the caller has to say what it does about it.
#[derive(Debug)]
pub(crate) struct Poisoned;

/// Per-call-site latch, so a permanently poisoned lock logs once and not per packet.
pub(crate) struct PoisonLog {
    logged: AtomicBool,
}

impl PoisonLog {
    pub(crate) const fn new() -> Self {
        Self {
            logged: AtomicBool::new(false),
        }
    }

    /// Log this site the first time it reports poison; quiet afterwards.
    pub(crate) fn log(&self, site: &'static str) {
        if self
            .logged
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            tracing::error!(
                site,
                "lock poisoned by a panic elsewhere; state behind it may be inconsistent"
            );
        }
    }
}

/// Acquire a `std::sync::Mutex`, reporting poison instead of panicking.
macro_rules! lock {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.lock() {
            Ok(guard) => Ok(guard),
            Err(_) => {
                POISON_LOG.log(stringify!($lock));
                Err($crate::poison::Poisoned)
            }
        }
    }};
}

/// Acquire a `std::sync::Mutex` where nothing can be done about poison but log it.
macro_rules! lock_recover {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                POISON_LOG.log(stringify!($lock));
                poisoned.into_inner()
            }
        }
    }};
}

/// Reading counterpart of [`lock!`].
macro_rules! read_lock {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.read() {
            Ok(guard) => Ok(guard),
            Err(_) => {
                POISON_LOG.log(stringify!($lock));
                Err($crate::poison::Poisoned)
            }
        }
    }};
}

/// Writing counterpart of [`lock!`].
macro_rules! write_lock {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.write() {
            Ok(guard) => Ok(guard),
            Err(_) => {
                POISON_LOG.log(stringify!($lock));
                Err($crate::poison::Poisoned)
            }
        }
    }};
}

/// Reading counterpart of [`lock_recover!`].
macro_rules! read_lock_recover {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                POISON_LOG.log(stringify!($lock));
                poisoned.into_inner()
            }
        }
    }};
}

/// Writing counterpart of [`lock_recover!`].
macro_rules! write_lock_recover {
    ($lock:expr) => {{
        static POISON_LOG: $crate::poison::PoisonLog = $crate::poison::PoisonLog::new();
        match $lock.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                POISON_LOG.log(stringify!($lock));
                poisoned.into_inner()
            }
        }
    }};
}
