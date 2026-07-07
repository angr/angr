//! Cross-module utilities for the AIL data classes.
//!
//! With the per-class pyclasses collapsed into a single
//! ``Expression`` / ``Statement`` pair, the only piece of shared state
//! in this module is the ``CachedHash`` slot used by the
//! ``ExprHeader`` / ``StmtHeader`` structs in ``ail_expr`` / ``ail_stmt``.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

/// Cached hash slot: an `i64` payload plus a separate presence flag.
///
/// The flag means the full `i64` range is a valid cached hash -- no value
/// is reserved as an "unset" sentinel. (The previous implementation used
/// `i64::MIN` as the sentinel and silently remapped a real hash of
/// `i64::MIN` to `i64::MIN + 1`, colliding with the genuine hash of
/// `i64::MIN + 1`.)
#[derive(Debug)]
pub struct CachedHash {
    hash: AtomicI64,
    present: AtomicBool,
}

impl CachedHash {
    pub fn new() -> Self {
        Self {
            hash: AtomicI64::new(0),
            present: AtomicBool::new(false),
        }
    }

    pub fn get(&self) -> Option<i64> {
        // ``Acquire`` on the flag pairs with the ``Release`` in ``set`` so
        // a reader that observes ``present`` also sees the hash write.
        if self.present.load(Ordering::Acquire) {
            Some(self.hash.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    pub fn set(&self, v: i64) {
        self.hash.store(v, Ordering::Relaxed);
        self.present.store(true, Ordering::Release);
    }

    pub fn clear(&self) {
        self.present.store(false, Ordering::Release);
    }
}

impl Clone for CachedHash {
    fn clone(&self) -> Self {
        Self {
            hash: AtomicI64::new(self.hash.load(Ordering::Relaxed)),
            present: AtomicBool::new(self.present.load(Ordering::Relaxed)),
        }
    }
}

impl Default for CachedHash {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_by_default() {
        assert_eq!(CachedHash::new().get(), None);
    }

    #[test]
    fn every_i64_round_trips() {
        // The full i64 range is storable, including the values the old
        // i64::MIN-sentinel scheme corrupted.
        for v in [0i64, 1, -1, i64::MAX, i64::MIN, i64::MIN + 1] {
            let c = CachedHash::new();
            c.set(v);
            assert_eq!(c.get(), Some(v), "value {v} did not round-trip");
        }
    }

    #[test]
    fn clear_resets_presence() {
        let c = CachedHash::new();
        c.set(i64::MIN);
        assert_eq!(c.get(), Some(i64::MIN));
        c.clear();
        assert_eq!(c.get(), None);
    }

    #[test]
    fn clone_preserves_state() {
        let set = CachedHash::new();
        set.set(i64::MIN);
        assert_eq!(set.clone().get(), Some(i64::MIN));
        assert_eq!(CachedHash::new().clone().get(), None);
    }
}
