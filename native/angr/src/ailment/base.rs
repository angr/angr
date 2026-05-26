//! Cross-module utilities for the AIL data classes.
//!
//! After Phase D collapsed the per-class pyclasses into a single
//! ``Expression`` / ``Statement`` pair, the only piece of shared state
//! left in this module is the ``CachedHash`` slot used by the
//! ``ExprHeader`` / ``StmtHeader`` structs in ``ail_expr`` / ``ail_stmt``.

use std::sync::atomic::{AtomicI64, Ordering};

/// Cached hash slot. `i64::MIN` is the sentinel for "unset".
#[derive(Debug)]
pub struct CachedHash(AtomicI64);

impl CachedHash {
    pub fn new() -> Self {
        Self(AtomicI64::new(i64::MIN))
    }

    pub fn get(&self) -> Option<i64> {
        let v = self.0.load(Ordering::Relaxed);
        if v == i64::MIN { None } else { Some(v) }
    }

    pub fn set(&self, v: i64) {
        // Avoid the sentinel collision; -1 is a common Python `hash` value
        // for the int -1, so we can't safely use it. i64::MIN is far enough
        // out of range that real `_hash_core` results won't collide with it.
        let stored = if v == i64::MIN { i64::MIN + 1 } else { v };
        self.0.store(stored, Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.0.store(i64::MIN, Ordering::Relaxed);
    }
}

impl Clone for CachedHash {
    fn clone(&self) -> Self {
        Self(AtomicI64::new(self.0.load(Ordering::Relaxed)))
    }
}

impl Default for CachedHash {
    fn default() -> Self {
        Self::new()
    }
}
