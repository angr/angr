//! Rust port of `angr.ailment` data classes.
//!
//! Exposed Python-side as `angr.rustylib.ailment`.
//!
//! There are two Python-facing pyclasses,
//! ``Expression`` and ``Statement``, each wrapping an inline fat-enum
//! (``ExprInner`` / ``StmtInner``) carrying per-variant data. Per-class
//! marker types (``Const``, ``BinaryOp``, ``Assignment``, ...) live on
//! the Python side and dispatch via metaclass ``__instancecheck__`` on
//! the variant tag.

pub mod ail_expr;
pub mod ail_stmt;
pub mod block;
pub mod const_value;
pub mod enums;
pub mod serialize;
pub mod tags;
pub mod utils;

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::wrap_pyfunction;
use rustc_hash::FxHasher;

pub fn ailment(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Tags
    m.add_class::<tags::TagsView>()?;
    m.add_class::<tags::TagsKeyIter>()?;

    // Enums
    m.add_class::<enums::VirtualVariableCategory>()?;
    m.add_class::<enums::ConvertType>()?;
    m.add_class::<enums::RoundingMode>()?;
    m.add_class::<enums::ExpressionKind>()?;
    m.add_class::<enums::StatementKind>()?;

    // Fat-enum pyclasses. ``Expression`` wraps the ``AilExpression``
    // sum, ``Statement`` wraps the ``AilStatement`` sum. Per-variant
    // marker classes live on the Python side; see
    // ``angr/ailment/expression.py`` and ``angr/ailment/statement.py``.
    m.add_class::<ail_expr::Expression>()?;
    m.add_class::<ail_stmt::Statement>()?;

    // Block.
    m.add_class::<block::Block>()?;

    // Module-level byte serialization helpers.
    m.add_function(wrap_pyfunction!(serialize::py_dumps, m)?)?;
    m.add_function(wrap_pyfunction!(serialize::py_loads, m)?)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Cross-module hashing utilities: the ``CachedHash`` slot used by the
// ``ExprHeader`` / ``StmtHeader`` structs in ``ail_expr`` / ``ail_stmt``,
// and the ``hash_of`` entry point that turns a ``Hash`` impl into the
// ``i64`` Python's hash slot expects.
// ---------------------------------------------------------------------------

/// Hash a value through its [`Hash`] impl and return the ``i64`` Python
/// expects in its signed-int hash slot. One-shot entry point for the
/// ``cached_hash_or_compute`` memoizers and ``__hash__`` methods.
///
/// The value must be:
///
/// - **Process-independent** -- for a given build, the same AIL node
///   hashes to the same value in every process, so hashes can be
///   compared across e.g. multiprocessing workers. (Cached hashes --
///   see [`CachedHash`] -- must in particular stay valid until the
///   instance is mutated.) It is **not** required to be stable across
///   builds: the value is never serialized, so a rebuild is free to
///   change it.
/// - **Well-distributed** -- Python uses the result as a dict / set
///   key on every visit.
/// - **Cheap to compute** -- decompiles hash millions of AIL nodes.
///
/// ``FxHasher`` (the hash rustc uses for its own symbol tables) is the
/// backing [`Hasher`]: it has no per-process random state (unlike
/// ``RandomState``, which would break cross-process comparison), and it
/// is the cheapest option for the small-integer / short-string inputs
/// that dominate AIL hashing (each write is one mul + rotate + xor, no
/// streaming-state setup).
#[inline]
pub fn hash_of<T: Hash + ?Sized>(v: &T) -> i64 {
    let mut h = FxHasher::default();
    v.hash(&mut h);
    h.finish() as i64
}

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
