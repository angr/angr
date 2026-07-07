//! Stable structural hash for AIL data classes.
//!
//! Used by ``Expression.__hash__`` / ``Statement.__hash__`` / ``Block.__hash__``
//! on the Rust side. The value just needs to be:
//!
//! - **Deterministic within a process** -- cached hashes (see
//!   [`crate::ailment::base::CachedHash`]) must stay valid until the
//!   instance is mutated.
//! - **Well-distributed** -- Python uses the result as a dict / set
//!   key on every visit.
//! - **Cheap to compute** -- decompiles hash millions of AIL nodes.
//!
//! It does **not** need to match any external byte format (the per-class
//! Python AIL pyclasses are collapsed into a single Rust pyclass, so
//! there is no parallel Python value whose hash must match), and it is
//! never serialized -- so the exact byte stream is free to change.
//!
//! ## Implementation
//!
//! Each ``_hash_core`` writes its fields straight into an
//! [`rustc_hash::FxHasher`] through the [`AilHash`] extension methods.
//! There is no intermediate representation: the old design boxed every
//! field into a ``HashItem`` enum and collected a ``Vec<HashItem>`` per
//! hash before streaming it, which allocated on a path that runs on
//! millions of nodes. Writing directly removes that allocation and the
//! per-item enum dispatch.
//!
//! ``FxHasher`` (the hash rustc uses for its own symbol tables) is kept
//! as the backing [`Hasher`]: compiler-strength distribution for the
//! small-integer / short-string inputs that dominate AIL hashing,
//! deterministic (no random seed -- unlike ``RandomState``), and cheap
//! for tiny inputs (each write is one mul + rotate + xor, no
//! streaming-state setup).
//!
//! ## Collision discipline
//!
//! Every [`AilHash`] method writes a one-byte discriminant tag before
//! its payload, so two items carrying the same bit pattern under
//! different kinds (e.g. an [`AilHash::int`] and a mixed-in child hash
//! via [`AilHash::child`]) cannot alias. Sequences are length-prefixed
//! ([`AilHash::seq`]) so a nested group cannot alias with a flattened
//! one, and [`AilHash::string`] vs [`AilHash::typename`] use distinct
//! tags so the same text hashes differently as a value vs a class name.
//! (``str``/slice hashing already length-prefixes on its own.)

use std::hash::{Hash, Hasher};

use rustc_hash::FxHasher;

// One byte per item kind. The values themselves do not matter, only that
// each kind has a distinct discriminant.
const TAG_NONE: u8 = 1;
const TAG_BOOL: u8 = 2;
const TAG_INT: u8 = 3;
const TAG_CHILD: u8 = 4;
const TAG_STR: u8 = 5;
const TAG_TYPENAME: u8 = 6;
const TAG_SEQ: u8 = 7;
const TAG_RAW: u8 = 9;

/// A fresh, deterministic AIL hasher.
#[inline]
pub fn hasher() -> FxHasher {
    FxHasher::default()
}

/// Finish a hash, returning ``i64`` so callers can drop the result
/// directly into Python's signed-int hash slot.
#[inline]
pub fn finish(h: FxHasher) -> i64 {
    h.finish() as i64
}

/// Direct-write helpers over a [`Hasher`] -- the streaming replacement
/// for the old ``HashItem`` enum + ``stable_hash``. Each method writes a
/// discriminant tag then the payload straight into the hasher; see the
/// module docs for the collision discipline.
pub trait AilHash: Hasher + Sized {
    #[inline]
    fn none(&mut self) {
        self.write_u8(TAG_NONE);
    }
    #[inline]
    fn boolean(&mut self, b: bool) {
        self.write_u8(TAG_BOOL);
        self.write_u8(b as u8);
    }
    #[inline]
    fn int(&mut self, v: i128) {
        self.write_u8(TAG_INT);
        self.write_i128(v);
    }
    /// Mix in another node's already-computed structural hash (this is
    /// the memoization that keeps hashing amortized O(1) per node -- the
    /// child is not re-walked).
    #[inline]
    fn child(&mut self, h: i64) {
        self.write_u8(TAG_CHILD);
        self.write_i64(h);
    }
    #[inline]
    fn string(&mut self, s: &str) {
        self.write_u8(TAG_STR);
        s.hash(self);
    }
    /// A type / class name. Distinct tag from [`Self::string`] so
    /// ``string("Foo")`` and ``typename("Foo")`` hash differently.
    #[inline]
    fn typename(&mut self, s: &str) {
        self.write_u8(TAG_TYPENAME);
        s.hash(self);
    }
    /// Open a length-prefixed sequence of ``len`` items. The caller
    /// writes exactly ``len`` items after this; the length prevents a
    /// nested group from aliasing with a flattened one.
    #[inline]
    fn seq(&mut self, len: usize) {
        self.write_u8(TAG_SEQ);
        self.write_u64(len as u64);
    }
    #[inline]
    fn raw(&mut self, bytes: &[u8]) {
        self.write_u8(TAG_RAW);
        bytes.hash(self);
    }
    #[inline]
    fn opt_int(&mut self, v: Option<i128>) {
        match v {
            Some(x) => self.int(x),
            None => self.none(),
        }
    }
    #[inline]
    fn opt_child(&mut self, h: Option<i64>) {
        match h {
            Some(x) => self.child(x),
            None => self.none(),
        }
    }
}

impl<H: Hasher> AilHash for H {}

#[cfg(test)]
mod tests {
    use super::*;

    fn h1(f: impl FnOnce(&mut FxHasher)) -> i64 {
        let mut h = hasher();
        f(&mut h);
        finish(h)
    }

    #[test]
    fn empty_input_is_deterministic() {
        assert_eq!(h1(|_| {}), h1(|_| {}));
    }

    #[test]
    fn distinct_kinds_with_same_value_differ() {
        // int(5), child(5), boolean(true) share the bit pattern of 5 but
        // must not collide because of the tag byte.
        let a = h1(|h| h.int(5));
        let b = h1(|h| h.child(5));
        let c = h1(|h| h.boolean(true));
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn string_and_typename_with_same_text_differ() {
        assert_ne!(h1(|h| h.string("Const")), h1(|h| h.typename("Const")));
    }

    #[test]
    fn concatenation_does_not_alias_with_split() {
        // string("ab") + string("c") vs string("a") + string("bc") --
        // str::hash length-prefixes, so these cannot collide.
        let a = h1(|h| {
            h.string("ab");
            h.string("c");
        });
        let b = h1(|h| {
            h.string("a");
            h.string("bc");
        });
        assert_ne!(a, b);
    }

    #[test]
    fn nested_sequence_does_not_alias_with_flat() {
        let flat = h1(|h| {
            h.int(1);
            h.int(2);
        });
        let nested = h1(|h| {
            h.seq(2);
            h.int(1);
            h.int(2);
        });
        assert_ne!(flat, nested);
    }

    #[test]
    fn none_writes_just_a_tag() {
        let n1 = h1(|h| h.none());
        let n2 = h1(|h| h.none());
        assert_eq!(n1, n2);
        assert_ne!(n1, h1(|h| h.int(0)));
        assert_ne!(n1, h1(|h| h.boolean(false)));
    }
}
