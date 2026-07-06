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
//! The previous implementation mirrored Python's
//! ``angr.ailment.utils.stable_hash`` byte format and ran the result
//! through MD5 -- holding both an exact-format requirement and a
//! cryptographic-strength hash. The format match was no longer needed
//! (Phase D collapsed the per-class Python AIL pyclasses into a single
//! Rust pyclass, so there is no parallel Python value whose hash needs
//! to match) and the MD5 strength was overkill.
//!
//! ## Implementation
//!
//! We use [`rustc_hash::FxHasher`] -- the same hash rustc uses for its
//! internal symbol tables. It is:
//!
//! - Compiler-strength quality (well-distributed for the small-integer
//!   / short-string inputs that dominate AIL hashing).
//! - Deterministic (no random seed).
//! - Trivially fast for short inputs -- each ``write_u8`` is one mul +
//!   one rotate + one xor, with no streaming-state setup overhead. An
//!   intermediate ``xxh3`` attempt over a tagged + length-prefixed
//!   byte stream was ~2.4x *slower* than the original MD5 path for
//!   typical AIL inputs because of streaming-state overhead and the
//!   length-prefix padding on tiny payloads. FxHasher sidesteps both.
//!
//! The std [`Hash`] trait handles disambiguation: ``str::hash`` writes
//! a length prefix, slices include their length, and our per-variant
//! discriminant byte separates payloads. ``Str`` vs ``TypeName`` get
//! distinct discriminants so the same text under each variant hashes
//! differently.

use std::hash::{Hash, Hasher};

use rustc_hash::FxHasher;

/// One item in a [`stable_hash`] input stream.
#[derive(Debug, Clone)]
pub enum HashItem<'a> {
    None,
    Bool(bool),
    Int(i128),
    /// A precomputed unsigned 64-bit hash (typically another AIL node's
    /// already-cached structural hash, mixed in by reference).
    U64Hash(u64),
    Str(&'a str),
    /// A Python class name; same payload as ``Str`` but a distinct
    /// discriminant so ``Str("Foo")`` and ``TypeName("Foo")`` hash
    /// differently.
    TypeName(&'a str),
    /// Nested tuple. Bracketed in the stream so a flat sequence cannot
    /// alias with a nested one of the same items.
    Tuple(Vec<HashItem<'a>>),
    /// Pre-rendered bytes (escape hatch for callers that already know
    /// how to project themselves into the hash stream).
    Raw(Vec<u8>),
}

// One byte per variant -- the values themselves do not matter, only
// that each variant has a distinct discriminant.
const TAG_NONE: u8 = 1;
const TAG_BOOL: u8 = 2;
const TAG_INT: u8 = 3;
const TAG_U64HASH: u8 = 4;
const TAG_STR: u8 = 5;
const TAG_TYPENAME: u8 = 6;
const TAG_TUPLE_OPEN: u8 = 7;
const TAG_TUPLE_CLOSE: u8 = 8;
const TAG_RAW: u8 = 9;

fn write_item(h: &mut FxHasher, item: &HashItem<'_>) {
    match item {
        HashItem::None => h.write_u8(TAG_NONE),
        HashItem::Bool(b) => {
            h.write_u8(TAG_BOOL);
            h.write_u8(*b as u8);
        }
        HashItem::Int(v) => {
            h.write_u8(TAG_INT);
            h.write_i128(*v);
        }
        HashItem::U64Hash(v) => {
            h.write_u8(TAG_U64HASH);
            h.write_u64(*v);
        }
        HashItem::Str(s) => {
            h.write_u8(TAG_STR);
            s.hash(h);
        }
        HashItem::TypeName(s) => {
            h.write_u8(TAG_TYPENAME);
            s.hash(h);
        }
        HashItem::Tuple(items) => {
            h.write_u8(TAG_TUPLE_OPEN);
            for inner in items {
                write_item(h, inner);
            }
            h.write_u8(TAG_TUPLE_CLOSE);
        }
        HashItem::Raw(bytes) => {
            h.write_u8(TAG_RAW);
            bytes.as_slice().hash(h);
        }
    }
}

/// Compute the stable hash of a sequence of items.
///
/// Returns ``i64`` (not ``u64``) so callers can drop the result
/// directly into Python's signed-int hash slot.
pub fn stable_hash(items: &[HashItem<'_>]) -> i64 {
    let mut h = FxHasher::default();
    for item in items {
        write_item(&mut h, item);
    }
    h.finish() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_deterministic() {
        assert_eq!(stable_hash(&[]), stable_hash(&[]));
    }

    #[test]
    fn distinct_variants_with_same_value_differ() {
        // ``Int(5)``, ``U64Hash(5)``, ``Bool(true)`` all share the bit
        // pattern of ``5`` but should not collide because of the tag byte.
        let a = stable_hash(&[HashItem::Int(5)]);
        let b = stable_hash(&[HashItem::U64Hash(5)]);
        let c = stable_hash(&[HashItem::Bool(true)]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn str_and_typename_with_same_text_differ() {
        let a = stable_hash(&[HashItem::Str("Const")]);
        let b = stable_hash(&[HashItem::TypeName("Const")]);
        assert_ne!(a, b);
    }

    #[test]
    fn concatenation_does_not_alias_with_split() {
        // ``Str("ab") + Str("c")`` vs ``Str("a") + Str("bc")`` --
        // std's ``str::hash`` writes a length prefix so these cannot
        // collide.
        let a = stable_hash(&[HashItem::Str("ab"), HashItem::Str("c")]);
        let b = stable_hash(&[HashItem::Str("a"), HashItem::Str("bc")]);
        assert_ne!(a, b);
    }

    #[test]
    fn nested_tuple_does_not_alias_with_flat() {
        let flat = stable_hash(&[HashItem::Int(1), HashItem::Int(2)]);
        let nested = stable_hash(&[HashItem::Tuple(vec![HashItem::Int(1), HashItem::Int(2)])]);
        assert_ne!(flat, nested);
    }

    #[test]
    fn none_writes_just_a_tag() {
        let n1 = stable_hash(&[HashItem::None]);
        let n2 = stable_hash(&[HashItem::None]);
        assert_eq!(n1, n2);
        assert_ne!(n1, stable_hash(&[HashItem::Int(0)]));
        assert_ne!(n1, stable_hash(&[HashItem::Bool(false)]));
    }
}
