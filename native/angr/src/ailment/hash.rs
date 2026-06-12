//! Port of `angr.ailment.utils.stable_hash`.
//!
//! The Python implementation MD5s a serialized form of a tuple and returns the
//! first 32 bits as an int. We reproduce the exact byte format so that hashes
//! computed in Rust agree with hashes computed in Python.
//!
//! Encoding rules (see `_dump_tuple` / `_dump_int` / `_dump_str` /
//! `_dump_type` in `angr/ailment/utils.py`):
//! * `None`           -> 0 bytes
//! * `str`            -> UTF-8 bytes
//! * `int`            -> optional `b"-"` prefix when negative, then little-endian
//!   u16 / u32 / u64 chunks (smallest that fits the absolute value, with larger
//!   ints recursively encoded in 64-bit chunks).
//! * Python `type`    -> the class name as ASCII bytes
//! * tuple            -> concatenation of dumped elements
//! * Anything else    -> `hash(item) & 0xFFFF_FFFF_FFFF_FFFF` packed as little-
//!   endian u64 (we use that escape hatch for nested PyObjects whose
//!   `__hash__` is stable).
//!
//! Each element (including `None`) is followed by a single `0xF0` separator byte.

use md5::{Digest, Md5};

/// Byte-level item used to build a `stable_hash` input.
#[derive(Debug, Clone)]
pub enum HashItem<'a> {
    None,
    Bool(bool),
    Int(i128),
    /// A precomputed unsigned 64-bit hash (used for foreign objects whose
    /// Python `__hash__` we trust to be stable).
    U64Hash(u64),
    Str(&'a str),
    /// A Python class name; encoded as raw ASCII bytes (no length prefix).
    TypeName(&'a str),
    /// Nested tuple.
    Tuple(Vec<HashItem<'a>>),
    /// Pre-dumped bytes (escape hatch for items that already know how to render
    /// themselves into the stable-hash byte stream).
    Raw(Vec<u8>),
}

impl<'a> HashItem<'a> {
    fn is_none(&self) -> bool {
        matches!(self, HashItem::None)
    }
}

fn dump_int(buf: &mut Vec<u8>, v: i128) {
    if v < 0 {
        buf.push(b'-');
    }
    dump_unsigned(buf, v.unsigned_abs());
}

fn dump_unsigned(buf: &mut Vec<u8>, u: u128) {
    if u <= 0xFFFF {
        buf.extend_from_slice(&(u as u16).to_le_bytes());
    } else if u <= 0xFFFF_FFFF {
        buf.extend_from_slice(&(u as u32).to_le_bytes());
    } else if u <= 0xFFFF_FFFF_FFFF_FFFF {
        buf.extend_from_slice(&(u as u64).to_le_bytes());
    } else {
        // Mirror Python's recursion: emit 64-bit chunks, low to high, each
        // chunk re-encoded by the smaller-int rules.
        let mut remaining = u;
        while remaining > 0 {
            let chunk = remaining & 0xFFFF_FFFF_FFFF_FFFF;
            dump_unsigned(buf, chunk);
            remaining >>= 64;
        }
    }
}

fn dump_item(buf: &mut Vec<u8>, item: &HashItem<'_>) {
    if !item.is_none() {
        match item {
            HashItem::None => unreachable!(),
            HashItem::Bool(b) => {
                // Python booleans are subclasses of int and serialize as ints.
                dump_int(buf, if *b { 1 } else { 0 });
            }
            HashItem::Int(v) => dump_int(buf, *v),
            HashItem::U64Hash(h) => buf.extend_from_slice(&h.to_le_bytes()),
            HashItem::Str(s) => buf.extend_from_slice(s.as_bytes()),
            HashItem::TypeName(s) => buf.extend_from_slice(s.as_bytes()),
            HashItem::Tuple(items) => {
                for inner in items {
                    dump_item(buf, inner);
                }
            }
            HashItem::Raw(bytes) => buf.extend_from_slice(bytes),
        }
    }
    buf.push(0xF0);
}

/// Compute the stable hash of a tuple-like sequence of items.
///
/// Returns the first 32 bits of MD5(payload) as in the Python implementation.
pub fn stable_hash(items: &[HashItem<'_>]) -> u32 {
    let mut buf = Vec::new();
    for item in items {
        dump_item(&mut buf, item);
    }
    let digest = Md5::digest(&buf);
    u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tuple() {
        // Python: stable_hash(()) -> first 32 bits of md5(b"") little-endian.
        // md5("") = d41d8cd98f00b204e9800998ecf8427e
        // first 4 bytes LE -> 0xd98c1dd4
        assert_eq!(stable_hash(&[]), 0xd98c1dd4);
    }

    #[test]
    fn small_int() {
        // Python: stable_hash((5,))
        //   _dump_int(5)  -> b"\x05\x00"            (LE u16)
        //   then separator 0xf0
        // md5(b"\x05\x00\xf0") first 4 bytes LE.
        let bytes = [0x05u8, 0x00, 0xF0];
        let d = Md5::digest(bytes);
        let want = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        assert_eq!(stable_hash(&[HashItem::Int(5)]), want);
    }

    #[test]
    fn none_only_writes_separator() {
        // dump([None]) -> b"\xf0" only.
        let d = Md5::digest([0xF0u8]);
        let want = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
        assert_eq!(stable_hash(&[HashItem::None]), want);
    }
}
