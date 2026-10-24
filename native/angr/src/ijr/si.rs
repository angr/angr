//! Guards as unsigned ranges, and a strided-interval evaluation of jump-table addresses under them.

use rustc_hash::FxHashMap;

use super::symex::{Arena, BinOp, CmpKind, ConvKind, Id, Node, mask};
use crate::cfg_scan::Snapshot;

pub const MAX_ENTRIES: u128 = 4096;

/// A strided interval `{lo, lo + st, ..., hi}`; `st == 0` iff `lo == hi`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Si {
    pub lo: u128,
    pub hi: u128,
    pub st: u128,
}

impl Si {
    pub fn konst(v: u128) -> Self {
        Si { lo: v, hi: v, st: 0 }
    }

    pub fn count(&self) -> u128 {
        if self.st == 0 {
            1
        } else {
            (self.hi - self.lo) / self.st + 1
        }
    }
}

pub fn gcd(a: u128, b: u128) -> u128 {
    let (mut a, mut b) = (a, b);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

fn sext(v: u64, w: u32) -> i128 {
    let v = v & mask(w);
    if w > 0 && (v >> (w - 1)) & 1 == 1 {
        v as i128 - (1i128 << w)
    } else {
        v as i128
    }
}

/// The unsigned range constraints `(expr, lo, hi)` implied by `g == truth`.
pub fn norm_guard(ar: &Arena, g: Id, truth: bool) -> Vec<(Id, u128, u128)> {
    let (mut g, mut truth) = (g, truth);
    loop {
        match ar.get(g) {
            Node::Not1 { a } => {
                g = a;
                truth = !truth;
            }
            Node::Conv {
                k: ConvKind::Trunc,
                wt: 1,
                a,
                ..
            }
            | Node::Conv {
                k: ConvKind::Zext,
                wf: 1,
                a,
                ..
            } => g = a,
            Node::Cmp {
                k: k @ (CmpKind::Eq | CmpKind::Ne),
                a,
                b,
                ..
            } if ar.const_val(b) == Some(0) => match ar.get(a) {
                // Zext(cond) == 0
                Node::Conv {
                    k: ConvKind::Zext,
                    wf: 1,
                    a: inner,
                    ..
                } => {
                    g = inner;
                    truth = if k == CmpKind::Ne { truth } else { !truth };
                }
                _ => break,
            },
            _ => break,
        }
    }
    let Node::Cmp { k, w, a, b } = ar.get(g) else {
        return Vec::new();
    };
    let w = w as u32;
    let m = mask(w) as u128;
    let (ca, cb) = (ar.const_val(a), ar.const_val(b));
    match k {
        CmpKind::Eq | CmpKind::Ne => {
            if (k == CmpKind::Eq) != truth {
                return Vec::new();
            }
            // Shr(x, k) == 0  <=>  x < 2**k (VEX folds `cmp x, 2**k-1; ja` into this)
            if cb == Some(0)
                && let Node::Bin {
                    op: BinOp::Shr,
                    a: x,
                    b: sh,
                    ..
                } = ar.get(a)
                && let Some(s) = ar.const_val(sh)
                && s < 64
            {
                return vec![(x, 0, (1u128 << s) - 1)];
            }
            if let Some(c) = cb {
                return vec![(a, c as u128, c as u128)];
            }
            if let Some(c) = ca {
                return vec![(b, c as u128, c as u128)];
            }
            Vec::new()
        }
        CmpKind::Lts | CmpKind::Les => {
            // signed: only usable when the range does not cross zero
            let lt = k == CmpKind::Lts;
            let smax = (1u128 << (w - 1)) - 1;
            match (ca, cb) {
                (None, Some(c)) => {
                    if truth {
                        return Vec::new();
                    }
                    let c = sext(c, w);
                    let lo = if lt { c } else { c + 1 };
                    if lo >= 0 {
                        vec![(a, lo as u128, smax)]
                    } else {
                        Vec::new()
                    }
                }
                (Some(c), None) => {
                    if !truth {
                        return Vec::new();
                    }
                    let c = sext(c, w);
                    let lo = if lt { c + 1 } else { c };
                    if lo >= 0 {
                        vec![(b, lo as u128, smax)]
                    } else {
                        Vec::new()
                    }
                }
                _ => Vec::new(),
            }
        }
        CmpKind::Ltu | CmpKind::Leu => {
            let lt = k == CmpKind::Ltu;
            match (ca, cb) {
                (None, Some(c)) => {
                    let c = c as i128;
                    if truth {
                        let hi = if lt { c - 1 } else { c };
                        if hi >= 0 { vec![(a, 0, hi as u128)] } else { Vec::new() }
                    } else {
                        let lo = if lt { c } else { c + 1 };
                        if lo as u128 <= m {
                            vec![(a, lo as u128, m)]
                        } else {
                            Vec::new()
                        }
                    }
                }
                (Some(c), None) => {
                    let c = c as i128;
                    if truth {
                        let lo = if lt { c + 1 } else { c };
                        if lo as u128 <= m {
                            vec![(b, lo as u128, m)]
                        } else {
                            Vec::new()
                        }
                    } else {
                        let hi = if lt { c } else { c - 1 };
                        if hi >= 0 { vec![(b, 0, hi as u128)] } else { Vec::new() }
                    }
                }
                _ => Vec::new(),
            }
        }
    }
}

pub type Ranges = FxHashMap<Id, (u128, u128)>;

/// Propagate range constraints through invertible operations: add a constant, zero/sign extension of
/// non-negative ranges, and on AMD64 a 32-bit truncation of a 64-bit register (the compiler indexes with the full
/// register only when its upper half is zero).
pub fn push_down(ar: &Arena, cons: &[(Id, u128, u128)], amd64: bool) -> Ranges {
    fn add(ar: &Arena, out: &mut Ranges, e: Id, lo: u128, hi: u128, amd64: bool) {
        if ar.const_val(e).is_some() {
            return;
        }
        let (lo, hi) = match out.get(&e) {
            Some(&(clo, chi)) => (lo.max(clo), hi.min(chi)),
            None => (lo, hi),
        };
        out.insert(e, (lo, hi));
        if lo > hi {
            return;
        }
        let w = ar.width(e);
        let m = mask(w) as u128;
        match ar.get(e) {
            Node::Bin {
                op: BinOp::Add, a, b, ..
            } => {
                if let Some(c) = ar.const_val(b) {
                    let c = c as u128;
                    let nlo = lo.wrapping_sub(c) & m;
                    let nhi = hi.wrapping_sub(c) & m;
                    if nlo <= nhi && hi - lo == nhi - nlo {
                        add(ar, out, a, nlo, nhi, amd64);
                    }
                }
            }
            Node::Conv {
                k: ConvKind::Zext,
                wf,
                a,
                ..
            } => {
                let fm = mask(wf as u32) as u128;
                if lo <= fm {
                    add(ar, out, a, lo, hi.min(fm), amd64);
                }
            }
            Node::Conv {
                k: ConvKind::Sext,
                wf,
                a,
                ..
            } => {
                if hi < (1u128 << (wf - 1)) {
                    add(ar, out, a, lo, hi, amd64);
                }
            }
            Node::Conv {
                k: ConvKind::Trunc,
                wf: 64,
                wt: 32,
                a,
            } if amd64 && matches!(ar.get(a), Node::R { .. }) => add(ar, out, a, lo, hi, amd64),
            _ => {}
        }
    }
    let mut out = Ranges::default();
    for &(e, lo, hi) in cons {
        add(ar, &mut out, e, lo, hi, amd64);
    }
    out
}

/// The guards of a path as ranges.
pub fn path_ranges(ar: &Arena, guards: &[(Id, bool)], amd64: bool) -> Ranges {
    let mut cons = Vec::new();
    for &(g, t) in guards {
        cons.extend(norm_guard(ar, g, t));
    }
    push_down(ar, &cons, amd64)
}

/// Whether `[lo, lo + n)` lies in read-only memory (an index table whose values cannot change).
fn read_only(snap: &Snapshot, lo: u64, n: u64) -> bool {
    let check = |a: u64| match snap.find_section_containing(a) {
        Some((oi, si)) => !snap.objects[oi].sections[si].is_writable,
        None => match snap.find_segment_containing(a) {
            Some((oi, si)) => !snap.objects[oi].segments[si].is_writable,
            None => false,
        },
    };
    n > 0 && check(lo) && check(lo + n - 1)
}

pub struct SiEval<'a> {
    pub ar: &'a Arena,
    pub ranges: &'a Ranges,
    pub snap: &'a Snapshot,
    memo: FxHashMap<Id, Option<Si>>,
}

impl<'a> SiEval<'a> {
    pub fn new(ar: &'a Arena, ranges: &'a Ranges, snap: &'a Snapshot) -> Self {
        SiEval {
            ar,
            ranges,
            snap,
            memo: FxHashMap::default(),
        }
    }

    /// None is TOP.
    pub fn eval(&mut self, e: Id, depth: u32) -> Option<Si> {
        if let Some(r) = self.memo.get(&e) {
            return *r;
        }
        let mut r = self.eval_inner(e, depth);
        if let Some(&(rlo, rhi)) = self.ranges.get(&e) {
            r = if rlo > rhi {
                None
            } else {
                match r {
                    None => Some(Si {
                        lo: rlo,
                        hi: rhi,
                        st: if rlo != rhi { 1 } else { 0 },
                    }),
                    Some(s) => {
                        let (mut lo, mut hi) = (s.lo.max(rlo), s.hi.min(rhi));
                        if s.st != 0 && lo <= hi {
                            lo = s.lo + (lo - s.lo).div_ceil(s.st) * s.st;
                            hi = s.lo + ((hi - s.lo) / s.st) * s.st;
                        }
                        if lo > hi {
                            None
                        } else {
                            Some(Si {
                                lo,
                                hi,
                                st: if lo != hi { s.st } else { 0 },
                            })
                        }
                    }
                }
            };
        }
        self.memo.insert(e, r);
        r
    }

    fn eval_inner(&mut self, e: Id, depth: u32) -> Option<Si> {
        let ar = self.ar;
        let w = ar.width(e);
        let m = mask(w) as u128;
        match ar.get(e) {
            Node::C { v, .. } => Some(Si::konst(v as u128)),
            Node::R { .. } | Node::U { .. } | Node::Cmp { .. } | Node::Not1 { .. } => None,
            Node::Ld { w, addr, be, .. } => {
                // a bounded index-table load: read all values (two-level tables)
                let a = self.eval(addr, depth + 1)?;
                if depth > 6 {
                    return None;
                }
                let size = (w / 8) as u128;
                let st = if a.st != 0 { a.st } else { size };
                let n = a.count();
                if n > MAX_ENTRIES || size == 0 {
                    return None;
                }
                let lo64 = u64::try_from(a.lo).ok()?;
                if !read_only(self.snap, lo64, ((n - 1) * st + size) as u64) {
                    return None;
                }
                let mut vals = Vec::with_capacity(n as usize);
                for i in 0..n {
                    let at = u64::try_from(a.lo + i * st).ok()?;
                    vals.push(self.snap.load_word_endian(at, size as usize, be)? as u128);
                }
                let lo = *vals.iter().min()?;
                let hi = *vals.iter().max()?;
                let g = vals.iter().fold(0, |g, &v| gcd(g, v - lo));
                Some(Si { lo, hi, st: g })
            }
            // the source width is not a bound: a guard or a mask must bound it
            Node::Conv {
                k: ConvKind::Zext, a, ..
            } => self.eval(a, depth + 1),
            Node::Conv {
                k: ConvKind::Sext,
                wf,
                a,
                ..
            } => {
                let s = self.eval(a, depth + 1)?;
                if s.hi >= (1u128 << (wf - 1)) { None } else { Some(s) }
            }
            Node::Conv {
                k: ConvKind::Trunc, a, ..
            } => {
                let s = self.eval(a, depth + 1)?;
                if s.hi > m { None } else { Some(s) }
            }
            Node::Bin { op, a, b, .. } => {
                let sa = self.eval(a, depth + 1);
                let sb = self.eval(b, depth + 1);
                if op == BinOp::And {
                    // x & m <= m and <= x
                    let hi = match (sa, sb) {
                        (None, None) => return None,
                        (Some(x), None) | (None, Some(x)) => x.hi,
                        (Some(x), Some(y)) => x.hi.min(y.hi),
                    };
                    if let (Some(x), Some(y)) = (sa, sb)
                        && x.st == 0
                        && y.st == 0
                    {
                        return Some(Si::konst(x.lo & y.lo));
                    }
                    let mut st = 1;
                    if let (Some(x), Some(y)) = (sa, sb)
                        && y.st == 0
                        && x.st != 0
                        && x.st.is_power_of_two()
                        && y.lo % x.st == 0
                        && x.lo % x.st == 0
                    {
                        st = x.st;
                    }
                    return Some(if hi != 0 { Si { lo: 0, hi, st } } else { Si::konst(0) });
                }
                let (sa, sb) = (sa?, sb?);
                match op {
                    BinOp::Add => {
                        if sa.st == 0 || sb.st == 0 {
                            let (x, c) = if sb.st == 0 { (sa, sb.lo) } else { (sb, sa.lo) };
                            let lo = (x.lo + c) & m;
                            let hi = (x.hi + c) & m;
                            if hi < lo || hi - lo != x.hi - x.lo {
                                return None;
                            }
                            Some(Si { lo, hi, st: x.st })
                        } else {
                            let (lo, hi) = (sa.lo + sb.lo, sa.hi + sb.hi);
                            if hi > m {
                                return None;
                            }
                            Some(Si {
                                lo,
                                hi,
                                st: gcd(sa.st, sb.st),
                            })
                        }
                    }
                    BinOp::Sub => {
                        if sb.st != 0 || sa.lo < sb.lo {
                            return None;
                        }
                        Some(Si {
                            lo: sa.lo - sb.lo,
                            hi: sa.hi - sb.lo,
                            st: sa.st,
                        })
                    }
                    BinOp::Mul => {
                        let (x, c) = if sb.st == 0 {
                            (sa, sb.lo)
                        } else if sa.st == 0 {
                            (sb, sa.lo)
                        } else {
                            return None;
                        };
                        let hi = x.hi.checked_mul(c)?;
                        if hi > m {
                            return None;
                        }
                        Some(Si {
                            lo: x.lo * c,
                            hi,
                            st: x.st * c,
                        })
                    }
                    BinOp::Shl => {
                        if sb.st != 0 || sb.lo >= 64 {
                            return None;
                        }
                        let k = sb.lo as u32;
                        let hi = sa.hi << k;
                        if hi > m {
                            return None;
                        }
                        Some(Si {
                            lo: sa.lo << k,
                            hi,
                            st: sa.st << k,
                        })
                    }
                    BinOp::Shr => {
                        if sb.st != 0 || sb.lo >= 128 {
                            return None;
                        }
                        let k = sb.lo as u32;
                        let (lo, hi) = (sa.lo >> k, sa.hi >> k);
                        Some(Si {
                            lo,
                            hi,
                            st: if lo != hi { 1 } else { 0 },
                        })
                    }
                    _ => None,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ijr::symex::Arena;

    fn eval(ar: &Arena, ranges: &Ranges, e: Id) -> Option<Si> {
        let snap = crate::cfg_scan::Snapshot::empty_for_tests();
        SiEval::new(ar, ranges, &snap).eval(e, 0)
    }

    #[test]
    fn unsigned_guards() {
        let mut ar = Arena::default();
        let x = ar.reg(16, 64);
        let c = ar.konst(0x12, 64);
        // ja (x >u 0x12) not taken: x <=u 0x12
        let g = ar.cmp(CmpKind::Leu, 64, x, c);
        assert_eq!(norm_guard(&ar, g, true), vec![(x, 0, 0x12)]);
        let ng = ar.not1(g);
        assert_eq!(norm_guard(&ar, ng, false), vec![(x, 0, 0x12)]);
        // x <u 0 is never true: no constraint
        let z = ar.konst(0, 64);
        let lt0 = ar.cmp(CmpKind::Ltu, 64, x, z);
        assert!(norm_guard(&ar, lt0, true).is_empty());
    }

    #[test]
    fn shr_fold_and_signed_guards() {
        let mut ar = Arena::default();
        let x = ar.reg(16, 64);
        let three = ar.konst(3, 8);
        let sh = ar.bin(BinOp::Shr, 64, x, three);
        let z = ar.konst(0, 64);
        let g = ar.cmp(CmpKind::Eq, 64, sh, z);
        assert_eq!(norm_guard(&ar, g, true), vec![(x, 0, 7)]);
        // jle 1 (signed) not taken: x >s 1; a signed bound that crosses zero gives nothing
        let one = ar.konst(1, 32);
        let w = ar.reg(16, 32);
        let le = ar.cmp(CmpKind::Les, 32, w, one);
        assert_eq!(norm_guard(&ar, le, false), vec![(w, 2, 0x7fff_ffff)]);
        assert!(norm_guard(&ar, le, true).is_empty());
    }

    #[test]
    fn push_down_through_add_and_trunc() {
        let mut ar = Arena::default();
        let r = ar.reg(16, 64);
        let t = ar.conv(ConvKind::Trunc, 64, 32, r);
        let m = ar.konst((-0x30i64) as u64, 32);
        let idx = ar.bin(BinOp::Add, 32, t, m);
        let ranges = push_down(&ar, &[(idx, 0, 15)], true);
        assert_eq!(ranges.get(&t), Some(&(0x30, 0x3f)));
        // AMD64: a bound on the low half bounds the register
        assert_eq!(ranges.get(&r), Some(&(0x30, 0x3f)));
        assert!(!push_down(&ar, &[(idx, 0, 15)], false).contains_key(&r));
    }

    #[test]
    fn strided_intervals() {
        let mut ar = Arena::default();
        let r = ar.reg(16, 64);
        let three = ar.konst(3, 64);
        let sc = ar.bin(BinOp::Shl, 64, r, three);
        let base = ar.konst(0xc171e8, 64);
        let a = ar.bin(BinOp::Add, 64, sc, base);
        let mut ranges = Ranges::default();
        assert_eq!(eval(&ar, &ranges, a), None);
        ranges.insert(r, (2, 22));
        assert_eq!(
            eval(&ar, &ranges, a),
            Some(Si {
                lo: 0xc171f8,
                hi: 0xc171e8 + 22 * 8,
                st: 8
            })
        );
        // a width is never a bound
        let b = ar.reg(24, 8);
        let zb = ar.conv(ConvKind::Zext, 8, 64, b);
        assert_eq!(eval(&ar, &Ranges::default(), zb), None);
        // a mask is
        let m = ar.konst(0xf, 64);
        let masked = ar.bin(BinOp::And, 64, zb, m);
        assert_eq!(eval(&ar, &Ranges::default(), masked), Some(Si { lo: 0, hi: 15, st: 1 }));
    }
}
