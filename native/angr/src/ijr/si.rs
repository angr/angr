//! Guards as unsigned ranges, and a strided-interval evaluation of jump-table addresses under them.

use rustc_hash::FxHashMap;

use super::symex::{Arena, BinOp, CmpKind, ConvKind, Id, Node, UnOp, mask};
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
        Si {
            lo: v,
            hi: v,
            st: 0,
        }
    }

    pub fn count(&self) -> u128 {
        (self.hi - self.lo)
            .checked_div(self.st)
            .map_or(1, |q| q + 1)
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

/// A signed range as unsigned intervals: one, or two when it crosses zero (`[0, hi]` and `[lo, max]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedRange {
    One(u128, u128),
    Two((u128, u128), (u128, u128)),
}

/// Negations and 1-bit conversions stripped from a guard: `(cmp, truth)`.
fn strip_guard(ar: &Arena, g: Id, truth: bool) -> (Id, bool) {
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
                _ => return (g, truth),
            },
            _ => return (g, truth),
        }
    }
}

/// The signed range a signed comparison against a constant implies, as unsigned intervals.
pub fn signed_range(ar: &Arena, g: Id, truth: bool) -> Option<(Id, SignedRange)> {
    let (g, truth) = strip_guard(ar, g, truth);
    let Node::Cmp {
        k: k @ (CmpKind::Lts | CmpKind::Les),
        w,
        a,
        b,
    } = ar.get(g)
    else {
        return None;
    };
    let w = w as u32;
    let lt = k == CmpKind::Lts;
    let (smin, smax) = (-(1i128 << (w - 1)), (1i128 << (w - 1)) - 1);
    let (x, lo, hi) = match (ar.const_val(a), ar.const_val(b)) {
        // x < c, x <= c
        (None, Some(c)) => {
            let c = sext(c, w);
            match (lt, truth) {
                (true, true) => (a, smin, c - 1),
                (true, false) => (a, c, smax),
                (false, true) => (a, smin, c),
                (false, false) => (a, c + 1, smax),
            }
        }
        // c < x, c <= x
        (Some(c), None) => {
            let c = sext(c, w);
            match (lt, truth) {
                (true, true) => (b, c + 1, smax),
                (true, false) => (b, smin, c),
                (false, true) => (b, c, smax),
                (false, false) => (b, smin, c - 1),
            }
        }
        _ => return None,
    };
    if lo > hi {
        return None;
    }
    let m = 1i128 << w;
    Some((
        x,
        if lo >= 0 {
            SignedRange::One(lo as u128, hi as u128)
        } else if hi < 0 {
            SignedRange::One((lo + m) as u128, (hi + m) as u128)
        } else {
            SignedRange::Two((0, hi as u128), ((lo + m) as u128, (m - 1) as u128))
        },
    ))
}

/// The unsigned range constraints `(expr, lo, hi)` implied by `g == truth`.
pub fn norm_guard(ar: &Arena, g: Id, truth: bool) -> Vec<(Id, u128, u128)> {
    let (g, truth) = strip_guard(ar, g, truth);
    let Node::Cmp { k, w, a, b } = ar.get(g) else {
        return Vec::new();
    };
    let w = w as u32;
    let m = mask(w) as u128;
    let (ca, cb) = (ar.const_val(a), ar.const_val(b));
    match k {
        CmpKind::Eq | CmpKind::Ne => {
            if (k == CmpKind::Eq) != truth {
                // x != 0 and x != max are ranges
                let (x, c) = match (ca, cb) {
                    (None, Some(c)) => (a, c as u128),
                    (Some(c), None) => (b, c as u128),
                    _ => return Vec::new(),
                };
                return if c == 0 {
                    vec![(x, 1, m)]
                } else if c == m {
                    vec![(x, 0, m - 1)]
                } else {
                    Vec::new()
                };
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
        CmpKind::Lts | CmpKind::Les => match signed_range(ar, g, truth) {
            Some((x, SignedRange::One(lo, hi))) => vec![(x, lo, hi)],
            _ => Vec::new(),
        },
        CmpKind::Ltu | CmpKind::Leu => {
            let lt = k == CmpKind::Ltu;
            match (ca, cb) {
                (None, Some(c)) => {
                    let c = c as i128;
                    if truth {
                        let hi = if lt { c - 1 } else { c };
                        if hi >= 0 {
                            vec![(a, 0, hi as u128)]
                        } else {
                            Vec::new()
                        }
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
                        if hi >= 0 {
                            vec![(b, 0, hi as u128)]
                        } else {
                            Vec::new()
                        }
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
                op: BinOp::Add,
                a,
                b,
                ..
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
            Node::Bin {
                op: BinOp::Shr,
                a,
                b,
                ..
            } => {
                // x >> k in [lo, hi]  <=>  x in [lo << k, ((hi + 1) << k) - 1]
                if let Some(k) = ar.const_val(b)
                    && k < 64
                {
                    let am = mask(ar.width(a)) as u128;
                    let nlo = lo << k;
                    let nhi = (((hi + 1) << k) - 1).min(am);
                    if nlo <= nhi {
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
            // trunc(x + c) in [lo, hi]  =>  trunc(x) in [lo - c, hi - c] when that does not wrap
            Node::Conv {
                k: ConvKind::Trunc,
                wf,
                wt,
                a,
            } => {
                if let Node::Bin {
                    op: BinOp::Add,
                    a: x,
                    b,
                    ..
                } = ar.get(a)
                    && let Some(c) = ar.const_val(b)
                    && let Some(tx) = match ar.get(x) {
                        // trunc(zext(y)) is y
                        Node::Conv {
                            k: ConvKind::Zext,
                            wf: yf,
                            a: y,
                            ..
                        } if yf == wt => Some(y),
                        _ => ar.lookup(&Node::Conv {
                            k: ConvKind::Trunc,
                            wf,
                            wt,
                            a: x,
                        }),
                    }
                {
                    let c = c as u128 & m;
                    let nlo = lo.wrapping_sub(c) & m;
                    let nhi = hi.wrapping_sub(c) & m;
                    if nlo <= nhi && hi - lo == nhi - nlo {
                        add(ar, out, tx, nlo, nhi, amd64);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Ranges::default();
    for &(e, lo, hi) in cons {
        add(ar, &mut out, e, lo, hi, amd64);
    }
    out
}

/// An unsigned comparison between two non-constant values: `(x, y, strict, width)` for `x < y` or `x <= y`.
fn relation(ar: &Arena, g: Id, truth: bool) -> Option<(Id, Id, bool, u32)> {
    let (g, truth) = strip_guard(ar, g, truth);
    let Node::Cmp {
        k: k @ (CmpKind::Ltu | CmpKind::Leu),
        w,
        a,
        b,
    } = ar.get(g)
    else {
        return None;
    };
    if ar.const_val(a).is_some() || ar.const_val(b).is_some() {
        return None;
    }
    let lt = k == CmpKind::Ltu;
    Some(match (lt, truth) {
        (true, true) => (a, b, true, w as u32),
        (true, false) => (b, a, false, w as u32),
        (false, true) => (a, b, false, w as u32),
        (false, false) => (b, a, true, w as u32),
    })
}

/// `e` without zero extensions.
fn strip_zext(ar: &Arena, mut e: Id) -> Id {
    while let Node::Conv {
        k: ConvKind::Zext,
        a,
        ..
    } = ar.get(e)
    {
        e = a;
    }
    e
}

/// Ranges of the arena's `(u + c) - v` nodes with `{u, v} = {x, y}` (zero extensions aside) when `x < y` (`x <= y`
/// when not strict): `c + (x - y)` or `c + (y - x)`, kept only when it does not wrap.
fn differences(
    ar: &Arena,
    ranges: &Ranges,
    snap: &Snapshot,
    x: Id,
    y: Id,
    strict: bool,
) -> Vec<(Id, u128, u128)> {
    let mut out = Vec::new();
    let mut ev = SiEval::new(ar, ranges, snap);
    let (Some(sx), Some(sy)) = (ev.eval(x, 0), ev.eval(y, 0)) else {
        return out;
    };
    let s = strict as i128;
    for id in 0..ar.len() as Id {
        let Node::Bin {
            op: BinOp::Sub,
            w,
            a,
            b,
            ..
        } = ar.get(id)
        else {
            continue;
        };
        let (u, c) = match ar.get(a) {
            Node::Bin {
                op: BinOp::Add,
                a: u,
                b: k,
                ..
            } if ar.const_val(k).is_some() => (u, ar.const_val(k).unwrap_or(0) as i128),
            _ => (a, 0),
        };
        let (u, v) = (strip_zext(ar, u), strip_zext(ar, b));
        let (lo, hi) = if (u, v) == (x, y) {
            // c + (x - y), x - y in [x.lo - y.hi, -s]
            (c + sx.lo as i128 - sy.hi as i128, c - s)
        } else if (u, v) == (y, x) {
            // c + (y - x), y - x in [s, y.hi - x.lo]
            (c + s, c + sy.hi as i128 - sx.lo as i128)
        } else {
            continue;
        };
        if lo >= 0 && lo <= hi && hi <= mask(w as u32) as i128 {
            out.push((id, lo as u128, hi as u128));
        }
    }
    out
}

/// The guards of a path as ranges.
pub fn path_ranges(ar: &Arena, guards: &[(Id, bool)], amd64: bool, snap: &Snapshot) -> Ranges {
    let mut cons = Vec::new();
    let mut pieces = Vec::new();
    for &(g, t) in guards {
        let unsigned = norm_guard(ar, g, t);
        // and unsigned ranges whose push-down through `x + c` stops where it wraps
        pieces.extend(unsigned.iter().map(|&(x, lo, hi)| (x, (lo, hi), (1, 0))));
        cons.extend(unsigned);
        // signed ranges are rechecked against the forward value of their operand: the ones crossing zero are two
        // intervals, and the push-down through `x - c` stops where the unsigned range wraps
        match signed_range(ar, g, t) {
            Some((x, SignedRange::Two(p0, p1))) => pieces.push((x, p0, p1)),
            Some((x, SignedRange::One(lo, hi))) => pieces.push((x, (lo, hi), (1, 0))),
            None => {}
        }
    }
    let rels: Vec<(Id, Id, bool, u32)> = guards
        .iter()
        .filter_map(|&(g, t)| relation(ar, g, t))
        .collect();
    let mut ranges = push_down(ar, &cons, amd64);
    // the other guards may rule one of the intervals out, or narrow the operand so that the range pushes down
    for _ in 0..3 {
        let mut changed = false;
        // differences of related values: (x + c) - y with x < y is c + (x - y), at most c - 1
        for &(x, y, strict, _) in &rels {
            for (id, lo, hi) in differences(ar, &ranges, snap, x, y, strict) {
                if ranges
                    .get(&id)
                    .is_none_or(|&(clo, chi)| lo > clo || hi < chi)
                {
                    cons.push((id, lo, hi));
                    changed = true;
                }
            }
        }
        // x < y (or x <= y): x is at most y's largest value, y at least x's smallest
        for &(x, y, strict, w) in &rels {
            let s = strict as u128;
            let mut ev = SiEval::new(ar, &ranges, snap);
            let (sx, sy) = (ev.eval(x, 0), ev.eval(y, 0));
            if let Some(sy) = sy
                && sy.hi >= s
                && ranges.get(&x).is_none_or(|&(_, hi)| sy.hi - s < hi)
            {
                cons.push((x, 0, sy.hi - s));
                changed = true;
            }
            if let Some(sx) = sx
                && sx.lo + s > 0
                && ranges.get(&y).is_none_or(|&(lo, _)| sx.lo + s > lo)
            {
                cons.push((y, sx.lo + s, mask(w) as u128));
                changed = true;
            }
        }
        for &(x, p0, p1) in &pieces {
            // the operand's value from its own inputs, and the other guards on it
            let mut without = ranges.clone();
            let own = without.remove(&x);
            let fwd = SiEval::new(ar, &without, snap)
                .eval(x, 0)
                .map(|si| (si.lo, si.hi));
            let (klo, khi) = match (fwd, own) {
                (Some((a, b)), Some((c, d))) => (a.max(c), b.min(d)),
                (Some(k), None) | (None, Some(k)) => k,
                (None, None) => continue,
            };
            let meet = |(lo, hi): (u128, u128)| (klo.max(lo), khi.min(hi));
            let (m0, m1) = (meet(p0), meet(p1));
            let one = match (m0.0 <= m0.1, m1.0 <= m1.1) {
                (true, false) => m0,
                (false, true) => m1,
                _ => continue,
            };
            if ranges
                .get(&x)
                .is_none_or(|&(lo, hi)| one.0 > lo || one.1 < hi)
            {
                cons.push((x, one.0, one.1));
                changed = true;
            }
        }
        if !changed {
            break;
        }
        ranges = push_down(ar, &cons, amd64);
    }
    ranges
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

    /// The bits a value can have set: the fewest its range or a zero extension allows.
    fn value_bits(&mut self, e: Id, depth: u32) -> Option<u32> {
        let from_range = self.eval(e, depth).map(|si| 128 - si.hi.leading_zeros());
        let structural = match self.ar.get(e) {
            Node::Conv {
                k: ConvKind::Zext,
                wf,
                a,
                ..
            } => Some(
                self.value_bits(a, depth + 1)
                    .map_or(wf as u32, |b| b.min(wf as u32)),
            ),
            _ => None,
        };
        match (from_range, structural) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }

    fn eval_inner(&mut self, e: Id, depth: u32) -> Option<Si> {
        let ar = self.ar;
        let w = ar.width(e);
        let m = mask(w) as u128;
        match ar.get(e) {
            Node::C { v, .. } => Some(Si::konst(v as u128)),
            Node::R { .. }
            | Node::U { .. }
            | Node::Cmp { .. }
            | Node::Not1 { .. }
            | Node::Ite { .. } => None,
            // a bit count of a nonzero value below 2^bits, bits < w (a count up to w bounds nothing useful)
            Node::Un { op, w, a } => {
                let w = w as u32;
                let bits = self.value_bits(a, depth + 1)?;
                if bits == 0 || bits >= w || self.eval(a, depth + 1).is_none_or(|s| s.lo == 0) {
                    return None;
                }
                let (lo, hi) = match op {
                    UnOp::Ctz => (0, bits - 1),
                    UnOp::Clz => (w - bits, w - 1),
                };
                Some(Si {
                    lo: lo as u128,
                    hi: hi as u128,
                    st: if lo != hi { 1 } else { 0 },
                })
            }
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
                k: ConvKind::Zext,
                a,
                ..
            } => self.eval(a, depth + 1),
            Node::Conv {
                k: ConvKind::Sext,
                wf,
                a,
                ..
            } => {
                let s = self.eval(a, depth + 1)?;
                if s.hi >= (1u128 << (wf - 1)) {
                    None
                } else {
                    Some(s)
                }
            }
            Node::Conv {
                k: ConvKind::Trunc,
                a,
                ..
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
                    return Some(if hi != 0 {
                        Si { lo: 0, hi, st }
                    } else {
                        Si::konst(0)
                    });
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
                        // no wrap: the smallest minuend is at least the largest subtrahend
                        if sa.lo < sb.hi {
                            return None;
                        }
                        let (lo, hi) = (sa.lo - sb.hi, sa.hi - sb.lo);
                        Some(Si {
                            lo,
                            hi,
                            st: if lo == hi {
                                0
                            } else {
                                gcd(sa.st, sb.st).max(1)
                            },
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
        // test eax, eax; jne: x != 0
        let ne0 = ar.cmp(CmpKind::Ne, 64, x, z);
        assert_eq!(norm_guard(&ar, ne0, true), vec![(x, 1, u64::MAX as u128)]);
        assert_eq!(norm_guard(&ar, ne0, false), vec![(x, 0, 0)]);
        // cmp x, 1; jbe not taken: VEX folds it to Shr(x, 1) != 0, so x >= 2
        let one = ar.konst(1, 8);
        let sh = ar.bin(BinOp::Shr, 64, x, one);
        let g = ar.cmp(CmpKind::Eq, 64, sh, z);
        let ranges = push_down(&ar, &norm_guard(&ar, g, false), false);
        assert_eq!(ranges.get(&x), Some(&(2, u64::MAX as u128)));
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
    fn signed_ranges_across_zero() {
        let mut ar = Arena::default();
        let snap = crate::cfg_scan::Snapshot::empty_for_tests();
        let x = ar.reg(16, 64);
        let c = ar.konst((-0x40i64) as u64, 64);
        let neg64 = (-0x40i64) as u64 as u128;
        // jl -0x40 not taken: x >=s -0x40, two unsigned intervals
        let lt = ar.cmp(CmpKind::Lts, 64, x, c);
        assert_eq!(
            signed_range(&ar, lt, false),
            Some((
                x,
                SignedRange::Two((0, i64::MAX as u128), (neg64, u64::MAX as u128))
            ))
        );
        assert!(!path_ranges(&ar, &[(lt, false)], true, &snap).contains_key(&x));
        // x <s 0 on the same path leaves the negative interval, so x + 0x40 is in [0, 0x3f]
        let z = ar.konst(0, 64);
        let neg = ar.cmp(CmpKind::Lts, 64, x, z);
        let ranges = path_ranges(&ar, &[(lt, false), (neg, true)], true, &snap);
        assert_eq!(ranges.get(&x), Some(&(neg64, u64::MAX as u128)));
        let k = ar.konst(0x40, 64);
        let idx = ar.bin(BinOp::Add, 64, x, k);
        assert_eq!(
            eval(&ar, &ranges, idx),
            Some(Si {
                lo: 0,
                hi: 0x3f,
                st: 1
            })
        );
        // a mask rules out the negative interval of x <s 0x10
        let r = ar.reg(24, 64);
        let m = ar.konst(0xffff, 64);
        let masked = ar.bin(BinOp::And, 64, r, m);
        let c16 = ar.konst(0x10, 64);
        let lt16 = ar.cmp(CmpKind::Lts, 64, masked, c16);
        let ranges = path_ranges(&ar, &[(lt16, true)], true, &snap);
        assert_eq!(ranges.get(&masked), Some(&(0, 0xf)));
    }

    #[test]
    fn bit_counts_and_relations() {
        let mut ar = Arena::default();
        let snap = crate::cfg_scan::Snapshot::empty_for_tests();
        // bsf of a nonzero pmovmskb mask: below 16
        let m = ar.opaque(16);
        let mask16 = ar.conv(ConvKind::Zext, 16, 64, m);
        let ctz = ar.un(UnOp::Ctz, 64, mask16);
        let z = ar.konst(0, 64);
        let nz = ar.cmp(CmpKind::Eq, 64, mask16, z);
        let ranges = path_ranges(&ar, &[(nz, false)], true, &snap);
        assert_eq!(
            eval(&ar, &ranges, ctz),
            Some(Si {
                lo: 0,
                hi: 15,
                st: 1
            })
        );
        // without the zero test the count may be 64
        assert_eq!(eval(&ar, &Ranges::default(), ctz), None);
        // cmp rdx, r8; jb not taken: r8 <= bsf, so r8 is below 16
        let r8 = ar.reg(80, 64);
        let jb = ar.cmp(CmpKind::Ltu, 64, ctz, r8);
        let ranges = path_ranges(&ar, &[(nz, false), (jb, false)], true, &snap);
        assert_eq!(ranges.get(&r8), Some(&(0, 15)));
        // x < y, both below 16: (x + 15) - y is in [0, 14]
        let (x, y) = (ar.reg(16, 64), ar.reg(24, 64));
        let f = ar.konst(0xf, 64);
        let (mx, my) = (ar.bin(BinOp::And, 64, x, f), ar.bin(BinOp::And, 64, y, f));
        let lt = ar.cmp(CmpKind::Ltu, 64, mx, my);
        let sum = ar.bin(BinOp::Add, 64, mx, f);
        let idx = ar.bin(BinOp::Sub, 64, sum, my);
        let ranges = path_ranges(&ar, &[(lt, true)], true, &snap);
        assert_eq!(
            eval(&ar, &ranges, idx),
            Some(Si {
                lo: 0,
                hi: 14,
                st: 1
            })
        );
        // unrelated: the interval difference
        assert_eq!(
            eval(&ar, &Ranges::default(), idx),
            Some(Si {
                lo: 0,
                hi: 30,
                st: 1
            })
        );
    }

    #[test]
    fn unsigned_ranges_meet_forward_values() {
        let mut ar = Arena::default();
        let snap = crate::cfg_scan::Snapshot::empty_for_tests();
        // x in [0x40, 0x80), and (x - 0x40) >=u 0x20: the second range wraps through x, but x - 0x40 is in
        // [0, 0x3f] and so in [0x20, 0x3f]
        let x = ar.reg(32, 64);
        let c80 = ar.konst(0x80, 64);
        let lt80 = ar.cmp(CmpKind::Ltu, 64, x, c80);
        let c40 = ar.konst(0x40, 64);
        let lt40 = ar.cmp(CmpKind::Ltu, 64, x, c40);
        let m40 = ar.konst((-0x40i64) as u64, 64);
        let d = ar.bin(BinOp::Add, 64, x, m40);
        let c20 = ar.konst(0x20, 64);
        let lt20 = ar.cmp(CmpKind::Ltu, 64, d, c20);
        let ranges = path_ranges(
            &ar,
            &[(lt80, true), (lt40, false), (lt20, false)],
            true,
            &snap,
        );
        assert_eq!(ranges.get(&x), Some(&(0x60, 0x7f)));
        let m60 = ar.konst((-0x60i64) as u64, 64);
        let idx = ar.bin(BinOp::Add, 64, x, m60);
        assert_eq!(
            eval(&ar, &ranges, idx),
            Some(Si {
                lo: 0,
                hi: 0x1f,
                st: 1
            })
        );
    }

    #[test]
    fn push_down_through_truncated_sums() {
        let mut ar = Arena::default();
        let r = ar.reg(40, 64);
        let t = ar.conv(ConvKind::Trunc, 64, 8, r);
        let m20 = ar.konst((-0x20i64) as u64, 64);
        let s = ar.bin(BinOp::Add, 64, r, m20);
        let ts = ar.conv(ConvKind::Trunc, 64, 8, s);
        // (c - 0x20) & 0xff <= 0x5a: the byte c is in [0x20, 0x7a]
        let ranges = push_down(&ar, &[(ts, 0, 0x5a)], true);
        assert_eq!(ranges.get(&t), Some(&(0x20, 0x7a)));
        // trunc(zext(b) - 0x20) bounds b itself
        let b = ar.opaque(8);
        let zb = ar.conv(ConvKind::Zext, 8, 64, b);
        let s2 = ar.bin(BinOp::Add, 64, zb, m20);
        let ts2 = ar.conv(ConvKind::Trunc, 64, 8, s2);
        let ranges = push_down(&ar, &[(ts2, 0, 0x5a)], true);
        assert_eq!(ranges.get(&b), Some(&(0x20, 0x7a)));
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
        assert_eq!(
            eval(&ar, &Ranges::default(), masked),
            Some(Si {
                lo: 0,
                hi: 15,
                st: 1
            })
        );
    }
}
