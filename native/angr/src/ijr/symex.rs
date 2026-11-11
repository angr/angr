//! Forward symbolic execution of short VEX block paths for the jump-table resolver.
//!
//! Expressions live in a hash-consed [`Arena`]. Leaves are registers at path start (`R`), loads keyed by (address,
//! memory epoch) (`Ld`) and opaque values (`U`). Values are integers of 1..=64 bits; anything wider or non-integer is
//! opaque. No claripy, no solver: guards are collected as expressions and evaluated by `si.rs`.

use std::sync::OnceLock;

use rustc_hash::FxHashMap;

use super::fcp::{FcpTable, Var};
use crate::ailment::vex_ffi::{self, IEND_BE};
use crate::cfg_scan::Snapshot;
use crate::vexir::{Expr, ExprId, IrConst, NO_EXPR, Stmt, VexIrsb, op_name};
use crate::vexlift::{IJK_BORING, jumpkind_name};

pub type Id = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConvKind {
    Zext,
    Sext,
    Trunc,
}

/// Bit counts (`Iop_CtzNat64` and the like): the width for a zero operand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnOp {
    Ctz,
    Clz,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CmpKind {
    Eq,
    Ne,
    Ltu,
    Leu,
    Lts,
    Les,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Node {
    C {
        v: u64,
        w: u8,
    },
    R {
        off: i32,
        w: u8,
    },
    U {
        n: u32,
        w: u8,
    },
    Ld {
        w: u8,
        addr: Id,
        epoch: u32,
        be: bool,
    },
    Bin {
        op: BinOp,
        w: u8,
        a: Id,
        b: Id,
    },
    Conv {
        k: ConvKind,
        wf: u8,
        wt: u8,
        a: Id,
    },
    /// `w` is the operand width; the result is 1 bit.
    Cmp {
        k: CmpKind,
        w: u8,
        a: Id,
        b: Id,
    },
    Not1 {
        a: Id,
    },
    Un {
        op: UnOp,
        w: u8,
        a: Id,
    },
    /// `c ? a : b`, `w` bits.
    Ite {
        c: Id,
        a: Id,
        b: Id,
        w: u8,
    },
}

pub fn mask(w: u32) -> u64 {
    if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
}

fn sext(v: u64, w: u32) -> i128 {
    let v = v & mask(w);
    if w > 0 && (v >> (w - 1)) & 1 == 1 {
        v as i128 - (1i128 << w)
    } else {
        v as i128
    }
}

pub fn eval_cmp(k: CmpKind, w: u32, x: u64, y: u64) -> bool {
    match k {
        CmpKind::Eq => x == y,
        CmpKind::Ne => x != y,
        CmpKind::Ltu => x < y,
        CmpKind::Leu => x <= y,
        CmpKind::Lts => sext(x, w) < sext(y, w),
        CmpKind::Les => sext(x, w) <= sext(y, w),
    }
}

/// The hash-consed expression store of one resolution (shared by all paths of a jump).
#[derive(Default)]
pub struct Arena {
    nodes: Vec<Node>,
    map: FxHashMap<Node, Id>,
    uniq: u32,
}

impl Arena {
    pub fn get(&self, id: Id) -> Node {
        self.nodes[id as usize]
    }

    fn intern(&mut self, n: Node) -> Id {
        if let Some(&id) = self.map.get(&n) {
            return id;
        }
        let id = self.nodes.len() as Id;
        self.nodes.push(n);
        self.map.insert(n, id);
        id
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The id of a node already in the arena.
    pub fn lookup(&self, n: &Node) -> Option<Id> {
        self.map.get(n).copied()
    }

    pub fn width(&self, id: Id) -> u32 {
        match self.get(id) {
            Node::C { w, .. }
            | Node::R { w, .. }
            | Node::U { w, .. }
            | Node::Ld { w, .. }
            | Node::Bin { w, .. } => w as u32,
            Node::Conv { wt, .. } => wt as u32,
            Node::Ite { w, .. } | Node::Un { w, .. } => w as u32,
            Node::Cmp { .. } | Node::Not1 { .. } => 1,
        }
    }

    pub fn konst(&mut self, v: u64, w: u32) -> Id {
        self.intern(Node::C {
            v: v & mask(w),
            w: w as u8,
        })
    }

    pub fn const_val(&self, id: Id) -> Option<u64> {
        match self.get(id) {
            Node::C { v, .. } => Some(v),
            _ => None,
        }
    }

    pub fn opaque(&mut self, w: u32) -> Id {
        self.uniq += 1;
        let n = self.uniq;
        self.intern(Node::U { n, w: w as u8 })
    }

    pub fn reg(&mut self, off: i32, w: u32) -> Id {
        self.intern(Node::R { off, w: w as u8 })
    }

    pub fn load(&mut self, w: u32, addr: Id, epoch: u32, be: bool) -> Id {
        self.intern(Node::Ld {
            w: w as u8,
            addr,
            epoch,
            be,
        })
    }

    pub fn cmp(&mut self, k: CmpKind, w: u32, a: Id, b: Id) -> Id {
        if let (Some(x), Some(y)) = (self.const_val(a), self.const_val(b)) {
            return self.konst(eval_cmp(k, w, x, y) as u64, 1);
        }
        self.intern(Node::Cmp {
            k,
            w: w as u8,
            a,
            b,
        })
    }

    pub fn not1(&mut self, a: Id) -> Id {
        match self.get(a) {
            Node::Not1 { a: inner } => inner,
            Node::C { v, .. } => self.konst(v ^ 1, 1),
            _ => self.intern(Node::Not1 { a }),
        }
    }

    pub fn ite(&mut self, c: Id, a: Id, b: Id, w: u32) -> Id {
        if let Some(v) = self.const_val(c) {
            return if v != 0 { a } else { b };
        }
        if a == b {
            return a;
        }
        self.intern(Node::Ite {
            c,
            a,
            b,
            w: w as u8,
        })
    }

    /// A 1-bit condition with its negations and 1-bit conversions stripped: `(base, value)` such that `e == v`
    /// means `base == value`.
    pub fn bool_base(&self, mut e: Id, mut v: bool) -> (Id, bool) {
        loop {
            match self.get(e) {
                Node::Not1 { a } => {
                    e = a;
                    v = !v;
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
                } => e = a,
                _ => return (e, v),
            }
        }
    }

    /// The value `decided` fixes for a condition, also through its complement (`a != b` for `a == b`).
    fn decided(&self, decided: &FxHashMap<Id, bool>, base: Id) -> Option<bool> {
        if let Some(&d) = decided.get(&base) {
            return Some(d);
        }
        let Node::Cmp {
            k: k @ (CmpKind::Eq | CmpKind::Ne),
            w,
            a,
            b,
        } = self.get(base)
        else {
            return None;
        };
        let k2 = if k == CmpKind::Eq {
            CmpKind::Ne
        } else {
            CmpKind::Eq
        };
        let other = self.map.get(&Node::Cmp { k: k2, w, a, b })?;
        decided.get(other).map(|&d| !d)
    }

    pub fn un(&mut self, op: UnOp, w: u32, a: Id) -> Id {
        if let Some(v) = self.const_val(a) {
            let v = v & mask(w);
            let r = match op {
                _ if v == 0 => w,
                UnOp::Ctz => v.trailing_zeros(),
                UnOp::Clz => v.leading_zeros() - (64 - w),
            };
            return self.konst(r as u64, w);
        }
        self.intern(Node::Un { op, w: w as u8, a })
    }

    /// Replace the ITEs whose conditions `decided` fixes (keyed by `bool_base`).
    pub fn decide_ites(
        &mut self,
        e: Id,
        decided: &FxHashMap<Id, bool>,
        memo: &mut FxHashMap<Id, Id>,
    ) -> Id {
        if let Some(&r) = memo.get(&e) {
            return r;
        }
        let r = match self.get(e) {
            Node::C { .. } | Node::R { .. } | Node::U { .. } => e,
            Node::Ite { c, a, b, .. } => {
                let (base, v) = self.bool_base(c, true);
                match self.decided(decided, base).map(|d| d == v) {
                    Some(true) => self.decide_ites(a, decided, memo),
                    Some(false) => self.decide_ites(b, decided, memo),
                    // undecided: kept, so guard ranges on the ITE itself (a `cmov` index) still apply
                    None => e,
                }
            }
            Node::Ld { w, addr, epoch, be } => {
                let na = self.decide_ites(addr, decided, memo);
                if na == addr {
                    e
                } else {
                    self.load(w as u32, na, epoch, be)
                }
            }
            Node::Bin { op, w, a, b } => {
                let (na, nb) = (
                    self.decide_ites(a, decided, memo),
                    self.decide_ites(b, decided, memo),
                );
                if (na, nb) == (a, b) {
                    e
                } else {
                    self.bin(op, w as u32, na, nb)
                }
            }
            Node::Conv { k, wf, wt, a } => {
                let na = self.decide_ites(a, decided, memo);
                if na == a {
                    e
                } else {
                    self.conv(k, wf as u32, wt as u32, na)
                }
            }
            Node::Cmp { k, w, a, b } => {
                let (na, nb) = (
                    self.decide_ites(a, decided, memo),
                    self.decide_ites(b, decided, memo),
                );
                if (na, nb) == (a, b) {
                    e
                } else {
                    self.cmp(k, w as u32, na, nb)
                }
            }
            Node::Not1 { a } => {
                let na = self.decide_ites(a, decided, memo);
                if na == a { e } else { self.not1(na) }
            }
            Node::Un { op, w, a } => {
                let na = self.decide_ites(a, decided, memo);
                if na == a {
                    e
                } else {
                    self.un(op, w as u32, na)
                }
            }
        };
        memo.insert(e, r);
        r
    }

    pub fn bin(&mut self, op: BinOp, w: u32, a: Id, b: Id) -> Id {
        let (mut op, mut a, mut b) = (op, a, b);
        let m = mask(w);
        if let (Some(x), Some(y)) = (self.const_val(a), self.const_val(b)) {
            let v = match op {
                BinOp::Add => x.wrapping_add(y),
                BinOp::Sub => x.wrapping_sub(y),
                BinOp::Mul => x.wrapping_mul(y),
                BinOp::And => x & y,
                BinOp::Or => x | y,
                BinOp::Xor => x ^ y,
                BinOp::Shl => {
                    if y >= w as u64 {
                        0
                    } else {
                        x << y
                    }
                }
                BinOp::Shr => {
                    if y >= w as u64 {
                        0
                    } else {
                        (x & m) >> y
                    }
                }
                BinOp::Sar => {
                    let s = sext(x, w);
                    (s >> y.min(127)) as u64
                }
            };
            return self.konst(v, w);
        }
        if op == BinOp::Sub
            && let Some(y) = self.const_val(b)
        {
            op = BinOp::Add;
            b = self.konst(y.wrapping_neg(), w);
        }
        if matches!(
            op,
            BinOp::Add | BinOp::Mul | BinOp::And | BinOp::Or | BinOp::Xor
        ) && self.const_val(a).is_some()
        {
            std::mem::swap(&mut a, &mut b);
        }
        if op == BinOp::Add
            && let Some(c) = self.const_val(b)
        {
            if c == 0 {
                return a;
            }
            if let Node::Bin {
                op: BinOp::Add,
                a: a2,
                b: b2,
                ..
            } = self.get(a)
                && let Some(c2) = self.const_val(b2)
            {
                let nc = self.konst(c2.wrapping_add(c), w);
                return self.bin(BinOp::Add, w, a2, nc);
            }
        }
        if op == BinOp::Xor && a == b {
            return self.konst(0, w);
        }
        // Zext(c) ^ 1 = Zext(!c) for a 1-bit c (ARM's `!cond` before a conditional exit)
        if op == BinOp::Xor
            && self.const_val(b) == Some(1)
            && let Node::Conv {
                k: ConvKind::Zext,
                wf: 1,
                a: c,
                ..
            } = self.get(a)
        {
            let nc = self.not1(c);
            return self.conv(ConvKind::Zext, 1, w, nc);
        }
        if op == BinOp::And
            && let Some(c) = self.const_val(b)
        {
            if c == m {
                return a;
            }
            if let Node::Conv {
                k: ConvKind::Zext,
                wf,
                ..
            } = self.get(a)
                && c & mask(wf as u32) == mask(wf as u32)
            {
                return a;
            }
        }
        if matches!(op, BinOp::Shl | BinOp::Shr | BinOp::Sar) && self.const_val(b) == Some(0) {
            return a;
        }
        self.intern(Node::Bin {
            op,
            w: w as u8,
            a,
            b,
        })
    }

    pub fn conv(&mut self, k: ConvKind, wf: u32, wt: u32, a: Id) -> Id {
        if let Some(v) = self.const_val(a) {
            let v = match k {
                ConvKind::Sext => sext(v, wf) as u64,
                _ => v,
            };
            return self.konst(v, wt);
        }
        let inner = self.get(a);
        if k == ConvKind::Trunc {
            match inner {
                Node::Conv {
                    k: ik @ (ConvKind::Zext | ConvKind::Sext),
                    wf: iwf,
                    a: ia,
                    ..
                } => {
                    let iwf = iwf as u32;
                    if iwf == wt {
                        return ia;
                    }
                    if iwf < wt {
                        return self.intern(Node::Conv {
                            k: ik,
                            wf: iwf as u8,
                            wt: wt as u8,
                            a: ia,
                        });
                    }
                    return self.conv(ConvKind::Trunc, iwf, wt, ia);
                }
                Node::Conv {
                    k: ConvKind::Trunc,
                    wf: iwf,
                    a: ia,
                    ..
                } => {
                    return self.intern(Node::Conv {
                        k: ConvKind::Trunc,
                        wf: iwf,
                        wt: wt as u8,
                        a: ia,
                    });
                }
                _ => {}
            }
        }
        if k == ConvKind::Zext
            && let Node::Conv {
                k: ConvKind::Zext,
                wf: iwf,
                a: ia,
                ..
            } = inner
        {
            return self.intern(Node::Conv {
                k: ConvKind::Zext,
                wf: iwf,
                wt: wt as u8,
                a: ia,
            });
        }
        if wf == wt {
            return a;
        }
        self.intern(Node::Conv {
            k,
            wf: wf as u8,
            wt: wt as u8,
            a,
        })
    }

    /// Constant-evaluate `e` with `target` replaced by `val`; None if anything else is symbolic.
    pub fn eval_with(&mut self, e: Id, target: Id, val: u64) -> Option<u64> {
        if e == target {
            return Some(val);
        }
        match self.get(e) {
            Node::C { v, .. } => Some(v),
            Node::R { .. }
            | Node::U { .. }
            | Node::Ld { .. }
            | Node::Cmp { .. }
            | Node::Not1 { .. }
            | Node::Ite { .. } => None,
            Node::Un { op, w, a } => {
                let v = self.eval_with(a, target, val)?;
                let c = self.konst(v, w as u32);
                let r = self.un(op, w as u32, c);
                self.const_val(r)
            }
            Node::Conv { k, wf, wt, a } => {
                let v = self.eval_with(a, target, val)?;
                let c = self.konst(v, wf as u32);
                let r = self.conv(k, wf as u32, wt as u32, c);
                self.const_val(r)
            }
            Node::Bin { op, w, a, b } => {
                let x = self.eval_with(a, target, val)?;
                let y = self.eval_with(b, target, val)?;
                let (cx, cy) = (self.konst(x, w as u32), self.konst(y, w as u32));
                let r = self.bin(op, w as u32, cx, cy);
                self.const_val(r)
            }
        }
    }

    /// A short rendering for logs and shadow records.
    pub fn render(&self, e: Id, depth: u32) -> String {
        if depth > 6 {
            return "...".into();
        }
        match self.get(e) {
            Node::C { v, .. } => format!("{v:#x}"),
            Node::R { off, .. } => format!("r{off}"),
            Node::U { .. } => "?".into(),
            Node::Ld { w, addr, .. } => format!("[{}]{w}", self.render(addr, depth + 1)),
            Node::Conv { k, wf, wt, a } => format!("{k:?}{wf}_{wt}({})", self.render(a, depth + 1)),
            Node::Not1 { a } => format!("!({})", self.render(a, depth + 1)),
            Node::Un { op, w, a } => format!("{op:?}{w}({})", self.render(a, depth + 1)),
            Node::Ite { c, a, b, .. } => format!(
                "ite({},{},{})",
                self.render(c, depth + 1),
                self.render(a, depth + 1),
                self.render(b, depth + 1)
            ),
            Node::Cmp { k, w, a, b } => {
                format!(
                    "{k:?}{w}({},{})",
                    self.render(a, depth + 1),
                    self.render(b, depth + 1)
                )
            }
            Node::Bin { op, a, b, .. } => {
                format!(
                    "{op:?}({},{})",
                    self.render(a, depth + 1),
                    self.render(b, depth + 1)
                )
            }
        }
    }
}

/// What an `IROp` means to the executor.
#[derive(Clone, Copy, Debug)]
enum OpKind {
    Conv {
        k: ConvKind,
        wf: u32,
        wt: u32,
    },
    /// `Iop_64HIto32` and the like.
    ConvHi {
        wt: u32,
    },
    Bin {
        op: BinOp,
        w: u32,
    },
    Cmp {
        k: CmpKind,
        w: u32,
    },
    Not1,
    Un {
        op: UnOp,
        w: u32,
    },
    Other,
}

fn parse_op(name: &str) -> OpKind {
    let Some(rest) = name.strip_prefix("Iop_") else {
        return OpKind::Other;
    };
    if rest == "Not1" {
        return OpKind::Not1;
    }
    for (p, op) in [("CtzNat", UnOp::Ctz), ("ClzNat", UnOp::Clz)] {
        if let Some(d) = rest.strip_prefix(p)
            && matches!(d, "32" | "64")
        {
            return OpKind::Un {
                op,
                w: d.parse().unwrap_or(64),
            };
        }
    }
    // the memcheck-precise comparisons are the same comparisons
    let rest = rest
        .strip_prefix("Exp")
        .filter(|r| r.starts_with("CmpNE"))
        .unwrap_or(rest);
    // Iop_<from>[U|S|HI|HL]to<to>
    if let Some(pos) = rest.find("to") {
        let (lhs, rhs) = (&rest[..pos], &rest[pos + 2..]);
        let digits = lhs.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let suffix = &lhs[digits.len()..];
        if !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit())
            && !rhs.is_empty()
            && rhs.chars().all(|c| c.is_ascii_digit())
            && matches!(suffix, "" | "U" | "S" | "HI" | "HL")
        {
            let wf: u32 = digits.parse().unwrap_or(0);
            let wt: u32 = rhs.parse().unwrap_or(0);
            if suffix == "HI" || suffix == "HL" {
                return OpKind::ConvHi { wt };
            }
            let k = if wt < wf {
                ConvKind::Trunc
            } else if suffix == "S" {
                ConvKind::Sext
            } else {
                ConvKind::Zext
            };
            return OpKind::Conv { k, wf, wt };
        }
    }
    for (p, op) in [
        ("Add", BinOp::Add),
        ("Sub", BinOp::Sub),
        ("Mul", BinOp::Mul),
        ("And", BinOp::And),
        ("Or", BinOp::Or),
        ("Xor", BinOp::Xor),
        ("Shl", BinOp::Shl),
        ("Shr", BinOp::Shr),
        ("Sar", BinOp::Sar),
    ] {
        if let Some(d) = rest.strip_prefix(p)
            && !d.is_empty()
            && d.chars().all(|c| c.is_ascii_digit())
        {
            return OpKind::Bin {
                op,
                w: d.parse().unwrap_or(0),
            };
        }
    }
    if let Some(c) = rest.strip_prefix("Cmp") {
        for p in ["EQ", "NE", "LT", "LE"] {
            let Some(d) = c.strip_prefix(p) else { continue };
            let digits = d.trim_end_matches(['U', 'S']);
            let suffix = &d[digits.len()..];
            if digits.is_empty()
                || !digits.chars().all(|ch| ch.is_ascii_digit())
                || suffix.len() > 1
            {
                continue;
            }
            let w: u32 = digits.parse().unwrap_or(0);
            let k = match (p, suffix) {
                ("EQ", "") => CmpKind::Eq,
                ("NE", "") => CmpKind::Ne,
                ("LT", "U") => CmpKind::Ltu,
                ("LT", "S") => CmpKind::Lts,
                ("LE", "U") => CmpKind::Leu,
                ("LE", "S") => CmpKind::Les,
                _ => continue,
            };
            return OpKind::Cmp { k, w };
        }
    }
    OpKind::Other
}

fn op_kind(op: u32) -> OpKind {
    static TABLE: OnceLock<FxHashMap<u32, OpKind>> = OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut m = FxHashMap::default();
        for (i, _) in crate::ailment::vexop_names::IROP_NAMES.iter().enumerate() {
            let op = crate::ailment::vexop_names::IOP_BASE + i as u32;
            m.insert(op, parse_op(op_name(op)));
        }
        m
    });
    t.get(&op).copied().unwrap_or(OpKind::Other)
}

fn int_bits(ty: u32) -> Option<u32> {
    match ty {
        vex_ffi::ITY_I1 => Some(1),
        vex_ffi::ITY_I8 => Some(8),
        vex_ffi::ITY_I16 => Some(16),
        vex_ffi::ITY_I32 => Some(32),
        vex_ffi::ITY_I64 => Some(64),
        _ => None,
    }
}

// cc_op -> (kind, width) for the flag-thunk condition helpers; condition codes per architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThunkKind {
    Add,
    Sub,
    Logic,
}

fn thunk_op(helper: &str, op: u64) -> Option<(ThunkKind, u32)> {
    match helper {
        "amd64g_calculate_condition" => match op {
            1..=4 => Some((ThunkKind::Add, 8 << (op - 1))),
            5..=8 => Some((ThunkKind::Sub, 8 << (op - 5))),
            17..=20 => Some((ThunkKind::Logic, 8 << (op - 17))),
            _ => None,
        },
        "x86g_calculate_condition" => match op {
            1..=3 => Some((ThunkKind::Add, 8 << (op - 1))),
            4..=6 => Some((ThunkKind::Sub, 8 << (op - 4))),
            13..=15 => Some((ThunkKind::Logic, 8 << (op - 13))),
            _ => None,
        },
        "armg_calculate_condition" => match op {
            1 => Some((ThunkKind::Add, 32)),
            2 => Some((ThunkKind::Sub, 32)),
            5 => Some((ThunkKind::Logic, 32)),
            _ => None,
        },
        "arm64g_calculate_condition" => match op {
            1 => Some((ThunkKind::Add, 32)),
            2 => Some((ThunkKind::Add, 64)),
            3 => Some((ThunkKind::Sub, 32)),
            4 => Some((ThunkKind::Sub, 64)),
            9 => Some((ThunkKind::Logic, 32)),
            10 => Some((ThunkKind::Logic, 64)),
            _ => None,
        },
        _ => None,
    }
}

/// x86 conditions B NB Z NZ BE NBE L NL LE NLE -> (relation, negated).
fn x86_cond(c: u64) -> Option<(CmpKind, bool)> {
    Some(match c {
        2 => (CmpKind::Ltu, false),
        3 => (CmpKind::Ltu, true),
        4 => (CmpKind::Eq, false),
        5 => (CmpKind::Eq, true),
        6 => (CmpKind::Leu, false),
        7 => (CmpKind::Leu, true),
        12 => (CmpKind::Lts, false),
        13 => (CmpKind::Lts, true),
        14 => (CmpKind::Les, false),
        15 => (CmpKind::Les, true),
        _ => return None,
    })
}

/// An x86 condition after `a + b` as a comparison of `a`: exact for a constant `b` (ZF also for any `b`).
fn add_cond(ar: &mut Arena, rel: CmpKind, w: u32, a: Id, b: Id) -> Option<Id> {
    let z = ar.konst(0, w);
    let Some(c) = ar.const_val(b) else {
        if rel != CmpKind::Eq {
            return None;
        }
        let r = ar.bin(BinOp::Add, w, a, b);
        return Some(ar.cmp(CmpKind::Eq, w, r, z));
    };
    let c = c & mask(w);
    let m = mask(w) as u128 + 1;
    Some(match rel {
        // the result is zero
        CmpKind::Eq => {
            let k = ar.konst(((m - c as u128) % m) as u64, w);
            ar.cmp(CmpKind::Eq, w, a, k)
        }
        // SF != OF: the sum is negative; with ZF: at most zero
        CmpKind::Lts | CmpKind::Les => {
            let neg = -sext(c, w);
            if neg >= 1i128 << (w - 1) {
                return None;
            }
            let k = ar.konst((neg.rem_euclid(m as i128)) as u64, w);
            ar.cmp(rel, w, a, k)
        }
        // CF: a carry out, a >= 2^w - c; with ZF also a == 2^w - c (the same set), or a == 0 when c == 0
        CmpKind::Ltu | CmpKind::Leu => {
            if c == 0 {
                return Some(if rel == CmpKind::Ltu {
                    ar.konst(0, 1)
                } else {
                    ar.cmp(CmpKind::Eq, w, a, z)
                });
            }
            let k = ar.konst((m - c as u128) as u64, w);
            let lt = ar.cmp(CmpKind::Ltu, w, a, k);
            ar.not1(lt)
        }
        CmpKind::Ne => return None,
    })
}

/// ARM conditions EQ NE HS LO HI LS GE LT GT LE -> (relation, negated).
fn arm_cond(c: u64) -> Option<(CmpKind, bool)> {
    Some(match c {
        0 => (CmpKind::Eq, false),
        1 => (CmpKind::Eq, true),
        2 => (CmpKind::Ltu, true),
        3 => (CmpKind::Ltu, false),
        8 => (CmpKind::Leu, true),
        9 => (CmpKind::Leu, false),
        10 => (CmpKind::Lts, true),
        11 => (CmpKind::Lts, false),
        12 => (CmpKind::Les, true),
        13 => (CmpKind::Les, false),
        _ => return None,
    })
}

/// The per-architecture constants the executor needs.
pub struct SymArch {
    pub bits: u32,
    pub bytes: u32,
    pub sp: i32,
    pub bp: i32,
    pub call_pushes_ret: bool,
    /// Offsets of the full-width registers.
    pub full_regs: rustc_hash::FxHashSet<i32>,
    /// The default calling convention's caller-saved offsets; None: calls cannot be crossed.
    pub caller_saved: Option<rustc_hash::FxHashSet<i32>>,
    pub amd64: bool,
}

/// How a block on a path ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The jump block: its `next`.
    Next(Id),
    /// Continues to the next block on the path.
    Continue,
}

/// One path's symbolic state.
pub struct PathState<'a> {
    pub ar: &'a mut Arena,
    arch: &'a SymArch,
    snap: &'a Snapshot,
    cvm: Option<&'a FcpTable>,
    /// MIPS: (gp offset, the function's gp); gp reads are pinned to it (Python's MIPSGPHook).
    gp: Option<(i32, u64)>,
    /// i386 PIC: (ebx offset, value of ebx at path start, `__x86.get_pc_thunk.bx` addresses); a call to a thunk
    /// sets ebx to the return address.
    pic: Option<(i32, Option<u64>, &'a rustc_hash::FxHashSet<u64>)>,
    /// offset -> (bits, value); None: a wide or non-integer value.
    regs: FxHashMap<i32, (u32, Option<Id>)>,
    mem: Vec<(Id, u32, Id)>,
    epoch: u32,
    pub guards: Vec<(Id, bool)>,
    after_call: bool,
    loc: (u64, i32, i64),
    pub cvm_hits: u32,
    /// Why the path could not be executed.
    pub why: &'static str,
}

impl<'a> PathState<'a> {
    pub fn new(
        ar: &'a mut Arena,
        arch: &'a SymArch,
        snap: &'a Snapshot,
        cvm: Option<&'a FcpTable>,
    ) -> Self {
        PathState {
            ar,
            arch,
            snap,
            cvm,
            gp: None,
            pic: None,
            regs: FxHashMap::default(),
            mem: Vec::new(),
            epoch: 0,
            guards: Vec::new(),
            after_call: false,
            loc: (0, 0, 0),
            cvm_hits: 0,
            why: "",
        }
    }

    pub fn with_gp(mut self, gp: Option<(i32, u64)>) -> Self {
        self.gp = gp;
        self
    }

    pub fn with_pic(
        mut self,
        pic: Option<(i32, Option<u64>, &'a rustc_hash::FxHashSet<u64>)>,
    ) -> Self {
        self.pic = pic;
        self
    }

    /// The value written to a register on this path, if any (full width).
    pub fn reg_value(&self, off: i32) -> Option<Id> {
        match self.regs.get(&off) {
            Some(&(_, v)) => v,
            None => None,
        }
    }

    fn gp_value(&mut self, w: u32) -> Option<Id> {
        let (_, gp) = self.gp?;
        let c = self.ar.konst(gp, self.arch.bits);
        Some(self.ar.conv(ConvKind::Trunc, self.arch.bits, w, c))
    }

    fn get_reg(&mut self, off: i32, w: u32) -> Id {
        if let Some((goff, _)) = self.gp
            && goff == off
        {
            return self.gp_value(w).unwrap();
        }
        if let Some(&(bw, v)) = self.regs.get(&off) {
            return match v {
                Some(e) if bw == w => e,
                Some(e) if bw > w => self.ar.conv(ConvKind::Trunc, bw, w, e),
                _ => self.ar.opaque(w),
            };
        }
        let end = off + (w / 8).max(1) as i32;
        if self
            .regs
            .iter()
            .any(|(&o, &(bw, _))| o != off && o < end && off < o + (bw / 8).max(1) as i32)
        {
            return self.ar.opaque(w);
        }
        if self.after_call {
            let killed = match &self.arch.caller_saved {
                Some(cs) => cs.contains(&off),
                None => true,
            };
            if killed || !self.arch.full_regs.contains(&off) {
                return self.ar.opaque(w);
            }
        }
        if let Some((poff, Some(v), _)) = self.pic
            && poff == off
        {
            let c = self.ar.konst(v, self.arch.bits);
            return self.ar.conv(ConvKind::Trunc, self.arch.bits, w, c);
        }
        if let Some(t) = self.cvm
            && let Some(v) = t.get(&self.loc, &Var::Reg(off, w / 8))
            && let Some(v) = v.to_u64()
        {
            self.cvm_hits += 1;
            return self.ar.konst(v, w);
        }
        let fw = self.arch.bits;
        if self.arch.full_regs.contains(&off) && fw >= w {
            let leaf = self.ar.reg(off, fw);
            return if fw == w {
                leaf
            } else {
                self.ar.conv(ConvKind::Trunc, fw, w, leaf)
            };
        }
        self.ar.reg(off, w)
    }

    fn put_reg(&mut self, off: i32, bits: u32, v: Option<Id>) {
        let end = off + (bits / 8).max(1) as i32;
        let mut killed = Vec::new();
        for (&o, &(bw, _)) in self.regs.iter() {
            if o != off && o < end && off < o + (bw / 8).max(1) as i32 {
                killed.push((o, bw));
            }
        }
        for (o, bw) in killed {
            self.regs.insert(o, (bw, None));
        }
        self.regs.insert(off, (bits, v));
    }

    /// A constant load from memory that cannot change (read-only sections/segments, `.got`, `.data.rel.ro`).
    fn read_const(&self, a: u64, size: usize, be: bool) -> Option<u64> {
        let snap = self.snap;
        snap.find_object_containing(a, true)?;
        let ro = match snap.find_section_containing(a) {
            Some((oi, si)) => {
                let sec = &snap.objects[oi].sections[si];
                !sec.is_writable || matches!(sec.name.as_deref(), Some(".got" | ".data.rel.ro"))
            }
            None => match snap.find_segment_containing(a) {
                Some((oi, si)) => !snap.objects[oi].segments[si].is_writable,
                None => false,
            },
        };
        if !ro {
            return None;
        }
        let data = snap.load_bytes(a, size)?;
        if data.len() != size {
            return None;
        }
        Some(if be {
            data.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
        } else {
            data.iter()
                .rev()
                .fold(0u64, |acc, &x| (acc << 8) | x as u64)
        })
    }

    fn load(&mut self, addr: Id, w: u32, be: bool) -> Id {
        if let Some(&(_, _, v)) = self.mem.iter().find(|(a, mw, _)| *a == addr && *mw == w) {
            return v;
        }
        if let Some(a) = self.ar.const_val(addr)
            && let Some(v) = self.read_const(a, (w / 8) as usize, be)
        {
            return self.ar.konst(v, w);
        }
        self.ar.load(w, addr, self.epoch, be)
    }

    fn split_base(&self, x: Id) -> (Id, i128) {
        if let Node::Bin {
            op: BinOp::Add,
            a,
            b,
            ..
        } = self.ar.get(x)
            && let Some(c) = self.ar.const_val(b)
        {
            return (a, sext(c, self.ar.width(b)));
        }
        (x, 0)
    }

    fn store(&mut self, addr: Id, w: u32, v: Id) {
        let (b0, o0) = self.split_base(addr);
        let a0 = self.ar.const_val(addr);
        let size = (w / 8) as i128;
        let mut keep = Vec::new();
        for &(k, kw, kv) in &self.mem {
            let ksize = (kw / 8) as i128;
            let (b1, o1) = self.split_base(k);
            let distinct = if b1 == b0 {
                o1 + ksize <= o0 || o0 + size <= o1
            } else if let (Some(x), Some(y)) = (self.ar.const_val(k), a0) {
                let (x, y) = (x as i128, y as i128);
                x + ksize <= y || y + size <= x
            } else {
                false
            };
            if distinct {
                keep.push((k, kw, kv));
            }
        }
        self.mem = keep;
        // stack slots (sp/bp + c) cannot hold the table or the index
        let stack = matches!(self.ar.get(addr), Node::Bin { op: BinOp::Add, a, b, .. }
            if self.ar.const_val(b).is_some()
                && matches!(self.ar.get(a), Node::R { off, .. } if off == self.arch.sp || off == self.arch.bp));
        if !stack {
            self.epoch += 1;
        }
        self.mem.push((addr, w, v));
    }

    fn clobber_call(&mut self) -> bool {
        let Some(cs) = &self.arch.caller_saved else {
            return false;
        };
        let sp = self.regs.get(&self.arch.sp).copied();
        let mut regs = FxHashMap::default();
        for (&o, &v) in &self.regs {
            if self.arch.full_regs.contains(&o) && !cs.contains(&o) {
                regs.insert(o, v);
            }
        }
        if self.arch.call_pushes_ret
            && let Some((bw, Some(e))) = sp
        {
            let c = self.ar.konst(self.arch.bytes as u64, bw);
            let v = self.ar.bin(BinOp::Add, bw, e, c);
            regs.insert(self.arch.sp, (bw, Some(v)));
        }
        self.regs = regs;
        self.after_call = true;
        self.epoch += 1;
        self.mem.clear();
        true
    }

    fn ex(&mut self, ir: &VexIrsb, tmps: &[Option<Id>], e: ExprId) -> Id {
        let Some(expr) = ir.expr(e) else {
            return self.ar.opaque(64);
        };
        match expr {
            Expr::RdTmp(t) => match tmps.get(*t as usize).copied().flatten() {
                Some(v) => v,
                None => {
                    let w = int_bits(ir.tmp_type(*t)).unwrap_or(64);
                    self.ar.opaque(w)
                }
            },
            Expr::Const(c) => self.konst_of(c),
            Expr::Get { offset, ty } => match int_bits(*ty) {
                Some(w) => self.get_reg(*offset, w),
                None => self.ar.opaque(64),
            },
            Expr::Load { end, ty, addr } => {
                let a = self.ex(ir, tmps, *addr);
                match int_bits(*ty) {
                    Some(w) if w >= 8 => self.load(a, w, *end == IEND_BE),
                    _ => self.ar.opaque(64),
                }
            }
            Expr::Unop { op, arg } => {
                let a = self.ex(ir, tmps, *arg);
                match op_kind(*op) {
                    OpKind::Conv { k, wf, wt } if wf <= 64 && wt <= 64 && wf > 0 && wt > 0 => {
                        self.ar.conv(k, wf, wt, a)
                    }
                    OpKind::ConvHi { wt } if wt <= 64 => self.ar.opaque(wt),
                    OpKind::Not1 => self.ar.not1(a),
                    OpKind::Un { op, w } if self.ar.width(a) == w => self.ar.un(op, w, a),
                    _ => self.opaque_like(ir, e),
                }
            }
            Expr::Binop { op, args } => match op_kind(*op) {
                OpKind::Bin { op: bop, w } if w <= 64 && w > 0 => {
                    let a = self.ex(ir, tmps, args[0]);
                    let mut b = self.ex(ir, tmps, args[1]);
                    if matches!(bop, BinOp::Shl | BinOp::Shr | BinOp::Sar)
                        && let Some(v) = self.ar.const_val(b)
                    {
                        b = self.ar.konst(v, w);
                    }
                    self.ar.bin(bop, w, a, b)
                }
                OpKind::Cmp { k, w } if w <= 64 && w > 0 => {
                    let a = self.ex(ir, tmps, args[0]);
                    let b = self.ex(ir, tmps, args[1]);
                    self.ar.cmp(k, w, a, b)
                }
                _ => self.opaque_like(ir, e),
            },
            Expr::Ite {
                cond,
                iftrue,
                iffalse,
            } => {
                let c = self.ex(ir, tmps, *cond);
                match (self.ar.const_val(c), int_bits(ir.result_type(e))) {
                    (Some(v), _) => self.ex(ir, tmps, if v != 0 { *iftrue } else { *iffalse }),
                    (None, Some(w)) => {
                        let a = self.ex(ir, tmps, *iftrue);
                        let b = self.ex(ir, tmps, *iffalse);
                        self.ar.ite(c, a, b, w)
                    }
                    (None, None) => self.opaque_like(ir, e),
                }
            }
            Expr::CCall {
                callee,
                retty,
                args,
            } => {
                let w = int_bits(*retty).unwrap_or(64);
                let ids: Vec<ExprId> = ir.arg_ids(*args).to_vec();
                let vals: Vec<Id> = ids.iter().map(|&a| self.ex(ir, tmps, a)).collect();
                match self.spec_ccall(callee, &vals) {
                    Some(c) => match self.ar.const_val(c) {
                        Some(v) => self.ar.konst(v, w),
                        None => self.ar.conv(ConvKind::Zext, 1, w, c),
                    },
                    None => self.ar.opaque(w),
                }
            }
            _ => self.opaque_like(ir, e),
        }
    }

    /// An opaque value of the expression's integer width (64 bits for anything else).
    fn opaque_like(&mut self, ir: &VexIrsb, e: ExprId) -> Id {
        let w = int_bits(ir.result_type(e)).unwrap_or(64);
        self.ar.opaque(w)
    }

    fn konst_of(&mut self, c: &IrConst) -> Id {
        match c.int_value() {
            Some(v) if c.bits() <= 64 => self.ar.konst(v, c.bits()),
            _ => self.ar.opaque(64),
        }
    }

    /// A flag-thunk condition helper with a constant cc_op, as a comparison.
    fn spec_ccall(&mut self, helper: &str, args: &[Id]) -> Option<Id> {
        let x86 = helper.starts_with("amd64") || helper.starts_with("x86");
        let (cv, opv, d1, d2) = if x86 {
            if args.len() < 4 {
                return None;
            }
            (
                self.ar.const_val(args[0])?,
                self.ar.const_val(args[1])?,
                args[2],
                args[3],
            )
        } else {
            if args.len() < 3 {
                return None;
            }
            let c = self.ar.const_val(args[0])?;
            (c >> 4, c & 0xF, args[1], args[2])
        };
        let (kind, w) = thunk_op(helper, opv)?;
        let (rel, neg) = if x86 { x86_cond(cv)? } else { arm_cond(cv)? };
        let trunc = |ar: &mut Arena, d: Id| {
            let dw = ar.width(d);
            if dw > w {
                ar.conv(ConvKind::Trunc, dw, w, d)
            } else {
                d
            }
        };
        let a = trunc(self.ar, d1);
        let b = trunc(self.ar, d2);
        let c = match kind {
            ThunkKind::Sub => {
                if let (Some(x), Some(y)) = (self.ar.const_val(a), self.ar.const_val(b)) {
                    return Some(self.ar.konst((eval_cmp(rel, w, x, y) != neg) as u64, 1));
                }
                self.ar.cmp(rel, w, a, b)
            }
            ThunkKind::Logic => {
                let z = self.ar.konst(0, w);
                match rel {
                    CmpKind::Eq | CmpKind::Leu => self.ar.cmp(CmpKind::Eq, w, a, z),
                    CmpKind::Les | CmpKind::Lts => self.ar.cmp(rel, w, a, z),
                    _ => return None,
                }
            }
            ThunkKind::Add if x86 => add_cond(self.ar, rel, w, a, b)?,
            ThunkKind::Add => return None,
        };
        Some(if neg { self.ar.not1(c) } else { c })
    }

    /// Execute one block of the path. `next_addr` is the next block on the path (None for the jump block).
    /// Returns None when the path cannot be executed (see `why`).
    pub fn run_block(&mut self, ir: &VexIrsb, next_addr: Option<u64>) -> Option<Step> {
        let mut tmps: Vec<Option<Id>> = vec![None; ir.tyenv.len()];
        let mut ins: u64 = ir.addr;
        for (idx, st) in ir.stmts.iter().enumerate() {
            if let Stmt::IMark { addr, delta, .. } = st {
                ins = addr + *delta as u64;
            }
            self.loc = (ir.addr, idx as i32, ins as i64);
            match st {
                Stmt::WrTmp { tmp, data } => {
                    let v = self.ex(ir, &tmps, *data);
                    if let Some(slot) = tmps.get_mut(*tmp as usize) {
                        *slot = Some(v);
                    }
                }
                Stmt::Put { offset, data } => {
                    let ty = ir.result_type(*data);
                    match int_bits(ty) {
                        Some(w) => {
                            let v = self.ex(ir, &tmps, *data);
                            self.put_reg(*offset, w, Some(v));
                        }
                        None => {
                            let bits = vex_ffi::type_size_bits(ty).max(8);
                            self.put_reg(*offset, bits, None);
                        }
                    }
                }
                Stmt::Store { addr, data, .. } => {
                    let a = self.ex(ir, &tmps, *addr);
                    let ty = ir.result_type(*data);
                    match int_bits(ty) {
                        Some(w) if w >= 8 => {
                            let v = self.ex(ir, &tmps, *data);
                            self.store(a, w, v);
                        }
                        _ => {
                            self.epoch += 1;
                            self.mem.clear();
                        }
                    }
                }
                Stmt::Exit { guard, dst, jk, .. } => {
                    let g = self.ex(ir, &tmps, *guard);
                    if *jk != IJK_BORING {
                        self.guards.push((g, false));
                        continue;
                    }
                    if let Some(nxt) = next_addr
                        && dst.int_value() == Some(nxt)
                    {
                        // both the exit and the fall-through reach the next block: no constraint
                        if ir.next_const() != Some(nxt) {
                            self.guards.push((g, true));
                        }
                        return Some(Step::Continue);
                    }
                    self.guards.push((g, false));
                }
                Stmt::LoadG {
                    end,
                    cvt,
                    dst,
                    addr,
                    alt,
                    guard,
                } => {
                    let g = self.ex(ir, &tmps, *guard);
                    let w = int_bits(ir.tmp_type(*dst)).unwrap_or(32);
                    // ILGop_Ident64 / ILGop_Ident32
                    let lw = match *cvt {
                        0x1D02 => Some(64),
                        0x1D03 => Some(32),
                        _ => None,
                    };
                    let v = match (self.ar.const_val(g), lw) {
                        (Some(0), _) => self.ex(ir, &tmps, *alt),
                        (_, Some(lw)) if lw == w => {
                            let a = self.ex(ir, &tmps, *addr);
                            let ld = self.load(a, lw, *end == IEND_BE);
                            let alt_v = self.ex(ir, &tmps, *alt);
                            // `ldrls pc, [...]`: the load only when the guard holds
                            self.ar.ite(g, ld, alt_v, w)
                        }
                        _ => self.ar.opaque(w),
                    };
                    if let Some(slot) = tmps.get_mut(*dst as usize) {
                        *slot = Some(v);
                    }
                }
                Stmt::StoreG { .. } => {
                    self.epoch += 1;
                    self.mem.clear();
                }
                Stmt::Dirty { tmp, nfx_state, .. } => {
                    if *nfx_state > 0 {
                        self.why = "dirty_fx";
                        return None;
                    }
                    if *tmp != u32::MAX
                        && let Some(slot) = tmps.get_mut(*tmp as usize)
                    {
                        let w = int_bits(ir.tmp_type(*tmp)).unwrap_or(64);
                        *slot = Some(self.ar.opaque(w));
                    }
                    self.epoch += 1;
                    self.mem.clear();
                }
                Stmt::Cas { old_lo, old_hi, .. } => {
                    for t in [*old_lo, *old_hi] {
                        if t != u32::MAX
                            && let Some(slot) = tmps.get_mut(t as usize)
                        {
                            let w = int_bits(ir.tmp_type(t)).unwrap_or(64);
                            *slot = Some(self.ar.opaque(w));
                        }
                    }
                    self.epoch += 1;
                    self.mem.clear();
                }
                Stmt::Llsc { result, .. } => {
                    if let Some(slot) = tmps.get_mut(*result as usize) {
                        let w = int_bits(ir.tmp_type(*result)).unwrap_or(64);
                        *slot = Some(self.ar.opaque(w));
                    }
                    self.epoch += 1;
                    self.mem.clear();
                }
                Stmt::PutI { .. } => {
                    self.why = "puti";
                    return None;
                }
                _ => {}
            }
        }
        let nxt = if ir.next == NO_EXPR {
            self.ar.opaque(self.arch.bits)
        } else {
            self.ex(ir, &tmps, ir.next)
        };
        let Some(nxt_addr) = next_addr else {
            return Some(Step::Next(nxt));
        };
        if jumpkind_name(ir.jumpkind) == "Ijk_Call" && nxt_addr == ir.addr + ir.size as u64 {
            if !self.clobber_call() {
                self.why = "call";
                return None;
            }
            if let Some((ebx, _, thunks)) = self.pic
                && ir
                    .next_const()
                    .is_some_and(|callee| thunks.contains(&callee))
            {
                let ret = self.ar.konst(nxt_addr, self.arch.bits);
                self.put_reg(ebx, self.arch.bits, Some(ret));
            }
            return Some(Step::Continue);
        }
        if ir.jumpkind != IJK_BORING {
            self.why = "jumpkind";
            return None;
        }
        match self.ar.const_val(nxt) {
            Some(v) if v == nxt_addr => Some(Step::Continue),
            Some(_) => {
                self.why = "next_const";
                None
            }
            // an indirect-jump predecessor: follow its CFG edge
            None => Some(Step::Continue),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_parsing() {
        assert!(matches!(
            parse_op("Iop_32Uto64"),
            OpKind::Conv {
                k: ConvKind::Zext,
                wf: 32,
                wt: 64
            }
        ));
        assert!(matches!(
            parse_op("Iop_8Sto32"),
            OpKind::Conv {
                k: ConvKind::Sext,
                wf: 8,
                wt: 32
            }
        ));
        assert!(matches!(
            parse_op("Iop_64to32"),
            OpKind::Conv {
                k: ConvKind::Trunc,
                wf: 64,
                wt: 32
            }
        ));
        assert!(matches!(
            parse_op("Iop_64HIto32"),
            OpKind::ConvHi { wt: 32 }
        ));
        assert!(matches!(
            parse_op("Iop_Add64"),
            OpKind::Bin {
                op: BinOp::Add,
                w: 64
            }
        ));
        assert!(matches!(
            parse_op("Iop_CmpLT32S"),
            OpKind::Cmp {
                k: CmpKind::Lts,
                w: 32
            }
        ));
        assert!(matches!(
            parse_op("Iop_CmpNE8"),
            OpKind::Cmp {
                k: CmpKind::Ne,
                w: 8
            }
        ));
        assert!(matches!(parse_op("Iop_F64toI32S"), OpKind::Other));
        assert!(matches!(parse_op("Iop_Add32x4"), OpKind::Other));
        assert!(matches!(parse_op("Iop_CmpEQ8x16"), OpKind::Other));
        assert!(matches!(
            parse_op("Iop_CtzNat64"),
            OpKind::Un {
                op: UnOp::Ctz,
                w: 64
            }
        ));
        assert!(matches!(
            parse_op("Iop_ClzNat32"),
            OpKind::Un {
                op: UnOp::Clz,
                w: 32
            }
        ));
        assert!(matches!(
            parse_op("Iop_ExpCmpNE64"),
            OpKind::Cmp {
                k: CmpKind::Ne,
                w: 64
            }
        ));
    }

    #[test]
    fn simplification() {
        let mut ar = Arena::default();
        let r = ar.reg(16, 64);
        let c1 = ar.konst(8, 64);
        let c2 = ar.konst((-8i64) as u64, 64);
        let a = ar.bin(BinOp::Add, 64, r, c1);
        assert_eq!(ar.bin(BinOp::Add, 64, a, c2), r);
        assert_eq!(ar.bin(BinOp::Sub, 64, a, c1), r);
        let t = ar.conv(ConvKind::Trunc, 64, 32, r);
        let z = ar.conv(ConvKind::Zext, 32, 64, t);
        assert_eq!(ar.conv(ConvKind::Trunc, 64, 32, z), t);
        let ff = ar.konst(0xffff_ffff, 64);
        assert_eq!(ar.bin(BinOp::And, 64, z, ff), z);
        let x = ar.bin(BinOp::Xor, 64, r, r);
        assert_eq!(ar.const_val(x), Some(0));
        let s = ar.konst(0xfffffff0, 32);
        let sx = ar.conv(ConvKind::Sext, 32, 64, s);
        assert_eq!(ar.const_val(sx), Some(0xffff_ffff_ffff_fff0));
    }

    #[test]
    fn eval_with_target_function() {
        let mut ar = Arena::default();
        let r = ar.reg(16, 64);
        let ld = ar.load(32, r, 0, false);
        let sx = ar.conv(ConvKind::Sext, 32, 64, ld);
        let base = ar.konst(0x5d1760, 64);
        let tgt = ar.bin(BinOp::Add, 64, sx, base);
        assert_eq!(ar.eval_with(tgt, ld, 0xfffffff0), Some(0x5d1750));
        assert_eq!(ar.eval_with(tgt, r, 0), None);
    }

    #[test]
    fn x86_add_conditions() {
        let mut ar = Arena::default();
        let x = ar.reg(16, 64);
        let c = ar.konst(0x20, 64);
        // add r8, 0x20; jl: the sum is negative, x <s -0x20
        let lt = add_cond(&mut ar, CmpKind::Lts, 64, x, c).unwrap();
        let k = ar.konst((-0x20i64) as u64, 64);
        assert_eq!(lt, ar.cmp(CmpKind::Lts, 64, x, k));
        // jle: x <=s -0x20
        let le = add_cond(&mut ar, CmpKind::Les, 64, x, c).unwrap();
        assert_eq!(le, ar.cmp(CmpKind::Les, 64, x, k));
        // jc: a carry out, !(x <u 2^64 - 0x20)
        let cf = add_cond(&mut ar, CmpKind::Ltu, 64, x, c).unwrap();
        let lt_k = ar.cmp(CmpKind::Ltu, 64, x, k);
        assert_eq!(cf, ar.not1(lt_k));
        // jz: x == -0x20
        let zf = add_cond(&mut ar, CmpKind::Eq, 64, x, c).unwrap();
        assert_eq!(zf, ar.cmp(CmpKind::Eq, 64, x, k));
        // adding the most negative value: -c does not fit
        let smin = ar.konst(1 << 63, 64);
        assert_eq!(add_cond(&mut ar, CmpKind::Lts, 64, x, smin), None);
        // no carry when adding zero
        let z = ar.konst(0, 64);
        assert_eq!(
            add_cond(&mut ar, CmpKind::Ltu, 64, x, z).and_then(|e| ar.const_val(e)),
            Some(0)
        );
    }

    #[test]
    fn x86_flag_thunk() {
        assert_eq!(
            thunk_op("amd64g_calculate_condition", 8),
            Some((ThunkKind::Sub, 64))
        );
        assert_eq!(
            thunk_op("x86g_calculate_condition", 6),
            Some((ThunkKind::Sub, 32))
        );
        assert_eq!(x86_cond(7), Some((CmpKind::Leu, true)));
        assert_eq!(arm_cond(9), Some((CmpKind::Leu, false)));
    }
}
