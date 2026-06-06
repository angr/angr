//! Phase D fat-enum design for AIL Statements (spike).
//!
//! Mirror of [`super::ail_expr`] for the Statement side of AIL. A single
//! [`Statement`] pyclass wraps an [`AilStatement`] which embeds an
//! [`StmtInner`] enum carrying per-variant data inline. Operand
//! subtrees are AIL expressions (modelled as
//! [`super::ail_expr::AilExpression`]), so the entire AIL tree is plain
//! Rust under the surface.
//!
//! The Python-side marker classes (``Assignment``, ``Store``, ...)
//! override ``__new__`` to construct [`Statement`] instances and use a
//! metaclass ``__instancecheck__`` that dispatches on the variant kind.
//! See ``angr/ailment/_phase_d_spike.py`` for the marker module.

use pyo3::exceptions::{PyAttributeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};

use crate::ailment::ail_expr::{AilExpression, Expression};
use crate::ailment::base::CachedHash;
use crate::ailment::hash::{HashItem, stable_hash};
use crate::ailment::tags::{Tags, TagsView};

// ---------------------------------------------------------------------------
// StmtHeader -- shared header carried by every variant
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct StmtHeader {
    pub idx: i64,
    pub tags: Tags,
    pub cached_hash: CachedHash,
}

impl Clone for StmtHeader {
    fn clone(&self) -> Self {
        Self {
            idx: self.idx,
            tags: self.tags.clone(),
            cached_hash: CachedHash::new(),
        }
    }
}

impl StmtHeader {
    pub fn new(idx: i64, tags: Tags) -> Self {
        Self {
            idx,
            tags,
            cached_hash: CachedHash::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// StmtInner -- fat enum, one arm per legacy Statement subclass
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum StmtInner {
    Assignment {
        dst: Box<AilExpression>,
        src: Box<AilExpression>,
    },
    WeakAssignment {
        dst: Box<AilExpression>,
        src: Box<AilExpression>,
    },
    Label {
        name: String,
    },
    Store {
        addr: Box<AilExpression>,
        data: Box<AilExpression>,
        /// Signed to accommodate the ``UNDETERMINED_SIZE = -0xC0DE`` sentinel.
        size: i32,
        endness: String,
        guard: Option<Box<AilExpression>>,
    },
    Jump {
        /// Typically a Const expression, but can be a Python int/str
        /// for indirect jumps with unresolved targets. Kept opaque.
        target: Py<PyAny>,
        target_idx: Option<i64>,
    },
    ConditionalJump {
        condition: Box<AilExpression>,
        true_target: Option<Py<PyAny>>,
        false_target: Option<Py<PyAny>>,
        true_target_idx: Option<i64>,
        false_target_idx: Option<i64>,
    },
    SideEffectStatement {
        expr: Box<AilExpression>,
        ret_expr: Option<Box<AilExpression>>,
        fp_ret_expr: Option<Box<AilExpression>>,
    },
    Return {
        ret_exprs: Vec<AilExpression>,
    },
    CAS {
        addr: Box<AilExpression>,
        data_lo: Box<AilExpression>,
        data_hi: Option<Box<AilExpression>>,
        expd_lo: Box<AilExpression>,
        expd_hi: Option<Box<AilExpression>>,
        old_lo: Box<AilExpression>,
        old_hi: Option<Box<AilExpression>>,
        endness: String,
    },
    DirtyStatement {
        /// Wraps a DirtyExpression AIL expression.
        dirty: Box<AilExpression>,
    },
}

impl StmtInner {
    pub fn kind(&self) -> &'static str {
        match self {
            StmtInner::Assignment { .. } => "Assignment",
            StmtInner::WeakAssignment { .. } => "WeakAssignment",
            StmtInner::Label { .. } => "Label",
            StmtInner::Store { .. } => "Store",
            StmtInner::Jump { .. } => "Jump",
            StmtInner::ConditionalJump { .. } => "ConditionalJump",
            StmtInner::SideEffectStatement { .. } => "SideEffectStatement",
            StmtInner::Return { .. } => "Return",
            StmtInner::CAS { .. } => "CAS",
            StmtInner::DirtyStatement { .. } => "DirtyStatement",
        }
    }
}

// ---------------------------------------------------------------------------
// AilStatement -- pure Rust, not exposed
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AilStatement {
    pub header: StmtHeader,
    pub inner: StmtInner,
}

impl AilStatement {
    pub fn kind(&self) -> &'static str {
        self.inner.kind()
    }

    pub fn _hash_core(&self) -> i64 {
        match &self.inner {
            StmtInner::Assignment { dst, src } => stable_hash(&[
                HashItem::TypeName("Assignment"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(dst.cached_hash_or_compute() as u64),
                HashItem::U64Hash(src.cached_hash_or_compute() as u64),
            ]) as i64,
            StmtInner::WeakAssignment { dst, src } => stable_hash(&[
                HashItem::TypeName("WeakAssignment"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(dst.cached_hash_or_compute() as u64),
                HashItem::U64Hash(src.cached_hash_or_compute() as u64),
            ]) as i64,
            StmtInner::Label { name } => stable_hash(&[
                HashItem::TypeName("Label"),
                HashItem::Int(self.header.idx as i128),
                HashItem::Str(name.as_str()),
            ]) as i64,
            StmtInner::Store {
                addr, data, size, endness, ..
            } => stable_hash(&[
                HashItem::TypeName("Store"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(addr.cached_hash_or_compute() as u64),
                HashItem::U64Hash(data.cached_hash_or_compute() as u64),
                HashItem::Int(*size as i128),
                HashItem::Str(endness.as_str()),
            ]) as i64,
            StmtInner::Jump { target, target_idx } => Python::attach(|py| {
                let th =
                    crate::ailment::utils::py_object_hash_u64(target.bind(py)).unwrap_or(0);
                let ti = match target_idx {
                    Some(v) => HashItem::Int(*v as i128),
                    None => HashItem::None,
                };
                stable_hash(&[
                    HashItem::TypeName("Jump"),
                    HashItem::Int(self.header.idx as i128),
                    HashItem::U64Hash(th),
                    ti,
                ]) as i64
            }),
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => Python::attach(|py| {
                let tt = match true_target {
                    Some(t) => HashItem::U64Hash(
                        crate::ailment::utils::py_object_hash_u64(t.bind(py)).unwrap_or(0),
                    ),
                    None => HashItem::None,
                };
                let ft = match false_target {
                    Some(t) => HashItem::U64Hash(
                        crate::ailment::utils::py_object_hash_u64(t.bind(py)).unwrap_or(0),
                    ),
                    None => HashItem::None,
                };
                stable_hash(&[
                    HashItem::TypeName("ConditionalJump"),
                    HashItem::Int(self.header.idx as i128),
                    HashItem::U64Hash(condition.cached_hash_or_compute() as u64),
                    tt,
                    ft,
                ]) as i64
            }),
            StmtInner::SideEffectStatement { expr, .. } => stable_hash(&[
                HashItem::TypeName("SideEffectStatement"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(expr.cached_hash_or_compute() as u64),
            ]) as i64,
            StmtInner::Return { ret_exprs } => {
                let items: Vec<HashItem> = ret_exprs
                    .iter()
                    .map(|e| HashItem::U64Hash(e.cached_hash_or_compute() as u64))
                    .collect();
                stable_hash(&[
                    HashItem::TypeName("Return"),
                    HashItem::Int(self.header.idx as i128),
                    HashItem::Tuple(items),
                ]) as i64
            }
            StmtInner::CAS {
                addr,
                data_lo,
                expd_lo,
                old_lo,
                endness,
                ..
            } => stable_hash(&[
                HashItem::TypeName("CAS"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(addr.cached_hash_or_compute() as u64),
                HashItem::U64Hash(data_lo.cached_hash_or_compute() as u64),
                HashItem::U64Hash(expd_lo.cached_hash_or_compute() as u64),
                HashItem::U64Hash(old_lo.cached_hash_or_compute() as u64),
                HashItem::Str(endness.as_str()),
            ]) as i64,
            StmtInner::DirtyStatement { dirty } => stable_hash(&[
                HashItem::TypeName("DirtyStatement"),
                HashItem::Int(self.header.idx as i128),
                HashItem::U64Hash(dirty.cached_hash_or_compute() as u64),
            ]) as i64,
        }
    }

    pub fn cached_hash_or_compute(&self) -> i64 {
        if let Some(h) = self.header.cached_hash.get() {
            return h;
        }
        let h = self._hash_core();
        self.header.cached_hash.set(h);
        h
    }

    /// Recursive deep-copy with fresh idx from
    /// ``manager.next_atom()``. Mirrors the expression-side helper;
    /// MultiStatementExpression's stmts are walked through this when
    /// the parent Expression's ``deep_copy_ail`` recurses.
    pub fn deep_copy_ail_stmt(
        &self,
        py: Python<'_>,
        manager: &Bound<'_, PyAny>,
    ) -> PyResult<AilStatement> {
        let new_idx: i64 = manager.call_method0("next_atom")?.extract()?;
        let new_header = StmtHeader::new(new_idx, self.header.tags.clone());
        let recurse = |child: &Box<AilExpression>| -> PyResult<Box<AilExpression>> {
            Ok(Box::new(child.deep_copy_ail(py, manager)?))
        };
        let recurse_opt = |o: &Option<Box<AilExpression>>| -> PyResult<Option<Box<AilExpression>>> {
            match o {
                None => Ok(None),
                Some(c) => Ok(Some(Box::new(c.deep_copy_ail(py, manager)?))),
            }
        };
        let recurse_vec = |v: &Vec<AilExpression>| -> PyResult<Vec<AilExpression>> {
            v.iter().map(|x| x.deep_copy_ail(py, manager)).collect()
        };
        let dc_pyany = |obj: &Py<PyAny>| -> PyResult<Py<PyAny>> {
            let copy_mod = py.import("copy")?;
            Ok(copy_mod.call_method1("deepcopy", (obj,))?.unbind())
        };
        let inner = match &self.inner {
            StmtInner::Assignment { dst, src } => StmtInner::Assignment {
                dst: recurse(dst)?,
                src: recurse(src)?,
            },
            StmtInner::WeakAssignment { dst, src } => StmtInner::WeakAssignment {
                dst: recurse(dst)?,
                src: recurse(src)?,
            },
            StmtInner::Label { name } => StmtInner::Label { name: name.clone() },
            StmtInner::Store {
                addr,
                data,
                size,
                endness,
                guard,
            } => StmtInner::Store {
                addr: recurse(addr)?,
                data: recurse(data)?,
                size: *size,
                endness: endness.clone(),
                guard: recurse_opt(guard)?,
            },
            StmtInner::Jump { target, target_idx } => StmtInner::Jump {
                target: dc_pyany(target)?,
                target_idx: *target_idx,
            },
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                true_target_idx,
                false_target_idx,
            } => StmtInner::ConditionalJump {
                condition: recurse(condition)?,
                true_target: match true_target {
                    Some(t) => Some(dc_pyany(t)?),
                    None => None,
                },
                false_target: match false_target {
                    Some(t) => Some(dc_pyany(t)?),
                    None => None,
                },
                true_target_idx: *true_target_idx,
                false_target_idx: *false_target_idx,
            },
            StmtInner::SideEffectStatement {
                expr,
                ret_expr,
                fp_ret_expr,
            } => StmtInner::SideEffectStatement {
                expr: recurse(expr)?,
                ret_expr: recurse_opt(ret_expr)?,
                fp_ret_expr: recurse_opt(fp_ret_expr)?,
            },
            StmtInner::Return { ret_exprs } => StmtInner::Return {
                ret_exprs: recurse_vec(ret_exprs)?,
            },
            StmtInner::CAS {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                endness,
            } => StmtInner::CAS {
                addr: recurse(addr)?,
                data_lo: recurse(data_lo)?,
                data_hi: recurse_opt(data_hi)?,
                expd_lo: recurse(expd_lo)?,
                expd_hi: recurse_opt(expd_hi)?,
                old_lo: recurse(old_lo)?,
                old_hi: recurse_opt(old_hi)?,
                endness: endness.clone(),
            },
            StmtInner::DirtyStatement { dirty } => StmtInner::DirtyStatement {
                dirty: recurse(dirty)?,
            },
        };
        Ok(AilStatement {
            header: new_header,
            inner,
        })
    }

    /// Recursive ``replace`` -- mirrors expression-side semantics.
    /// Walks operand subtrees and substitutes any expression node that
    /// ``__eq__``-matches ``old_expr``. Polymorphic Python-typed slots
    /// (e.g. Jump.target) are NOT walked into; replacement is for AIL
    /// expression substitution only.
    pub fn replace_ail_stmt(
        &self,
        old_expr: &AilExpression,
        new_expr: &AilExpression,
    ) -> (bool, AilStatement) {
        let walk =
            |child: &Box<AilExpression>| -> (bool, Box<AilExpression>) {
                let (c, r) = child.replace_ail(old_expr, new_expr);
                (c, Box::new(r))
            };
        let walk_opt = |o: &Option<Box<AilExpression>>| -> (bool, Option<Box<AilExpression>>) {
            match o {
                None => (false, None),
                Some(c) => {
                    let (changed, r) = c.replace_ail(old_expr, new_expr);
                    (changed, Some(Box::new(r)))
                }
            }
        };
        let walk_vec = |v: &Vec<AilExpression>| -> (bool, Vec<AilExpression>) {
            let mut changed = false;
            let mut out = Vec::with_capacity(v.len());
            for x in v {
                let (c, r) = x.replace_ail(old_expr, new_expr);
                changed |= c;
                out.push(r);
            }
            (changed, out)
        };
        match &self.inner {
            StmtInner::Assignment { dst, src } => {
                let (cd, rd) = walk(dst);
                let (cs, rs) = walk(src);
                if !cd && !cs {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::Assignment { dst: rd, src: rs },
                    },
                )
            }
            StmtInner::WeakAssignment { dst, src } => {
                let (cd, rd) = walk(dst);
                let (cs, rs) = walk(src);
                if !cd && !cs {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::WeakAssignment { dst: rd, src: rs },
                    },
                )
            }
            StmtInner::Store {
                addr,
                data,
                size,
                endness,
                guard,
            } => {
                let (ca, ra) = walk(addr);
                let (cd, rd) = walk(data);
                let (cg, rg) = walk_opt(guard);
                if !ca && !cd && !cg {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::Store {
                            addr: ra,
                            data: rd,
                            size: *size,
                            endness: endness.clone(),
                            guard: rg,
                        },
                    },
                )
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                true_target_idx,
                false_target_idx,
            } => {
                let (cc, rc) = walk(condition);
                if !cc {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::ConditionalJump {
                            condition: rc,
                            true_target: true_target.as_ref().map(|t| {
                                Python::attach(|py| t.clone_ref(py))
                            }),
                            false_target: false_target.as_ref().map(|t| {
                                Python::attach(|py| t.clone_ref(py))
                            }),
                            true_target_idx: *true_target_idx,
                            false_target_idx: *false_target_idx,
                        },
                    },
                )
            }
            StmtInner::SideEffectStatement {
                expr,
                ret_expr,
                fp_ret_expr,
            } => {
                let (ce, re) = walk(expr);
                let (cr, rr) = walk_opt(ret_expr);
                let (cf, rf) = walk_opt(fp_ret_expr);
                if !ce && !cr && !cf {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::SideEffectStatement {
                            expr: re,
                            ret_expr: rr,
                            fp_ret_expr: rf,
                        },
                    },
                )
            }
            StmtInner::Return { ret_exprs } => {
                let (c, r) = walk_vec(ret_exprs);
                if !c {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::Return { ret_exprs: r },
                    },
                )
            }
            StmtInner::CAS {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                endness,
            } => {
                let (ca, ra) = walk(addr);
                let (cdl, rdl) = walk(data_lo);
                let (cdh, rdh) = walk_opt(data_hi);
                let (cel, rel) = walk(expd_lo);
                let (ceh, reh) = walk_opt(expd_hi);
                let (col, rol) = walk(old_lo);
                let (coh, roh) = walk_opt(old_hi);
                if !ca && !cdl && !cdh && !cel && !ceh && !col && !coh {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::CAS {
                            addr: ra,
                            data_lo: rdl,
                            data_hi: rdh,
                            expd_lo: rel,
                            expd_hi: reh,
                            old_lo: rol,
                            old_hi: roh,
                            endness: endness.clone(),
                        },
                    },
                )
            }
            StmtInner::DirtyStatement { dirty } => {
                let (c, r) = walk(dirty);
                if !c {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::DirtyStatement { dirty: r },
                    },
                )
            }
            // Label and Jump have no expression subtrees to walk.
            _ => (false, self.clone()),
        }
    }

    /// Recursive ``has_atom`` -- check whether any expression subtree
    /// contains an expression node matching ``atom``.
    pub fn has_atom_ail_stmt(&self, atom: &AilExpression, identity: bool) -> bool {
        let check = |c: &Box<AilExpression>| c.has_atom_ail(atom, identity);
        let check_opt = |o: &Option<Box<AilExpression>>| -> bool {
            o.as_ref().is_some_and(|c| c.has_atom_ail(atom, identity))
        };
        let check_vec = |v: &Vec<AilExpression>| -> bool {
            v.iter().any(|x| x.has_atom_ail(atom, identity))
        };
        match &self.inner {
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                check(dst) || check(src)
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => check(addr) || check(data) || check_opt(guard),
            StmtInner::ConditionalJump { condition, .. } => check(condition),
            StmtInner::SideEffectStatement {
                expr,
                ret_expr,
                fp_ret_expr,
            } => check(expr) || check_opt(ret_expr) || check_opt(fp_ret_expr),
            StmtInner::Return { ret_exprs } => check_vec(ret_exprs),
            StmtInner::CAS {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                ..
            } => {
                check(addr)
                    || check(data_lo)
                    || check_opt(data_hi)
                    || check(expd_lo)
                    || check_opt(expd_hi)
                    || check(old_lo)
                    || check_opt(old_hi)
            }
            StmtInner::DirtyStatement { dirty } => check(dirty),
            StmtInner::Label { .. } | StmtInner::Jump { .. } => false,
        }
    }

    pub fn likes(&self, other: &AilStatement) -> bool {
        if self.kind() != other.kind() {
            return false;
        }
        // Helper used by Jump/ConditionalJump arms below: compare two
        // ``Py<PyAny>`` slots that hold a Jump target. Targets are typically
        // Expression instances (``Const``) but can also be plain Python
        // ``int`` or ``str`` for unresolved indirect jumps. ``Expression``
        // sees ``Expression.__eq__`` whose contract is idx-strict -- which
        // means two structurally equal targets with different freshly minted
        // ``.idx`` round-trip as not-equal, and structural ``likes()``
        // semantics on the surrounding Statement get poisoned by it. Prefer
        // calling ``.likes()`` when available (the structurally-equivalent
        // check used everywhere else on AIL atoms), and only fall back to
        // ``==`` for non-Expression target shapes.
        fn py_target_likes(py: Python<'_>, a: &Py<PyAny>, b: &Py<PyAny>) -> bool {
            let ab = a.bind(py);
            let bb = b.bind(py);
            if ab.is(&bb) {
                return true;
            }
            if let Ok(r) = ab.call_method1("likes", (bb,)) {
                if let Ok(t) = r.is_truthy() {
                    return t;
                }
            }
            ab.eq(b.bind(py)).unwrap_or(false)
        }
        match (&self.inner, &other.inner) {
            (
                StmtInner::Assignment { dst: a_d, src: a_s },
                StmtInner::Assignment { dst: b_d, src: b_s },
            )
            | (
                StmtInner::WeakAssignment { dst: a_d, src: a_s },
                StmtInner::WeakAssignment { dst: b_d, src: b_s },
            ) => a_d.likes(b_d) && a_s.likes(b_s),
            (
                StmtInner::Label { name: a },
                StmtInner::Label { name: b },
            ) => a == b,
            (
                StmtInner::Store {
                    addr: a_a,
                    data: a_d,
                    size: a_s,
                    endness: a_e,
                    ..
                },
                StmtInner::Store {
                    addr: b_a,
                    data: b_d,
                    size: b_s,
                    endness: b_e,
                    ..
                },
            ) => a_s == b_s && a_e == b_e && a_a.likes(b_a) && a_d.likes(b_d),
            (
                StmtInner::Jump {
                    target: a_t,
                    target_idx: a_ti,
                },
                StmtInner::Jump {
                    target: b_t,
                    target_idx: b_ti,
                },
            ) => a_ti == b_ti && Python::attach(|py| py_target_likes(py, a_t, b_t)),
            (
                StmtInner::ConditionalJump {
                    condition: a_c,
                    true_target: a_t,
                    false_target: a_f,
                    ..
                },
                StmtInner::ConditionalJump {
                    condition: b_c,
                    true_target: b_t,
                    false_target: b_f,
                    ..
                },
            ) => {
                if !a_c.likes(b_c) {
                    return false;
                }
                Python::attach(|py| {
                    let opt_likes =
                        |a: &Option<Py<PyAny>>, b: &Option<Py<PyAny>>| match (a, b) {
                            (None, None) => true,
                            (Some(x), Some(y)) => py_target_likes(py, x, y),
                            _ => false,
                        };
                    opt_likes(a_t, b_t) && opt_likes(a_f, b_f)
                })
            }
            (
                StmtInner::SideEffectStatement {
                    expr: a_e,
                    ret_expr: a_r,
                    fp_ret_expr: a_f,
                },
                StmtInner::SideEffectStatement {
                    expr: b_e,
                    ret_expr: b_r,
                    fp_ret_expr: b_f,
                },
            ) => {
                let opt_likes = |a: &Option<Box<AilExpression>>,
                                 b: &Option<Box<AilExpression>>| match (a, b) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x.likes(y),
                    _ => false,
                };
                a_e.likes(b_e) && opt_likes(a_r, b_r) && opt_likes(a_f, b_f)
            }
            (
                StmtInner::Return { ret_exprs: a },
                StmtInner::Return { ret_exprs: b },
            ) => a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.likes(y)),
            (
                StmtInner::CAS {
                    addr: a_a,
                    data_lo: a_dl,
                    data_hi: a_dh,
                    expd_lo: a_el,
                    expd_hi: a_eh,
                    old_lo: a_ol,
                    old_hi: a_oh,
                    endness: a_e,
                },
                StmtInner::CAS {
                    addr: b_a,
                    data_lo: b_dl,
                    data_hi: b_dh,
                    expd_lo: b_el,
                    expd_hi: b_eh,
                    old_lo: b_ol,
                    old_hi: b_oh,
                    endness: b_e,
                },
            ) => {
                let opt_likes = |a: &Option<Box<AilExpression>>,
                                 b: &Option<Box<AilExpression>>| match (a, b) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x.likes(y),
                    _ => false,
                };
                a_e == b_e
                    && a_a.likes(b_a)
                    && a_dl.likes(b_dl)
                    && opt_likes(a_dh, b_dh)
                    && a_el.likes(b_el)
                    && opt_likes(a_eh, b_eh)
                    && a_ol.likes(b_ol)
                    && opt_likes(a_oh, b_oh)
            }
            (
                StmtInner::DirtyStatement { dirty: a },
                StmtInner::DirtyStatement { dirty: b },
            ) => a.likes(b),
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Statement pyclass -- the only Python-facing class
// ---------------------------------------------------------------------------

#[pyclass(name = "Statement", module = "angr.rustylib.ailment", skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct Statement {
    pub stmt: AilStatement,
}

impl Statement {
    pub fn wrap(stmt: AilStatement) -> Self {
        Self { stmt }
    }

    /// Public stringifier used by stmt-bearing expressions (e.g.
    /// MultiStatementExpression's ``__str__``). Same logic as the
    /// ``#[getter]``-exposed ``__str__``.
    pub fn render(&self, py: Python<'_>) -> PyResult<String> {
        self.__str__(py)
    }
}

#[pymethods]
impl Statement {
    // --- Per-variant constructor factories ----------------------------

    #[staticmethod]
    #[pyo3(signature = (idx, dst, src, **kwargs))]
    fn _new_assignment(
        idx: i64,
        dst: Bound<'_, PyAny>,
        src: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let dst_ail = extract_ail_expr(&dst)?;
        let src_ail = extract_ail_expr(&src)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::Assignment {
                dst: Box::new(dst_ail),
                src: Box::new(src_ail),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, dst, src, **kwargs))]
    fn _new_weak_assignment(
        idx: i64,
        dst: Bound<'_, PyAny>,
        src: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let dst_ail = extract_ail_expr(&dst)?;
        let src_ail = extract_ail_expr(&src)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::WeakAssignment {
                dst: Box::new(dst_ail),
                src: Box::new(src_ail),
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, name, **kwargs))]
    fn _new_label(
        idx: i64,
        name: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::Label { name },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, addr, data, size, endness, guard=None, **kwargs))]
    #[allow(clippy::too_many_arguments)]
    fn _new_store(
        idx: i64,
        addr: Bound<'_, PyAny>,
        data: Bound<'_, PyAny>,
        size: i32,
        endness: String,
        guard: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let addr_ail = extract_ail_expr(&addr)?;
        let data_ail = extract_ail_expr(&data)?;
        let guard_box = match guard {
            Some(g) if !g.is_none() => Some(Box::new(extract_ail_expr(&g)?)),
            _ => None,
        };
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::Store {
                addr: Box::new(addr_ail),
                data: Box::new(data_ail),
                size,
                endness,
                guard: guard_box,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, target, target_idx=None, **kwargs))]
    fn _new_jump(
        idx: i64,
        target: Bound<'_, PyAny>,
        target_idx: Option<i64>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::Jump {
                target: target.unbind(),
                target_idx,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (
        idx, condition, true_target, false_target, *,
        true_target_idx=None, false_target_idx=None, **kwargs
    ))]
    #[allow(clippy::too_many_arguments)]
    fn _new_conditional_jump(
        idx: i64,
        condition: Bound<'_, PyAny>,
        true_target: Option<Bound<'_, PyAny>>,
        false_target: Option<Bound<'_, PyAny>>,
        true_target_idx: Option<i64>,
        false_target_idx: Option<i64>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let cond_ail = extract_ail_expr(&condition)?;
        let tt = true_target.and_then(|t| if t.is_none() { None } else { Some(t.unbind()) });
        let ft = false_target.and_then(|t| if t.is_none() { None } else { Some(t.unbind()) });
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::ConditionalJump {
                condition: Box::new(cond_ail),
                true_target: tt,
                false_target: ft,
                true_target_idx,
                false_target_idx,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, expr, ret_expr=None, fp_ret_expr=None, **kwargs))]
    fn _new_side_effect_statement(
        idx: i64,
        expr: Bound<'_, PyAny>,
        ret_expr: Option<Bound<'_, PyAny>>,
        fp_ret_expr: Option<Bound<'_, PyAny>>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let expr_ail = extract_ail_expr(&expr)?;
        let ret_box = match ret_expr {
            Some(r) if !r.is_none() => Some(Box::new(extract_ail_expr(&r)?)),
            _ => None,
        };
        let fp_box = match fp_ret_expr {
            Some(r) if !r.is_none() => Some(Box::new(extract_ail_expr(&r)?)),
            _ => None,
        };
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::SideEffectStatement {
                expr: Box::new(expr_ail),
                ret_expr: ret_box,
                fp_ret_expr: fp_box,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, ret_exprs, **kwargs))]
    fn _new_return(
        idx: i64,
        ret_exprs: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let mut v = Vec::new();
        if !ret_exprs.is_none() {
            for item in ret_exprs.try_iter()? {
                v.push(extract_ail_expr(&item?)?);
            }
        }
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::Return { ret_exprs: v },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (
        idx, addr, data_lo, data_hi, expd_lo, expd_hi, old_lo, old_hi, endness, **kwargs
    ))]
    #[allow(clippy::too_many_arguments)]
    fn _new_cas(
        idx: i64,
        addr: Bound<'_, PyAny>,
        data_lo: Bound<'_, PyAny>,
        data_hi: Option<Bound<'_, PyAny>>,
        expd_lo: Bound<'_, PyAny>,
        expd_hi: Option<Bound<'_, PyAny>>,
        old_lo: Bound<'_, PyAny>,
        old_hi: Option<Bound<'_, PyAny>>,
        endness: String,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let opt = |b: Option<Bound<'_, PyAny>>| -> PyResult<Option<Box<AilExpression>>> {
            match b {
                Some(x) if !x.is_none() => Ok(Some(Box::new(extract_ail_expr(&x)?))),
                _ => Ok(None),
            }
        };
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::CAS {
                addr: Box::new(extract_ail_expr(&addr)?),
                data_lo: Box::new(extract_ail_expr(&data_lo)?),
                data_hi: opt(data_hi)?,
                expd_lo: Box::new(extract_ail_expr(&expd_lo)?),
                expd_hi: opt(expd_hi)?,
                old_lo: Box::new(extract_ail_expr(&old_lo)?),
                old_hi: opt(old_hi)?,
                endness,
            },
        }))
    }

    #[staticmethod]
    #[pyo3(signature = (idx, dirty, **kwargs))]
    fn _new_dirty_statement(
        idx: i64,
        dirty: Bound<'_, PyAny>,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        let dirty_ail = extract_ail_expr(&dirty)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::DirtyStatement {
                dirty: Box::new(dirty_ail),
            },
        }))
    }

    // --- Universal header accessors -----------------------------------

    #[getter]
    fn idx(&self) -> i64 {
        self.stmt.header.idx
    }
    #[setter]
    fn set_idx(&mut self, v: i64) {
        self.stmt.header.idx = v;
        self.stmt.header.cached_hash.clear();
    }
    #[getter]
    fn tags(slf: Bound<'_, Self>) -> TagsView {
        let inner = slf.borrow().stmt.header.tags.clone();
        TagsView::with_parent(inner, slf.into_any().unbind())
    }
    #[setter]
    fn set_tags(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        if let Ok(tv) = value.cast::<TagsView>() {
            self.stmt.header.tags = tv.borrow().inner().clone();
        } else {
            self.stmt.header.tags = Tags::from_mapping(Some(&value))?;
        }
        self.stmt.header.cached_hash.clear();
        Ok(())
    }
    /// Variant discriminator. Python-side metaclass uses this for
    /// ``isinstance(x, Assignment)`` dispatch.
    #[getter]
    fn kind(&self) -> &'static str {
        self.stmt.kind()
    }

    fn clear_hash(&self) {
        self.stmt.header.cached_hash.clear();
    }

    // --- Per-variant accessors ----------------------------------------

    /// Assignment.dst / WeakAssignment.dst (operand subtree)
    #[getter]
    fn dst(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::Assignment { dst, .. } | StmtInner::WeakAssignment { dst, .. } => {
                Ok(Py::new(py, Expression::wrap((**dst).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'dst' on this Statement")),
        }
    }

    /// Store.addr / CAS.addr
    #[getter]
    fn addr(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::Store { addr, .. } | StmtInner::CAS { addr, .. } => {
                Ok(Py::new(py, Expression::wrap((**addr).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'addr' on this Statement")),
        }
    }

    /// Store.data
    #[getter]
    fn data(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::Store { data, .. } => {
                Ok(Py::new(py, Expression::wrap((**data).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'data' on this Statement")),
        }
    }

    /// Store.size
    #[getter]
    fn size(&self) -> PyResult<i32> {
        match &self.stmt.inner {
            StmtInner::Store { size, .. } => Ok(*size),
            _ => Err(PyAttributeError::new_err("no 'size' on this Statement")),
        }
    }

    /// Store.endness / CAS.endness
    #[getter]
    fn endness(&self) -> PyResult<String> {
        match &self.stmt.inner {
            StmtInner::Store { endness, .. } | StmtInner::CAS { endness, .. } => {
                Ok(endness.clone())
            }
            _ => Err(PyAttributeError::new_err("no 'endness' on this Statement")),
        }
    }

    /// Store.guard
    #[getter]
    fn guard(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::Store { guard, .. } => match guard {
                Some(g) => Ok(Some(
                    Py::new(py, Expression::wrap((**g).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'guard' on this Statement")),
        }
    }

    /// Jump.target / ConditionalJump callers reach for true_target/false_target
    /// (distinct getters below)
    #[getter]
    fn target(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::Jump { target, .. } => Ok(target.clone_ref(py)),
            _ => Err(PyAttributeError::new_err("no 'target' on this Statement")),
        }
    }

    /// Jump.target_idx
    #[getter]
    fn target_idx(&self) -> PyResult<Option<i64>> {
        match &self.stmt.inner {
            StmtInner::Jump { target_idx, .. } => Ok(*target_idx),
            _ => Err(PyAttributeError::new_err(
                "no 'target_idx' on this Statement",
            )),
        }
    }

    /// ConditionalJump.condition
    #[getter]
    fn condition(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { condition, .. } => {
                Ok(Py::new(py, Expression::wrap((**condition).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'condition' on this Statement",
            )),
        }
    }

    /// ConditionalJump.true_target
    #[getter]
    fn true_target<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { true_target, .. } => {
                Ok(true_target.as_ref().map(|t| t.bind(py).clone()))
            }
            _ => Err(PyAttributeError::new_err(
                "no 'true_target' on this Statement",
            )),
        }
    }

    /// ConditionalJump.false_target
    #[getter]
    fn false_target<'py>(&self, py: Python<'py>) -> PyResult<Option<Bound<'py, PyAny>>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { false_target, .. } => {
                Ok(false_target.as_ref().map(|t| t.bind(py).clone()))
            }
            _ => Err(PyAttributeError::new_err(
                "no 'false_target' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_target(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::Jump { target, .. } => {
                self.stmt.header.cached_hash.clear();
                *target = value.unbind();
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'target' on this Statement")),
        }
    }

    #[setter]
    fn set_target_idx(&mut self, value: Option<i64>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::Jump { target_idx, .. } => {
                self.stmt.header.cached_hash.clear();
                *target_idx = value;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'target_idx' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_condition(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail_expr(&value)?;
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { condition, .. } => {
                self.stmt.header.cached_hash.clear();
                *condition = Box::new(ail);
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'condition' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_true_target(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { true_target, .. } => {
                self.stmt.header.cached_hash.clear();
                *true_target = value.and_then(|v| if v.is_none() { None } else { Some(v.unbind()) });
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'true_target' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_false_target(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { false_target, .. } => {
                self.stmt.header.cached_hash.clear();
                *false_target = value.and_then(|v| if v.is_none() { None } else { Some(v.unbind()) });
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'false_target' on this Statement",
            )),
        }
    }

    /// ConditionalJump.true_target_idx
    #[getter]
    fn true_target_idx(&self) -> PyResult<Option<i64>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { true_target_idx, .. } => Ok(*true_target_idx),
            _ => Err(PyAttributeError::new_err(
                "no 'true_target_idx' on this Statement",
            )),
        }
    }

    /// ConditionalJump.false_target_idx
    #[getter]
    fn false_target_idx(&self) -> PyResult<Option<i64>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { false_target_idx, .. } => Ok(*false_target_idx),
            _ => Err(PyAttributeError::new_err(
                "no 'false_target_idx' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_true_target_idx(&mut self, value: Option<i64>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { true_target_idx, .. } => {
                self.stmt.header.cached_hash.clear();
                *true_target_idx = value;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'true_target_idx' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_false_target_idx(&mut self, value: Option<i64>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { false_target_idx, .. } => {
                self.stmt.header.cached_hash.clear();
                *false_target_idx = value;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'false_target_idx' on this Statement",
            )),
        }
    }

    /// SideEffectStatement.expr
    #[getter]
    fn expr(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::SideEffectStatement { expr, .. } => {
                Ok(Py::new(py, Expression::wrap((**expr).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'expr' on this Statement")),
        }
    }

    /// SideEffectStatement.ret_expr
    #[getter]
    fn ret_expr(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::SideEffectStatement { ret_expr, .. } => match ret_expr {
                Some(e) => Ok(Some(
                    Py::new(py, Expression::wrap((**e).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'ret_expr' on this Statement")),
        }
    }

    /// SideEffectStatement.fp_ret_expr
    #[getter]
    fn fp_ret_expr(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::SideEffectStatement { fp_ret_expr, .. } => match fp_ret_expr {
                Some(e) => Ok(Some(
                    Py::new(py, Expression::wrap((**e).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err(
                "no 'fp_ret_expr' on this Statement",
            )),
        }
    }

    /// Return.ret_exprs
    #[getter]
    fn ret_exprs<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        match &self.stmt.inner {
            StmtInner::Return { ret_exprs } => {
                let l = PyList::empty(py);
                for e in ret_exprs {
                    let py_e = Py::new(py, Expression::wrap(e.clone()))?;
                    l.append(py_e)?;
                }
                Ok(l)
            }
            _ => Err(PyAttributeError::new_err(
                "no 'ret_exprs' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_ret_exprs(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::Return { ret_exprs } => {
                let mut new_vec: Vec<AilExpression> = Vec::new();
                for item in value.try_iter()? {
                    new_vec.push(extract_ail_expr(&item?)?);
                }
                self.stmt.header.cached_hash.clear();
                *ret_exprs = new_vec;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'ret_exprs' on this Statement",
            )),
        }
    }

    /// CAS.data_lo / data_hi / expd_lo / expd_hi / old_lo / old_hi
    #[getter]
    fn data_lo(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::CAS { data_lo, .. } => {
                Ok(Py::new(py, Expression::wrap((**data_lo).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'data_lo' on this Statement")),
        }
    }
    #[getter]
    fn data_hi(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::CAS { data_hi, .. } => match data_hi {
                Some(e) => Ok(Some(
                    Py::new(py, Expression::wrap((**e).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'data_hi' on this Statement")),
        }
    }
    #[getter]
    fn expd_lo(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::CAS { expd_lo, .. } => {
                Ok(Py::new(py, Expression::wrap((**expd_lo).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'expd_lo' on this Statement")),
        }
    }
    #[getter]
    fn expd_hi(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::CAS { expd_hi, .. } => match expd_hi {
                Some(e) => Ok(Some(
                    Py::new(py, Expression::wrap((**e).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'expd_hi' on this Statement")),
        }
    }
    #[getter]
    fn old_lo(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::CAS { old_lo, .. } => {
                Ok(Py::new(py, Expression::wrap((**old_lo).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'old_lo' on this Statement")),
        }
    }
    #[getter]
    fn old_hi(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::CAS { old_hi, .. } => match old_hi {
                Some(e) => Ok(Some(
                    Py::new(py, Expression::wrap((**e).clone()))?.into_any(),
                )),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err("no 'old_hi' on this Statement")),
        }
    }

    /// DirtyStatement.dirty
    #[getter]
    fn dirty(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::DirtyStatement { dirty } => {
                Ok(Py::new(py, Expression::wrap((**dirty).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'dirty' on this Statement")),
        }
    }
    #[setter]
    fn set_dst(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail_expr(&value)?;
        match &mut self.stmt.inner {
            StmtInner::Assignment { dst, .. } | StmtInner::WeakAssignment { dst, .. } => {
                self.stmt.header.cached_hash.clear();
                *dst = Box::new(ail);
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'dst' on this Statement")),
        }
    }

    /// Assignment.src / WeakAssignment.src
    #[getter]
    fn src(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.stmt.inner {
            StmtInner::Assignment { src, .. } | StmtInner::WeakAssignment { src, .. } => {
                Ok(Py::new(py, Expression::wrap((**src).clone()))?.into_any())
            }
            _ => Err(PyAttributeError::new_err("no 'src' on this Statement")),
        }
    }
    #[setter]
    fn set_src(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail_expr(&value)?;
        match &mut self.stmt.inner {
            StmtInner::Assignment { src, .. } | StmtInner::WeakAssignment { src, .. } => {
                self.stmt.header.cached_hash.clear();
                *src = Box::new(ail);
                Ok(())
            }
            _ => Err(PyAttributeError::new_err("no 'src' on this Statement")),
        }
    }

    /// Label.name
    #[getter]
    fn name(&self) -> PyResult<String> {
        match &self.stmt.inner {
            StmtInner::Label { name } => Ok(name.clone()),
            _ => Err(PyAttributeError::new_err("no 'name' on this Statement")),
        }
    }

    /// SideEffectStatement.bits (derived from ``expr.bits``) /
    /// CAS.bits (sum of ``old_lo.bits`` + ``old_hi.bits``).
    #[getter]
    fn bits(&self) -> PyResult<u32> {
        match &self.stmt.inner {
            StmtInner::SideEffectStatement { expr, .. } => Ok(expr.header.bits),
            StmtInner::CAS { old_lo, old_hi, .. } => {
                let hi = old_hi.as_ref().map(|h| h.header.bits).unwrap_or(0);
                Ok(old_lo.header.bits + hi)
            }
            _ => Err(PyAttributeError::new_err("no 'bits' on this Statement")),
        }
    }

    /// Assignment/WeakAssignment/Store/CJump/SES/Return/CAS/Dirty depth
    #[getter]
    fn depth(&self, py: Python<'_>) -> PyResult<u32> {
        match &self.stmt.inner {
            StmtInner::Assignment { dst, src }
            | StmtInner::WeakAssignment { dst, src } => {
                Ok(dst.header.depth.max(src.header.depth) + 1)
            }
            StmtInner::Store { addr, data, .. } => {
                Ok(addr.header.depth.max(data.header.depth) + 1)
            }
            StmtInner::ConditionalJump { condition, .. } => Ok(condition.header.depth + 1),
            StmtInner::SideEffectStatement { expr, .. } => Ok(expr.header.depth + 1),
            StmtInner::Return { ret_exprs } => {
                Ok(ret_exprs
                    .iter()
                    .map(|e| e.header.depth)
                    .max()
                    .unwrap_or(0)
                    + 1)
            }
            StmtInner::CAS {
                addr,
                data_lo,
                expd_lo,
                old_lo,
                ..
            } => Ok(addr
                .header
                .depth
                .max(data_lo.header.depth)
                .max(expd_lo.header.depth)
                .max(old_lo.header.depth)
                + 1),
            StmtInner::DirtyStatement { dirty } => Ok(dirty.header.depth + 1),
            StmtInner::Jump { target, .. } => Ok(
                if let Ok(e) = target.bind(py).cast::<Expression>() {
                    e.borrow().expr.header.depth + 1
                } else {
                    1
                },
            ),
            _ => Err(PyAttributeError::new_err("no 'depth' on this Statement")),
        }
    }

    // --- Equality / hash ---------------------------------------------

    fn __hash__(&self) -> i64 {
        self.stmt.cached_hash_or_compute()
    }

    fn _hash_core(&self) -> i64 {
        self.stmt._hash_core()
    }

    /// Structural equality (ignores ``idx``). Exposed as a method
    /// because analyses use ``a.likes(b)`` rather than ``a == b``.
    fn likes(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Statement>() else {
            return Ok(false);
        };
        Ok(self.stmt.likes(&o.borrow().stmt))
    }

    /// Pattern matching -- identical to ``likes`` in the spike.
    fn matches(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        self.likes(other)
    }

    /// ``replace(old, new)`` -- substitute any expression node in
    /// operand subtrees that ``__eq__``-matches ``old``.
    fn replace<'py>(
        slf: PyRef<'py, Self>,
        old_expr: &Bound<'py, PyAny>,
        new_expr: &Bound<'py, PyAny>,
    ) -> PyResult<(bool, Py<PyAny>)> {
        let py = slf.py();
        let old_ail = extract_ail_expr(old_expr)?;
        let new_ail = extract_ail_expr(new_expr)?;
        let (changed, rebuilt) = slf.stmt.replace_ail_stmt(&old_ail, &new_ail);
        if !changed {
            return Ok((false, slf.into_pyobject(py)?.into_any().unbind()));
        }
        Ok((true, Py::new(py, Statement::wrap(rebuilt))?.into_any()))
    }

    /// ``has_atom(atom, identity=True)`` -- recursive subtree search.
    #[pyo3(signature = (atom, identity=true))]
    fn has_atom(&self, atom: &Bound<'_, PyAny>, identity: bool) -> PyResult<bool> {
        let atom_ail = extract_ail_expr(atom)?;
        Ok(self.stmt.has_atom_ail_stmt(&atom_ail, identity))
    }

    /// ``copy()`` -- shallow clone (same idx).
    fn copy(&self, py: Python<'_>) -> PyResult<Py<Self>> {
        Py::new(py, self.clone())
    }

    /// ``deep_copy(manager)`` -- recursive clone with fresh idx.
    fn deep_copy(&self, py: Python<'_>, manager: &Bound<'_, PyAny>) -> PyResult<Py<Self>> {
        let new = self.stmt.deep_copy_ail_stmt(py, manager)?;
        Py::new(py, Statement::wrap(new))
    }

    fn __copy__(&self, py: Python<'_>) -> PyResult<Py<Self>> {
        self.copy(py)
    }

    fn __deepcopy__<'py>(
        slf: Bound<'py, Self>,
        memo: Bound<'py, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let helper = py
            .import("angr.ailment._reconstruct")?
            .getattr("deepcopy_via_deep_copy")?;
        Ok(helper.call1((slf, memo))?.unbind())
    }

    /// Python ``pickle`` protocol via ``to_bytes`` / ``from_bytes``.
    /// Same lossy-field caveat as ``Expression.__reduce__``.
    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<Py<PyAny>> {
        let py = slf.py();
        let bytes = slf.borrow().to_bytes(py)?;
        let helper = py
            .import("angr.ailment._reconstruct")?
            .getattr("reconstruct_phase_d_statement")?;
        let args = pyo3::types::PyTuple::new(py, [bytes.into_any()])?;
        let tup = pyo3::types::PyTuple::new(py, [helper.unbind().into_any(), args.into_any().unbind()])?;
        Ok(tup.into_any().unbind())
    }

    fn __eq__(slf: Bound<'_, Self>, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        if slf.is(other) {
            return Ok(true);
        }
        let Ok(o) = other.cast::<Statement>() else {
            return Ok(false);
        };
        let s = slf.borrow();
        let o = o.borrow();
        if s.stmt.kind() != o.stmt.kind() {
            return Ok(false);
        }
        if s.stmt.header.idx != o.stmt.header.idx {
            return Ok(false);
        }
        Ok(s.stmt.likes(&o.stmt))
    }

    // --- Repr ---------------------------------------------------------

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        self.__str__(py)
    }

    fn __str__(&self, py: Python<'_>) -> PyResult<String> {
        match &self.stmt.inner {
            StmtInner::Assignment { dst, src } => {
                let d = Expression::wrap((**dst).clone()).render(py)?;
                let s = Expression::wrap((**src).clone()).render(py)?;
                Ok(format!("{} = {}", d, s))
            }
            StmtInner::WeakAssignment { dst, src } => {
                let d = Expression::wrap((**dst).clone()).render(py)?;
                let s = Expression::wrap((**src).clone()).render(py)?;
                Ok(format!("{} =w {}", d, s))
            }
            StmtInner::Label { name } => Ok(format!("Label {}:", name)),
            StmtInner::Store {
                addr, data, size, endness, guard, ..
            } => {
                let a = Expression::wrap((**addr).clone()).render(py)?;
                let d = Expression::wrap((**data).clone()).render(py)?;
                let g = match guard {
                    Some(gx) => format!(
                        " (guarded by {})",
                        Expression::wrap((**gx).clone()).render(py)?
                    ),
                    None => String::new(),
                };
                Ok(format!(
                    "STORE(addr={}, data={}, size={}, endness={}){}",
                    a, d, size, endness, g
                ))
            }
            StmtInner::Jump { target, .. } => {
                Ok(format!("Goto({})", target.bind(py).str()?))
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                let c = Expression::wrap((**condition).clone()).render(py)?;
                let t = match true_target {
                    Some(x) => x.bind(py).str()?.to_string(),
                    None => "None".into(),
                };
                let f = match false_target {
                    Some(x) => x.bind(py).str()?.to_string(),
                    None => "None".into(),
                };
                Ok(format!("if ({}) {{ Goto {} }} else {{ Goto {} }}", c, t, f))
            }
            StmtInner::SideEffectStatement { expr, .. } => {
                Ok(Expression::wrap((**expr).clone()).render(py)?)
            }
            StmtInner::Return { ret_exprs } => {
                let parts: Vec<String> = ret_exprs
                    .iter()
                    .map(|e| Expression::wrap(e.clone()).render(py).unwrap_or_default())
                    .collect();
                Ok(format!("Return ({})", parts.join(", ")))
            }
            StmtInner::CAS {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                endness,
            } => {
                let a = Expression::wrap((**addr).clone()).render(py)?;
                let dl = Expression::wrap((**data_lo).clone()).render(py)?;
                let dh = match data_hi {
                    Some(x) => Expression::wrap((**x).clone()).render(py)?,
                    None => "None".into(),
                };
                let el = Expression::wrap((**expd_lo).clone()).render(py)?;
                let eh = match expd_hi {
                    Some(x) => Expression::wrap((**x).clone()).render(py)?,
                    None => "None".into(),
                };
                let ol = Expression::wrap((**old_lo).clone()).render(py)?;
                let oh = match old_hi {
                    Some(x) => Expression::wrap((**x).clone()).render(py)?,
                    None => "None".into(),
                };
                Ok(format!(
                    "({}, {}) = CAS({}, ({}, {}), ({}, {}), {})",
                    ol, oh, a, el, eh, dl, dh, endness
                ))
            }
            StmtInner::DirtyStatement { dirty } => {
                Ok(Expression::wrap((**dirty).clone()).render(py)?)
            }
        }
    }

    // --- Byte serialization (spike-level) -----------------------------

    fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = postcard::to_stdvec(&serialize::StmtWire::from(&self.stmt))
            .map_err(|e| PyTypeError::new_err(format!("serialize: {}", e)))?;
        Ok(PyBytes::new(py, &bytes))
    }

    #[classmethod]
    fn from_bytes<'py>(
        _cls: &Bound<'_, pyo3::types::PyType>,
        py: Python<'py>,
        data: &[u8],
    ) -> PyResult<Py<Statement>> {
        let wire: serialize::StmtWire = postcard::from_bytes(data)
            .map_err(|e| PyTypeError::new_err(format!("deserialize: {}", e)))?;
        Py::new(py, Statement::wrap(wire.into_ail()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract an [`AilExpression`] from a Python object that must be a
/// Phase-D ``Expression`` instance.
fn extract_ail_expr(obj: &Bound<'_, PyAny>) -> PyResult<AilExpression> {
    let e: PyRef<'_, Expression> = obj
        .cast::<Expression>()
        .map_err(|_| PyTypeError::new_err("expected a Phase-D Expression"))?
        .borrow();
    Ok(e.expr.clone())
}

/// Extract an [`AilStatement`] from a Python object that must be a
/// Phase-D ``Statement`` instance. Used by stmt-bearing expressions
/// (MultiStatementExpression) once they migrate.
#[allow(dead_code)]
pub fn extract_ail_stmt(obj: &Bound<'_, PyAny>) -> PyResult<AilStatement> {
    let s: PyRef<'_, Statement> = obj
        .cast::<Statement>()
        .map_err(|_| PyTypeError::new_err("expected a Phase-D Statement"))?
        .borrow();
    Ok(s.stmt.clone())
}

// Silence the unused-imports warning for collection helpers reserved for
// the bulk migration's collection-bearing variants (Return, etc.).
#[allow(dead_code)]
fn _placeholder(l: &Bound<'_, PyList>, t: &Bound<'_, PyTuple>) {
    let _ = (l, t);
}

// ---------------------------------------------------------------------------
// Minimal serialization (spike-only)
// ---------------------------------------------------------------------------

mod serialize {
    use super::{AilStatement, StmtHeader, StmtInner};
    use crate::ailment::ail_expr::serialize as expr_serialize;
    use crate::ailment::tags::Tags;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct Hdr {
        pub idx: i64,
        pub tags: Tags,
    }

    #[derive(Serialize, Deserialize)]
    pub enum StmtWire {
        Assignment {
            h: Hdr,
            dst: expr_serialize::Wire,
            src: expr_serialize::Wire,
        },
        WeakAssignment {
            h: Hdr,
            dst: expr_serialize::Wire,
            src: expr_serialize::Wire,
        },
        Label {
            h: Hdr,
            name: String,
        },
        Store {
            h: Hdr,
            addr: expr_serialize::Wire,
            data: expr_serialize::Wire,
            size: i32,
            endness: String,
            guard: Option<expr_serialize::Wire>,
        },
        Jump {
            h: Hdr,
            target: expr_serialize::PolyValue,
            target_idx: Option<i64>,
        },
        ConditionalJump {
            h: Hdr,
            condition: expr_serialize::Wire,
            true_target: Option<expr_serialize::PolyValue>,
            false_target: Option<expr_serialize::PolyValue>,
            true_target_idx: Option<i64>,
            false_target_idx: Option<i64>,
        },
        SideEffectStatement {
            h: Hdr,
            expr: expr_serialize::Wire,
            ret_expr: Option<expr_serialize::Wire>,
            fp_ret_expr: Option<expr_serialize::Wire>,
        },
        Return {
            h: Hdr,
            ret_exprs: Vec<expr_serialize::Wire>,
        },
        CAS {
            h: Hdr,
            addr: expr_serialize::Wire,
            data_lo: expr_serialize::Wire,
            data_hi: Option<expr_serialize::Wire>,
            expd_lo: expr_serialize::Wire,
            expd_hi: Option<expr_serialize::Wire>,
            old_lo: expr_serialize::Wire,
            old_hi: Option<expr_serialize::Wire>,
            endness: String,
        },
        DirtyStatement {
            h: Hdr,
            dirty: expr_serialize::Wire,
        },
    }

    impl StmtWire {
        pub fn from(stmt: &AilStatement) -> Self {
            let h = Hdr {
                idx: stmt.header.idx,
                tags: stmt.header.tags.clone(),
            };
            match &stmt.inner {
                StmtInner::Assignment { dst, src } => StmtWire::Assignment {
                    h,
                    dst: expr_serialize::Wire::from(dst),
                    src: expr_serialize::Wire::from(src),
                },
                StmtInner::WeakAssignment { dst, src } => StmtWire::WeakAssignment {
                    h,
                    dst: expr_serialize::Wire::from(dst),
                    src: expr_serialize::Wire::from(src),
                },
                StmtInner::Label { name } => StmtWire::Label {
                    h,
                    name: name.clone(),
                },
                StmtInner::Store {
                    addr,
                    data,
                    size,
                    endness,
                    guard,
                } => StmtWire::Store {
                    h,
                    addr: expr_serialize::Wire::from(addr),
                    data: expr_serialize::Wire::from(data),
                    size: *size,
                    endness: endness.clone(),
                    guard: guard.as_ref().map(|g| expr_serialize::Wire::from(g)),
                },
                StmtInner::Jump { target, target_idx } => StmtWire::Jump {
                    h,
                    target: pyo3::Python::attach(|py| {
                        expr_serialize::PolyValue::from_pyany(target.bind(py))
                            .unwrap_or(expr_serialize::PolyValue::None)
                    }),
                    target_idx: *target_idx,
                },
                StmtInner::ConditionalJump {
                    condition,
                    true_target,
                    false_target,
                    true_target_idx,
                    false_target_idx,
                } => StmtWire::ConditionalJump {
                    h,
                    condition: expr_serialize::Wire::from(condition),
                    true_target: true_target.as_ref().map(|t| {
                        pyo3::Python::attach(|py| {
                            expr_serialize::PolyValue::from_pyany(t.bind(py))
                                .unwrap_or(expr_serialize::PolyValue::None)
                        })
                    }),
                    false_target: false_target.as_ref().map(|t| {
                        pyo3::Python::attach(|py| {
                            expr_serialize::PolyValue::from_pyany(t.bind(py))
                                .unwrap_or(expr_serialize::PolyValue::None)
                        })
                    }),
                    true_target_idx: *true_target_idx,
                    false_target_idx: *false_target_idx,
                },
                StmtInner::SideEffectStatement {
                    expr,
                    ret_expr,
                    fp_ret_expr,
                } => StmtWire::SideEffectStatement {
                    h,
                    expr: expr_serialize::Wire::from(expr),
                    ret_expr: ret_expr.as_ref().map(|e| expr_serialize::Wire::from(e)),
                    fp_ret_expr: fp_ret_expr.as_ref().map(|e| expr_serialize::Wire::from(e)),
                },
                StmtInner::Return { ret_exprs } => StmtWire::Return {
                    h,
                    ret_exprs: ret_exprs.iter().map(expr_serialize::Wire::from).collect(),
                },
                StmtInner::CAS {
                    addr,
                    data_lo,
                    data_hi,
                    expd_lo,
                    expd_hi,
                    old_lo,
                    old_hi,
                    endness,
                } => StmtWire::CAS {
                    h,
                    addr: expr_serialize::Wire::from(addr),
                    data_lo: expr_serialize::Wire::from(data_lo),
                    data_hi: data_hi.as_ref().map(|e| expr_serialize::Wire::from(e)),
                    expd_lo: expr_serialize::Wire::from(expd_lo),
                    expd_hi: expd_hi.as_ref().map(|e| expr_serialize::Wire::from(e)),
                    old_lo: expr_serialize::Wire::from(old_lo),
                    old_hi: old_hi.as_ref().map(|e| expr_serialize::Wire::from(e)),
                    endness: endness.clone(),
                },
                StmtInner::DirtyStatement { dirty } => StmtWire::DirtyStatement {
                    h,
                    dirty: expr_serialize::Wire::from(dirty),
                },
            }
        }

        pub fn into_ail(self) -> AilStatement {
            fn rebuild_header(h: Hdr) -> StmtHeader {
                StmtHeader::new(h.idx, h.tags)
            }
            match self {
                StmtWire::Assignment { h, dst, src } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Assignment {
                        dst: Box::new(dst.into_ail()),
                        src: Box::new(src.into_ail()),
                    },
                },
                StmtWire::WeakAssignment { h, dst, src } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::WeakAssignment {
                        dst: Box::new(dst.into_ail()),
                        src: Box::new(src.into_ail()),
                    },
                },
                StmtWire::Label { h, name } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Label { name },
                },
                StmtWire::Store {
                    h,
                    addr,
                    data,
                    size,
                    endness,
                    guard,
                } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Store {
                        addr: Box::new(addr.into_ail()),
                        data: Box::new(data.into_ail()),
                        size,
                        endness,
                        guard: guard.map(|g| Box::new(g.into_ail())),
                    },
                },
                StmtWire::Jump {
                    h,
                    target,
                    target_idx,
                } => pyo3::Python::attach(|py| AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Jump {
                        target: target.into_pyany(py).unwrap_or_else(|_| py.None()),
                        target_idx,
                    },
                }),
                StmtWire::ConditionalJump {
                    h,
                    condition,
                    true_target,
                    false_target,
                    true_target_idx,
                    false_target_idx,
                } => pyo3::Python::attach(|py| AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::ConditionalJump {
                        condition: Box::new(condition.into_ail()),
                        true_target: true_target.and_then(|pv| pv.into_pyany(py).ok()),
                        false_target: false_target.and_then(|pv| pv.into_pyany(py).ok()),
                        true_target_idx,
                        false_target_idx,
                    },
                }),
                StmtWire::SideEffectStatement {
                    h,
                    expr,
                    ret_expr,
                    fp_ret_expr,
                } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::SideEffectStatement {
                        expr: Box::new(expr.into_ail()),
                        ret_expr: ret_expr.map(|e| Box::new(e.into_ail())),
                        fp_ret_expr: fp_ret_expr.map(|e| Box::new(e.into_ail())),
                    },
                },
                StmtWire::Return { h, ret_exprs } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Return {
                        ret_exprs: ret_exprs
                            .into_iter()
                            .map(expr_serialize::Wire::into_ail)
                            .collect(),
                    },
                },
                StmtWire::CAS {
                    h,
                    addr,
                    data_lo,
                    data_hi,
                    expd_lo,
                    expd_hi,
                    old_lo,
                    old_hi,
                    endness,
                } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::CAS {
                        addr: Box::new(addr.into_ail()),
                        data_lo: Box::new(data_lo.into_ail()),
                        data_hi: data_hi.map(|e| Box::new(e.into_ail())),
                        expd_lo: Box::new(expd_lo.into_ail()),
                        expd_hi: expd_hi.map(|e| Box::new(e.into_ail())),
                        old_lo: Box::new(old_lo.into_ail()),
                        old_hi: old_hi.map(|e| Box::new(e.into_ail())),
                        endness,
                    },
                },
                StmtWire::DirtyStatement { h, dirty } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::DirtyStatement {
                        dirty: Box::new(dirty.into_ail()),
                    },
                },
            }
        }
    }
}

// Re-export for parent module
pub use serialize::StmtWire;
