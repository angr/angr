//! Fat-enum design for AIL Statements.
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
//! See ``angr/ailment/statement.py`` for the marker classes.

use pyo3::exceptions::{PyAttributeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::ailment::ail_expr::{AilExpression, CFGTarget, Expression};
use crate::ailment::base::CachedHash;
use crate::ailment::enums::StatementKind;
use crate::ailment::hash::{AilHash, finish, hasher};
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
        /// Typically a Const expression (resolved target) but may be a
        /// symbolic ``str`` for unresolved indirect jumps. Stored as the
        /// typed ``CFGTarget`` sum -- see ``ail_expr.rs::CFGTarget`` for
        /// rationale.
        target: CFGTarget,
        target_idx: Option<i64>,
    },
    ConditionalJump {
        condition: Box<AilExpression>,
        true_target: Option<CFGTarget>,
        false_target: Option<CFGTarget>,
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
    /// In-place placeholder for a removed statement. Defines and uses
    /// no atoms; primarily used by the AIL simplifier's dead-assignment
    /// removal so the indices of surrounding statements stay stable
    /// until the block is compacted.
    NoOp,
}

impl StmtInner {
    pub fn kind(&self) -> StatementKind {
        match self {
            StmtInner::Assignment { .. } => StatementKind::Assignment,
            StmtInner::WeakAssignment { .. } => StatementKind::WeakAssignment,
            StmtInner::Label { .. } => StatementKind::Label,
            StmtInner::Store { .. } => StatementKind::Store,
            StmtInner::Jump { .. } => StatementKind::Jump,
            StmtInner::ConditionalJump { .. } => StatementKind::ConditionalJump,
            StmtInner::SideEffectStatement { .. } => StatementKind::SideEffectStatement,
            StmtInner::Return { .. } => StatementKind::Return,
            StmtInner::CAS { .. } => StatementKind::CAS,
            StmtInner::DirtyStatement { .. } => StatementKind::DirtyStatement,
            StmtInner::NoOp => StatementKind::NoOp,
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
    pub fn kind(&self) -> StatementKind {
        self.inner.kind()
    }

    pub fn kind_str(&self) -> &'static str {
        self.inner.kind().as_str()
    }

    pub fn _hash_core(&self) -> i64 {
        let mut h = hasher();
        match &self.inner {
            StmtInner::Assignment { dst, src } => {
                h.typename("Assignment");
                h.int(self.header.idx as i128);
                h.child(dst.cached_hash_or_compute());
                h.child(src.cached_hash_or_compute());
            }
            StmtInner::WeakAssignment { dst, src } => {
                h.typename("WeakAssignment");
                h.int(self.header.idx as i128);
                h.child(dst.cached_hash_or_compute());
                h.child(src.cached_hash_or_compute());
            }
            StmtInner::Label { name } => {
                h.typename("Label");
                h.int(self.header.idx as i128);
                h.string(name.as_str());
            }
            StmtInner::Store {
                addr,
                data,
                size,
                endness,
                ..
            } => {
                h.typename("Store");
                h.int(self.header.idx as i128);
                h.child(addr.cached_hash_or_compute());
                h.child(data.cached_hash_or_compute());
                h.int(*size as i128);
                h.string(endness.as_str());
            }
            StmtInner::Jump { target, target_idx } => {
                h.typename("Jump");
                h.int(self.header.idx as i128);
                target.hash_into(&mut h);
                h.opt_int(target_idx.map(|v| v as i128));
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                h.typename("ConditionalJump");
                h.int(self.header.idx as i128);
                h.child(condition.cached_hash_or_compute());
                match true_target {
                    Some(t) => t.hash_into(&mut h),
                    None => h.none(),
                }
                match false_target {
                    Some(t) => t.hash_into(&mut h),
                    None => h.none(),
                }
            }
            StmtInner::SideEffectStatement { expr, .. } => {
                h.typename("SideEffectStatement");
                h.int(self.header.idx as i128);
                h.child(expr.cached_hash_or_compute());
            }
            StmtInner::Return { ret_exprs } => {
                h.typename("Return");
                h.int(self.header.idx as i128);
                h.seq(ret_exprs.len());
                for e in ret_exprs {
                    h.child(e.cached_hash_or_compute());
                }
            }
            StmtInner::CAS {
                addr,
                data_lo,
                expd_lo,
                old_lo,
                endness,
                ..
            } => {
                h.typename("CAS");
                h.int(self.header.idx as i128);
                h.child(addr.cached_hash_or_compute());
                h.child(data_lo.cached_hash_or_compute());
                h.child(expd_lo.cached_hash_or_compute());
                h.child(old_lo.cached_hash_or_compute());
                h.string(endness.as_str());
            }
            StmtInner::DirtyStatement { dirty } => {
                h.typename("DirtyStatement");
                h.int(self.header.idx as i128);
                h.child(dirty.cached_hash_or_compute());
            }
            StmtInner::NoOp => {
                h.typename("NoOp");
            }
        }
        finish(h)
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
        let vmap = manager.getattr("variable_map")?;
        if !vmap.is_none() {
            vmap.call_method1("transfer", (self.header.idx, new_idx))?;
        }
        let new_header = StmtHeader::new(new_idx, self.header.tags.clone());
        let recurse = |child: &AilExpression| -> PyResult<Box<AilExpression>> {
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
        // Deep copy a CFGTarget: recursively deep-copy the inner
        // expression for ``Expr``, clone the string for ``Symbol``.
        let dc_target = |t: &CFGTarget| -> PyResult<CFGTarget> {
            match t {
                CFGTarget::Expr(e) => Ok(CFGTarget::Expr(Box::new(e.deep_copy_ail(py, manager)?))),
                CFGTarget::Symbol(s) => Ok(CFGTarget::Symbol(s.clone())),
            }
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
                target: dc_target(target)?,
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
                    Some(t) => Some(dc_target(t)?),
                    None => None,
                },
                false_target: match false_target {
                    Some(t) => Some(dc_target(t)?),
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
            StmtInner::NoOp => StmtInner::NoOp,
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
        let walk = |child: &AilExpression| -> (bool, Box<AilExpression>) {
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
                let walk_target = |slot: &Option<CFGTarget>| -> (bool, Option<CFGTarget>) {
                    match slot {
                        None => (false, None),
                        Some(t) => {
                            let (c, r) = t.replace_ail(old_expr, new_expr);
                            (c, Some(r))
                        }
                    }
                };
                let (ct_ch, ct_new) = walk_target(true_target);
                let (cf_ch, cf_new) = walk_target(false_target);
                if !cc && !ct_ch && !cf_ch {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::ConditionalJump {
                            condition: rc,
                            true_target: ct_new,
                            false_target: cf_new,
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
            // Jump and ConditionalJump store target slots as
            // ``Py<PyAny>`` because callers occasionally place non-AIL
            // values there (plain ``int`` or ``str`` for unresolved
            // indirect targets), but the common case is an AIL
            // ``Expression`` and a propagator that wants to fold a vvar
            // into the target -- e.g. lowering ``Goto vvar_X`` into
            // ``Goto(Conv(Load(...)))`` so the structurer can recognize
            // a jumptable -- has to be able to walk into it. Recurse if
            // the slot wraps an ``Expression``.
            StmtInner::Jump { target, target_idx } => {
                let (changed, new_target) = target.replace_ail(old_expr, new_expr);
                if !changed {
                    return (false, self.clone());
                }
                (
                    true,
                    AilStatement {
                        header: self.header.clone(),
                        inner: StmtInner::Jump {
                            target: new_target,
                            target_idx: *target_idx,
                        },
                    },
                )
            }
            // Label has no expression subtrees to walk.
            _ => (false, self.clone()),
        }
    }

    /// Structural-with-identity equality on statements. ``likes`` is the
    /// statement-level analogue of ``AilExpression::likes``: two statements
    /// like each other when they are the same variant, every sub-expression
    /// like-matches, and every plain-Python slot (Jump targets,
    /// SimCC/SimType payloads, etc.) compares equal via Python ``==``.
    /// Sub-expressions are compared via ``AilExpression::likes``, so SSA
    /// ``varid`` differences propagate up and cause two structurally
    /// identical statements to not ``likes`` each other.
    ///
    /// Backs Python ``Statement.__eq__`` (after an idx-first short-circuit)
    /// and is used by rewriting passes that replace one statement with an
    /// SSA-equivalent one. For the structural-only variant that dedup /
    /// similarity passes want, see ``matches`` below.
    pub fn likes(&self, other: &AilStatement) -> bool {
        if self.kind() != other.kind() {
            return false;
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
            (StmtInner::Label { name: a }, StmtInner::Label { name: b }) => a == b,
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
            ) => a_ti == b_ti && a_t.likes(b_t),
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
                let opt_likes = |a: &Option<CFGTarget>, b: &Option<CFGTarget>| match (a, b) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x.likes(y),
                    _ => false,
                };
                opt_likes(a_t, b_t) && opt_likes(a_f, b_f)
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
                let opt_likes =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.likes(y),
                        _ => false,
                    };
                a_e.likes(b_e) && opt_likes(a_r, b_r) && opt_likes(a_f, b_f)
            }
            (StmtInner::Return { ret_exprs: a }, StmtInner::Return { ret_exprs: b }) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.likes(y))
            }
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
                let opt_likes =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
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
            (StmtInner::DirtyStatement { dirty: a }, StmtInner::DirtyStatement { dirty: b }) => {
                a.likes(b)
            }
            _ => false,
        }
    }

    /// Structural-only equality on statements. The statement-level
    /// counterpart of ``AilExpression::matches``: sub-expressions are
    /// compared via ``AilExpression::matches`` rather than ``likes``,
    /// so SSA ``varid`` differences are intentionally not observed.
    ///
    /// In master's Python AIL every statement class declares an explicit
    /// ``matches`` that mirrors ``likes`` but recurses through ``matches``
    /// on sub-expressions; we preserve that contract here. Plain
    /// Python-object slots (Jump targets, CC/SimType payloads, label
    /// names, dirty-statement payloads) keep their Python ``==`` (or
    /// structural ``.matches()`` for slots that wrap Expression).
    ///
    /// The deduplication / similarity passes
    /// (``block_similarity.is_similar``, ``DuplicationReverter``) call
    /// this to recognize that the same source-level statement compiled
    /// into two SSA branches should be treated as duplicates even
    /// though SSA renumbering gave their dst/src vvars different
    /// ``varid``s. Without this relaxation those passes never find
    /// merge candidates.
    pub fn matches(&self, other: &AilStatement) -> bool {
        if self.kind() != other.kind() {
            return false;
        }
        match (&self.inner, &other.inner) {
            (
                StmtInner::Assignment { dst: a_d, src: a_s },
                StmtInner::Assignment { dst: b_d, src: b_s },
            )
            | (
                StmtInner::WeakAssignment { dst: a_d, src: a_s },
                StmtInner::WeakAssignment { dst: b_d, src: b_s },
            ) => a_d.matches(b_d) && a_s.matches(b_s),
            (StmtInner::Label { name: a }, StmtInner::Label { name: b }) => a == b,
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
            ) => a_s == b_s && a_e == b_e && a_a.matches(b_a) && a_d.matches(b_d),
            (
                StmtInner::Jump {
                    target: a_t,
                    target_idx: a_ti,
                },
                StmtInner::Jump {
                    target: b_t,
                    target_idx: b_ti,
                },
            ) => a_ti == b_ti && a_t.matches(b_t),
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
                if !a_c.matches(b_c) {
                    return false;
                }
                let opt_matches = |a: &Option<CFGTarget>, b: &Option<CFGTarget>| match (a, b) {
                    (None, None) => true,
                    (Some(x), Some(y)) => x.matches(y),
                    _ => false,
                };
                opt_matches(a_t, b_t) && opt_matches(a_f, b_f)
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
                let opt_matches =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.matches(y),
                        _ => false,
                    };
                a_e.matches(b_e) && opt_matches(a_r, b_r) && opt_matches(a_f, b_f)
            }
            (StmtInner::Return { ret_exprs: a }, StmtInner::Return { ret_exprs: b }) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x.matches(y))
            }
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
                let opt_matches =
                    |a: &Option<Box<AilExpression>>, b: &Option<Box<AilExpression>>| match (a, b) {
                        (None, None) => true,
                        (Some(x), Some(y)) => x.matches(y),
                        _ => false,
                    };
                a_e == b_e
                    && a_a.matches(b_a)
                    && a_dl.matches(b_dl)
                    && opt_matches(a_dh, b_dh)
                    && a_el.matches(b_el)
                    && opt_matches(a_eh, b_eh)
                    && a_ol.matches(b_ol)
                    && opt_matches(a_oh, b_oh)
            }
            (StmtInner::DirtyStatement { dirty: a }, StmtInner::DirtyStatement { dirty: b }) => {
                a.matches(b)
            }
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Statement pyclass -- the only Python-facing class
// ---------------------------------------------------------------------------

#[pyclass(
    name = "Statement",
    module = "angr.rustylib.ailment",
    skip_from_py_object
)]
#[derive(Debug)]
pub struct Statement {
    pub stmt: AilStatement,
    /// Cached ``Py<int>``. See ``Expression::pykind``.
    pykind: Py<pyo3::types::PyAny>,
}

impl Clone for Statement {
    fn clone(&self) -> Self {
        Python::attach(|py| Self {
            stmt: self.stmt.clone(),
            pykind: self.pykind.clone_ref(py),
        })
    }
}

/// See ``ail_expr::EXPR_PYKINDS`` for rationale.
static STMT_PYKINDS: pyo3::sync::PyOnceLock<[Py<pyo3::types::PyAny>; 11]> =
    pyo3::sync::PyOnceLock::new();

fn stmt_pykind_for(py: Python<'_>, kind: StatementKind) -> Py<pyo3::types::PyAny> {
    use pyo3::IntoPyObjectExt;
    let arr = STMT_PYKINDS.get_or_init(py, || {
        std::array::from_fn(|i| {
            (i as u8)
                .into_py_any(py)
                .expect("u8 -> Py<int> cannot fail")
        })
    });
    arr[kind as usize].clone_ref(py)
}

impl Statement {
    pub fn wrap(stmt: AilStatement) -> Self {
        let pykind = Python::attach(|py| stmt_pykind_for(py, stmt.kind()));
        Self { stmt, pykind }
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
    fn _new_label(idx: i64, name: String, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
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
                target: CFGTarget::from_py(&target)?,
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
        let conv = |slot: Option<Bound<'_, PyAny>>| -> PyResult<Option<CFGTarget>> {
            match slot {
                Some(t) if !t.is_none() => Ok(Some(CFGTarget::from_py(&t)?)),
                _ => Ok(None),
            }
        };
        let tt = conv(true_target)?;
        let ft = conv(false_target)?;
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

    #[staticmethod]
    #[pyo3(signature = (idx, **kwargs))]
    fn _new_no_op(idx: i64, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        let tags = Tags::from_kwargs(kwargs)?;
        Ok(Self::wrap(AilStatement {
            header: StmtHeader::new(idx, tags),
            inner: StmtInner::NoOp,
        }))
    }

    // --- Universal header accessors -----------------------------------

    #[getter]
    fn idx(&self) -> i64 {
        self.stmt.header.idx
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
    fn kind(&self) -> StatementKind {
        self.stmt.kind()
    }

    /// String name of the variant, for repr/debug.
    #[getter]
    fn kind_name(&self) -> &'static str {
        self.stmt.kind_str()
    }

    /// Cached ``Py<int>`` form of the kind tag. Pre-materialized at
    /// construction; access is a single ``clone_ref``.
    #[getter]
    fn pykind(&self, py: Python<'_>) -> Py<pyo3::types::PyAny> {
        self.pykind.clone_ref(py)
    }

    fn clear_hash(&self) {
        self.stmt.header.cached_hash.clear();
    }

    // --- Per-variant accessors ----------------------------------------

    /// True iff this is an SSA phi assignment: an ``Assignment`` whose
    /// ``dst`` is a ``VirtualVariable`` and whose ``src`` is a ``Phi``.
    ///
    /// Cheap projection for the hot ``is_phi_assignment`` helpers in
    /// ``angr.utils.ail`` / ``angr.utils.ssa``: answers the question in
    /// one FFI call without materializing ``dst`` / ``src`` wrappers
    /// (each of which deep-clones its whole subtree).
    #[getter]
    fn is_phi_assignment(&self) -> bool {
        match &self.stmt.inner {
            StmtInner::Assignment { dst, src } => {
                matches!(
                    dst.inner,
                    crate::ailment::ail_expr::ExprInner::VirtualVariable { .. }
                ) && matches!(src.inner, crate::ailment::ail_expr::ExprInner::Phi { .. })
            }
            _ => false,
        }
    }

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
            StmtInner::Jump { target, .. } => target.to_py(py),
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
    fn true_target(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { true_target, .. } => match true_target {
                Some(t) => Ok(Some(t.to_py(py)?)),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err(
                "no 'true_target' on this Statement",
            )),
        }
    }

    /// ConditionalJump.false_target
    #[getter]
    fn false_target(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump { false_target, .. } => match false_target {
                Some(t) => Ok(Some(t.to_py(py)?)),
                None => Ok(None),
            },
            _ => Err(PyAttributeError::new_err(
                "no 'false_target' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_target(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let new_target = CFGTarget::from_py(&value)?;
        match &mut self.stmt.inner {
            StmtInner::Jump { target, .. } => {
                self.stmt.header.cached_hash.clear();
                *target = new_target;
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
                **condition = ail;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'condition' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_true_target(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let new_target = match value {
            Some(v) if !v.is_none() => Some(CFGTarget::from_py(&v)?),
            _ => None,
        };
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { true_target, .. } => {
                self.stmt.header.cached_hash.clear();
                *true_target = new_target;
                Ok(())
            }
            _ => Err(PyAttributeError::new_err(
                "no 'true_target' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_false_target(&mut self, value: Option<Bound<'_, PyAny>>) -> PyResult<()> {
        let new_target = match value {
            Some(v) if !v.is_none() => Some(CFGTarget::from_py(&v)?),
            _ => None,
        };
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump { false_target, .. } => {
                self.stmt.header.cached_hash.clear();
                *false_target = new_target;
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
            StmtInner::ConditionalJump {
                true_target_idx, ..
            } => Ok(*true_target_idx),
            _ => Err(PyAttributeError::new_err(
                "no 'true_target_idx' on this Statement",
            )),
        }
    }

    /// ConditionalJump.false_target_idx
    #[getter]
    fn false_target_idx(&self) -> PyResult<Option<i64>> {
        match &self.stmt.inner {
            StmtInner::ConditionalJump {
                false_target_idx, ..
            } => Ok(*false_target_idx),
            _ => Err(PyAttributeError::new_err(
                "no 'false_target_idx' on this Statement",
            )),
        }
    }

    #[setter]
    fn set_true_target_idx(&mut self, value: Option<i64>) -> PyResult<()> {
        match &mut self.stmt.inner {
            StmtInner::ConditionalJump {
                true_target_idx, ..
            } => {
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
            StmtInner::ConditionalJump {
                false_target_idx, ..
            } => {
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

    #[setter]
    fn set_expr(&mut self, value: Bound<'_, PyAny>) -> PyResult<()> {
        let ail = extract_ail_expr(&value)?;
        match &mut self.stmt.inner {
            StmtInner::SideEffectStatement { expr, .. } => {
                self.stmt.header.cached_hash.clear();
                **expr = ail;
                Ok(())
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
                **dst = ail;
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
                **src = ail;
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
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                Ok(dst.header.depth.max(src.header.depth) + 1)
            }
            StmtInner::Store { addr, data, .. } => Ok(addr.header.depth.max(data.header.depth) + 1),
            StmtInner::ConditionalJump { condition, .. } => Ok(condition.header.depth + 1),
            StmtInner::SideEffectStatement { expr, .. } => Ok(expr.header.depth + 1),
            StmtInner::Return { ret_exprs } => {
                Ok(ret_exprs.iter().map(|e| e.header.depth).max().unwrap_or(0) + 1)
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
            StmtInner::Jump { target, .. } => {
                let _ = py;
                Ok(match target {
                    CFGTarget::Expr(e) => e.header.depth + 1,
                    CFGTarget::Symbol(_) => 1,
                })
            }
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

    /// Structural-with-identity equality. See ``AilStatement::likes``
    /// for the full contract. Backs Python ``Statement.__eq__`` after
    /// the idx-first short-circuit and is used by rewriting passes
    /// that swap a statement for an SSA-equivalent one; in particular,
    /// two statements that operate on the same source-level register
    /// through different SSA ``varid``s will *not* ``likes`` each other.
    fn likes(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Statement>() else {
            return Ok(false);
        };
        Ok(self.stmt.likes(&o.borrow().stmt))
    }

    /// Structural-only equality. See ``AilStatement::matches`` for the
    /// full contract. In one line: ``matches`` is ``likes`` with SSA
    /// identifying info on sub-expressions stripped, so two statements
    /// that compile from the same source but landed in different SSA
    /// numberings compare equal. Primary callers are dedup / similarity
    /// passes; not used by Python ``__eq__``.
    fn matches(&self, other: &Bound<'_, PyAny>) -> PyResult<bool> {
        let Ok(o) = other.cast::<Statement>() else {
            return Ok(false);
        };
        Ok(self.stmt.matches(&o.borrow().stmt))
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

    fn __deepcopy__<'py>(slf: Bound<'py, Self>, memo: Bound<'py, PyAny>) -> PyResult<Py<PyAny>> {
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
            .getattr("reconstruct_statement")?;
        let args = pyo3::types::PyTuple::new(py, [bytes.into_any()])?;
        let tup =
            pyo3::types::PyTuple::new(py, [helper.unbind().into_any(), args.into_any().unbind()])?;
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
                addr,
                data,
                size,
                endness,
                guard,
                ..
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
                let s = match target {
                    CFGTarget::Expr(e) => Expression::wrap((**e).clone()).render(py)?,
                    CFGTarget::Symbol(name) => name.clone(),
                };
                Ok(format!("Goto({})", s))
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                let c = Expression::wrap((**condition).clone()).render(py)?;
                let render = |opt: &Option<CFGTarget>| -> PyResult<String> {
                    Ok(match opt {
                        Some(CFGTarget::Expr(e)) => Expression::wrap((**e).clone()).render(py)?,
                        Some(CFGTarget::Symbol(s)) => s.clone(),
                        None => "None".into(),
                    })
                };
                let t = render(true_target)?;
                let f = render(false_target)?;
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
            StmtInner::NoOp => Ok("NoOp".to_string()),
        }
    }

    // --- Byte serialization --------------------------------------------

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

/// Extract an [`AilExpression`] from a Python object that must be an
/// ``Expression`` instance.
fn extract_ail_expr(obj: &Bound<'_, PyAny>) -> PyResult<AilExpression> {
    let e: PyRef<'_, Expression> = obj
        .cast::<Expression>()
        .map_err(|_| PyTypeError::new_err("expected an Expression"))?
        .borrow();
    Ok(e.expr.clone())
}

/// Extract an [`AilStatement`] from a Python object that must be a
/// ``Statement`` instance. Used by stmt-bearing expressions
/// (e.g. MultiStatementExpression).
pub fn extract_ail_stmt(obj: &Bound<'_, PyAny>) -> PyResult<AilStatement> {
    let s: PyRef<'_, Statement> = obj
        .cast::<Statement>()
        .map_err(|_| PyTypeError::new_err("expected a Statement"))?
        .borrow();
    Ok(s.stmt.clone())
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

mod serialize {
    use super::{AilStatement, CFGTarget, StmtHeader, StmtInner};
    use crate::ailment::ail_expr::serialize as expr_serialize;
    use crate::ailment::tags::Tags;
    use serde::{Deserialize, Serialize};

    /// Bridge a runtime ``CFGTarget`` to the wire-format ``PolyValue``
    /// already used for serialization. Symbol → ``PolyValue::Str``;
    /// Expr → ``PolyValue::Expr(Wire)``. Keeps the on-disk format
    /// unchanged so older cached blobs deserialize.
    fn cfgtarget_to_poly(t: &CFGTarget) -> expr_serialize::PolyValue {
        match t {
            CFGTarget::Expr(e) => {
                expr_serialize::PolyValue::Expr(Box::new(expr_serialize::Wire::from(e.as_ref())))
            }
            CFGTarget::Symbol(s) => expr_serialize::PolyValue::Str(s.clone()),
        }
    }

    /// Reverse of ``cfgtarget_to_poly``: read a ``PolyValue`` from the
    /// wire format and project into ``CFGTarget``. Any other ``PolyValue``
    /// shape (legacy ``Int`` for raw addresses, ``Pickle`` for opaque
    /// payloads, ...) is rendered as a ``Symbol`` carrying the value's
    /// debug string -- this keeps deserialization total but the
    /// resulting target won't ``likes`` an Expression peer, which is
    /// acceptable for the legacy unresolved-target case.
    fn poly_to_cfgtarget(pv: expr_serialize::PolyValue) -> CFGTarget {
        match pv {
            expr_serialize::PolyValue::Expr(wire) => CFGTarget::Expr(Box::new(wire.into_ail())),
            expr_serialize::PolyValue::Str(s) => CFGTarget::Symbol(s),
            expr_serialize::PolyValue::Int(i) => CFGTarget::Symbol(format!("{}", i)),
            expr_serialize::PolyValue::BigInt(s) => CFGTarget::Symbol(format!("0x{}", s)),
            _ => CFGTarget::Symbol("<unsupported jump target>".to_string()),
        }
    }

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
        // The ``Wire`` payloads are boxed to keep this variant's inline size
        // close to the other variants' (clippy::large_enum_variant); postcard
        // encodes ``Box<T>`` / ``Option<Box<T>>`` identically to ``T`` /
        // ``Option<T>``, so the wire format is unaffected.
        CAS {
            h: Hdr,
            addr: Box<expr_serialize::Wire>,
            data_lo: Box<expr_serialize::Wire>,
            data_hi: Option<Box<expr_serialize::Wire>>,
            expd_lo: Box<expr_serialize::Wire>,
            expd_hi: Option<Box<expr_serialize::Wire>>,
            old_lo: Box<expr_serialize::Wire>,
            old_hi: Option<Box<expr_serialize::Wire>>,
            endness: String,
        },
        DirtyStatement {
            h: Hdr,
            dirty: expr_serialize::Wire,
        },
        NoOp {
            h: Hdr,
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
                    target: cfgtarget_to_poly(target),
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
                    true_target: true_target.as_ref().map(cfgtarget_to_poly),
                    false_target: false_target.as_ref().map(cfgtarget_to_poly),
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
                    addr: Box::new(expr_serialize::Wire::from(addr)),
                    data_lo: Box::new(expr_serialize::Wire::from(data_lo)),
                    data_hi: data_hi
                        .as_ref()
                        .map(|e| Box::new(expr_serialize::Wire::from(e))),
                    expd_lo: Box::new(expr_serialize::Wire::from(expd_lo)),
                    expd_hi: expd_hi
                        .as_ref()
                        .map(|e| Box::new(expr_serialize::Wire::from(e))),
                    old_lo: Box::new(expr_serialize::Wire::from(old_lo)),
                    old_hi: old_hi
                        .as_ref()
                        .map(|e| Box::new(expr_serialize::Wire::from(e))),
                    endness: endness.clone(),
                },
                StmtInner::DirtyStatement { dirty } => StmtWire::DirtyStatement {
                    h,
                    dirty: expr_serialize::Wire::from(dirty),
                },
                StmtInner::NoOp => StmtWire::NoOp { h },
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
                } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::Jump {
                        target: poly_to_cfgtarget(target),
                        target_idx,
                    },
                },
                StmtWire::ConditionalJump {
                    h,
                    condition,
                    true_target,
                    false_target,
                    true_target_idx,
                    false_target_idx,
                } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::ConditionalJump {
                        condition: Box::new(condition.into_ail()),
                        true_target: true_target.map(poly_to_cfgtarget),
                        false_target: false_target.map(poly_to_cfgtarget),
                        true_target_idx,
                        false_target_idx,
                    },
                },
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
                StmtWire::NoOp { h } => AilStatement {
                    header: rebuild_header(h),
                    inner: StmtInner::NoOp,
                },
            }
        }
    }
}

// Re-export for parent module
pub use serialize::StmtWire;
