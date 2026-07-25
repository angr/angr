//! Native replacements for the *pure-predicate* [`AILBlockViewer`] subclasses.
//!
//! Four walkers in the decompiler hot path exist only to answer a yes/no
//! question about an AIL subtree, with no Python callback anywhere in the
//! walk:
//!
//! | walker                        | question |
//! |-------------------------------|----------|
//! | `AILWhitelistExprTypeWalker`  | is every expression kind in a whitelist? |
//! | `AILBlacklistExprTypeWalker`  | does any expression kind appear from a blacklist? |
//! | `HasCallExprWalker`           | is there a `Call` / `FunctionLikeMacro` / `SideEffectStatement`? |
//! | `AILReferenceFinder`          | is there a `Reference(VirtualVariable(varid))`? |
//!
//! Because the Python marker classes dispatch `isinstance` purely on the
//! variant tag (`_AilMarkerMeta.__instancecheck__` compares `pykind` against a
//! precomputed int set), each "is this expression one of these types?" test is
//! *exactly* a bitmask test on the kind. So these walks can run entirely
//! natively over the fat enum and return a single `bool`.
//!
//! The traversal mirrors [`AILBlockViewer`] node for node -- in particular it
//! does **not** descend into `Load.guard` / `Load.alt`,
//! `DirtyExpression.maddr`, `SideEffectStatement.ret_expr` /
//! `fp_ret_expr`, or into `Let` / `Macro` / `BasePointerOffset` /
//! `StackBaseOffset` / `Label` / `NoOp`, because the viewer registers no
//! handler for those positions.
//!
//! Every entry point returns `None` when it meets a node that is not a native
//! AIL object, in which case the caller falls back to the Python walker. The
//! predicates are all monotone, so the native versions short-circuit as soon
//! as the answer is known; the Python walkers do not always do that, but since
//! only the final boolean is observable the results are identical.

use pyo3::prelude::*;
use pyo3::types::{PyList, PySet};

use crate::ailment::ail_expr::{AilExpression, CFGTarget, ExprInner, Expression};
use crate::ailment::ail_stmt::{AilStatement, Statement, StmtInner};
use crate::ailment::block::Block;
use crate::ailment::enums::{ExpressionKind, StatementKind};
use crate::ailment::tags::{TagExtra, TagKey};

#[inline]
fn ebit(kind: ExpressionKind) -> u32 {
    1u32 << (kind as u8)
}

/// Which predicate the shared traversal is evaluating.
enum Query {
    /// `AILWhitelistExprTypeWalker.has_nonwhitelisted_exprs`: an expression
    /// whose kind is *not* in `mask` was reached. A non-whitelisted node is
    /// not descended into (its subtree cannot change the answer).
    NonWhitelisted { mask: u32 },
    /// `AILBlacklistExprTypeWalker.has_blacklisted_exprs` with
    /// `skip_if_contains_vvar=None`: an expression whose kind is in `mask`
    /// was reached.
    Blacklisted { mask: u32 },
    /// `AILBlacklistExprTypeWalker.has_blacklisted_exprs` with
    /// `skip_if_contains_vvar=Some(varid)`: a blacklisted expression was
    /// reached whose subtree does *not* mention `varid`.
    BlacklistedSkipVvar { mask: u32, varid: i64 },
    /// `HasCallExprWalker`: a `Call` / `FunctionLikeMacro` expression or a
    /// `SideEffectStatement` was reached.
    HasCall,
    /// `AILReferenceFinder.has_references_to_vvar`.
    RefToVvar { varid: i64 },
}

struct Pred {
    query: Query,
    /// The answer, once known. All four predicates are monotone `false ->
    /// true`, so this doubles as the short-circuit flag.
    result: bool,
    /// `AILBlacklistExprTypeWalker._has_specified_vvar`.
    saw_vvar: bool,
}

impl Pred {
    fn new(query: Query) -> Self {
        Self {
            query,
            result: false,
            saw_vvar: false,
        }
    }

    /// One expression node: the per-node predicate test, then the descent the
    /// viewer would do. Returns early once `result` is set.
    fn expr(&mut self, e: &AilExpression) {
        if self.result {
            return;
        }
        let kind = e.kind();
        match self.query {
            Query::NonWhitelisted { mask } => {
                if mask & ebit(kind) == 0 {
                    // Not whitelisted: flag it and do not descend, exactly as
                    // ``AILWhitelistExprTypeWalker._handle_expr`` does.
                    self.result = true;
                    return;
                }
            }
            Query::Blacklisted { mask } => {
                if mask & ebit(kind) != 0 {
                    self.result = true;
                    return;
                }
            }
            Query::BlacklistedSkipVvar { mask, .. } => {
                if mask & ebit(kind) != 0 {
                    // ``_handle_expr``'s "more complicated check": reset the
                    // vvar flag, walk the blacklisted subtree, and only count
                    // the match if the subtree never mentioned the vvar.
                    self.saw_vvar = false;
                    self.descend_expr(e);
                    if self.result {
                        return;
                    }
                    if !self.saw_vvar {
                        self.result = true;
                    } else {
                        self.saw_vvar = false;
                    }
                    return;
                }
                if let ExprInner::VirtualVariable { varid, .. } = &e.inner {
                    if let Query::BlacklistedSkipVvar { varid: want, .. } = self.query {
                        if *varid == want {
                            self.saw_vvar = true;
                        }
                    }
                }
            }
            Query::HasCall => {
                if matches!(kind, ExpressionKind::Call | ExpressionKind::FunctionLikeMacro) {
                    self.result = true;
                    return;
                }
            }
            Query::RefToVvar { varid } => {
                if let ExprInner::UnaryOp { op, operand, .. } = &e.inner {
                    if op == "Reference" {
                        if let ExprInner::VirtualVariable { varid: v, .. } = &operand.inner {
                            if *v == varid {
                                self.result = true;
                                return;
                            }
                        }
                    }
                }
            }
        }
        self.descend_expr(e);
    }

    /// The child positions [`AILBlockViewer`] recurses into, and only those.
    fn descend_expr(&mut self, e: &AilExpression) {
        match &e.inner {
            // Leaves, plus the four kinds the viewer registers no handler for
            // (``Let``, ``Macro``, ``BasePointerOffset``, ``StackBaseOffset``)
            // and therefore never descends into.
            ExprInner::Const { .. }
            | ExprInner::Tmp { .. }
            | ExprInner::Register { .. }
            | ExprInner::VirtualVariable { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::Macro { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. }
            | ExprInner::Let { .. } => {}
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => self.expr(operand),
            ExprInner::BinaryOp { operands, .. } => {
                self.expr(&operands[0]);
                self.expr(&operands[1]);
            }
            // The viewer's ``_handle_Load`` descends into ``addr`` only.
            ExprInner::Load { addr, .. } => self.expr(addr),
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t);
                }
                for a in args.iter().flatten() {
                    self.expr(a);
                }
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.expr(cond);
                self.expr(iftrue);
                self.expr(iffalse);
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(v) = entry.vvar.as_deref() {
                        self.expr(v);
                    }
                }
            }
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.expr(r);
                }
            }
            ExprInner::MultiStatementExpression { stmts, expr } => {
                for s in stmts {
                    self.stmt(s);
                }
                self.expr(expr);
            }
            // ``_handle_DirtyExpression`` descends into operands + guard, but
            // not ``maddr``.
            ExprInner::DirtyExpression {
                operands, guard, ..
            } => {
                for o in operands {
                    self.expr(o);
                }
                if let Some(g) = guard.as_deref() {
                    self.expr(g);
                }
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.expr(o);
                }
            }
            ExprInner::Extract { base, offset, .. } => {
                self.expr(base);
                self.expr(offset);
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.expr(base);
                self.expr(offset);
                self.expr(value);
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.expr(f);
                }
            }
            ExprInner::Struct { fields, .. } => {
                for f in fields.values() {
                    self.expr(f);
                }
            }
            ExprInner::Array { elements } => {
                for x in elements {
                    self.expr(x);
                }
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                for a in args.iter().flatten() {
                    self.expr(a);
                }
            }
        }
    }

    fn stmt(&mut self, s: &AilStatement) {
        if self.result {
            return;
        }
        if matches!(self.query, Query::HasCall)
            && s.kind() == StatementKind::SideEffectStatement
        {
            // ``HasCallExprWalker._handle_SideEffectStatement`` raises before
            // descending.
            self.result = true;
            return;
        }
        let t = |p: &mut Self, x: &CFGTarget| {
            if let CFGTarget::Expr(x) = x {
                p.expr(x);
            }
        };
        match &s.inner {
            // No handler registered -> ``_stmt_top`` -> no descent.
            StmtInner::Label { .. } | StmtInner::NoOp => {}
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                self.expr(dst);
                self.expr(src);
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.expr(addr);
                self.expr(data);
                if let Some(g) = guard {
                    self.expr(g);
                }
            }
            StmtInner::Jump { target, .. } => t(self, target),
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.expr(condition);
                if let Some(x) = true_target {
                    t(self, x);
                }
                if let Some(x) = false_target {
                    t(self, x);
                }
            }
            // The viewer descends into ``expr`` only.
            StmtInner::SideEffectStatement { expr, .. } => self.expr(expr),
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.expr(e);
                }
            }
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
                self.expr(addr);
                self.expr(data_lo);
                if let Some(e) = data_hi {
                    self.expr(e);
                }
                self.expr(expd_lo);
                if let Some(e) = expd_hi {
                    self.expr(e);
                }
                self.expr(old_lo);
                if let Some(e) = old_hi {
                    self.expr(e);
                }
            }
            StmtInner::DirtyStatement { dirty } => self.expr(dirty),
        }
    }
}

/// Run `query` over `node`, which may be an `Expression`, a `Statement` or a
/// `Block`. `None` means "not a native AIL object" -- fall back to Python.
fn run(node: &Bound<'_, PyAny>, query: Query) -> PyResult<Option<bool>> {
    let mut p = Pred::new(query);
    if let Ok(cell) = node.cast::<Expression>() {
        p.expr(&cell.borrow().expr);
        return Ok(Some(p.result));
    }
    if let Ok(cell) = node.cast::<Statement>() {
        p.stmt(&cell.borrow().stmt);
        return Ok(Some(p.result));
    }
    if let Ok(cell) = node.cast::<Block>() {
        let stmts: Bound<'_, PyList> = cell.borrow().statements.bind(node.py()).clone();
        for obj in stmts.iter() {
            let Ok(cell) = obj.cast::<Statement>() else {
                return Ok(None);
            };
            p.stmt(&cell.borrow().stmt);
            if p.result {
                break;
            }
        }
        return Ok(Some(p.result));
    }
    Ok(None)
}

/// ``AILWhitelistExprTypeWalker(whitelist).walk*(node).has_nonwhitelisted_exprs``.
///
/// `mask` has bit `n` set for each whitelisted `ExpressionKind` value `n`.
#[pyfunction]
pub fn has_nonwhitelisted_exprs(node: &Bound<'_, PyAny>, mask: u32) -> PyResult<Option<bool>> {
    run(node, Query::NonWhitelisted { mask })
}

/// ``AILBlacklistExprTypeWalker(blacklist, skip_if_contains_vvar).walk*(node)
/// .has_blacklisted_exprs``.
#[pyfunction]
#[pyo3(signature = (node, mask, skip_if_contains_vvar=None))]
pub fn has_blacklisted_exprs(
    node: &Bound<'_, PyAny>,
    mask: u32,
    skip_if_contains_vvar: Option<i64>,
) -> PyResult<Option<bool>> {
    match skip_if_contains_vvar {
        None => run(node, Query::Blacklisted { mask }),
        Some(varid) => run(node, Query::BlacklistedSkipVvar { mask, varid }),
    }
}

/// ``HasCallExprWalker``: does the subtree contain a `Call` or
/// `FunctionLikeMacro` expression, or a `SideEffectStatement`?
#[pyfunction]
pub fn has_call_expr(node: &Bound<'_, PyAny>) -> PyResult<Option<bool>> {
    run(node, Query::HasCall)
}

/// ``AILReferenceFinder(varid).walk*(node).has_references_to_vvar``.
#[pyfunction]
pub fn has_reference_to_vvar(node: &Bound<'_, PyAny>, varid: i64) -> PyResult<Option<bool>> {
    run(node, Query::RefToVvar { varid })
}

// ---------------------------------------------------------------------------
// VVarUsesCollector, block-less form
// ---------------------------------------------------------------------------

/// ``VVarUsesCollector`` restricted to its ``vvars`` output.
///
/// ``SLivenessAnalysis`` drives the collector over one statement at a time with
/// no block context, so ``vvar_and_uselocs`` is never populated and only the
/// varid set is read. Collecting just that set needs no Python object per node.
struct VvarUses {
    out: Vec<i64>,
    walking_assignment_dst: bool,
    assignment_dst_varid: Option<i64>,
    assignment_src_is_phi: bool,
}

impl VvarUses {
    fn expr(&mut self, e: &AilExpression) {
        // ``_handle_expr``: ``extra_def`` expressions are defs, not uses.
        if is_extra_def(e) {
            return;
        }
        if let ExprInner::VirtualVariable { varid, .. } = &e.inner {
            if self.walking_assignment_dst {
                return;
            }
            if self.assignment_src_is_phi && self.assignment_dst_varid == Some(*varid) {
                // avoid phi loops
                return;
            }
            self.out.push(*varid);
            return;
        }
        self.descend(e);
    }

    fn descend(&mut self, e: &AilExpression) {
        match &e.inner {
            ExprInner::Const { .. }
            | ExprInner::Tmp { .. }
            | ExprInner::Register { .. }
            | ExprInner::VirtualVariable { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::Macro { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. }
            | ExprInner::Let { .. } => {}
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => self.expr(operand),
            ExprInner::BinaryOp { operands, .. } => {
                self.expr(&operands[0]);
                self.expr(&operands[1]);
            }
            ExprInner::Load { addr, .. } => self.expr(addr),
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t);
                }
                for a in args.iter().flatten() {
                    self.expr(a);
                }
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.expr(cond);
                self.expr(iftrue);
                self.expr(iffalse);
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(v) = entry.vvar.as_deref() {
                        self.expr(v);
                    }
                }
            }
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.expr(r);
                }
            }
            ExprInner::MultiStatementExpression { stmts, expr } => {
                for s in stmts {
                    self.stmt(s);
                }
                self.expr(expr);
            }
            ExprInner::DirtyExpression {
                operands, guard, ..
            } => {
                for o in operands {
                    self.expr(o);
                }
                if let Some(g) = guard.as_deref() {
                    self.expr(g);
                }
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.expr(o);
                }
            }
            ExprInner::Extract { base, offset, .. } => {
                self.expr(base);
                self.expr(offset);
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.expr(base);
                self.expr(offset);
                self.expr(value);
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.expr(f);
                }
            }
            ExprInner::Struct { fields, .. } => {
                for f in fields.values() {
                    self.expr(f);
                }
            }
            ExprInner::Array { elements } => {
                for x in elements {
                    self.expr(x);
                }
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                for a in args.iter().flatten() {
                    self.expr(a);
                }
            }
        }
    }

    fn stmt(&mut self, s: &AilStatement) {
        let t = |p: &mut Self, x: &CFGTarget| {
            if let CFGTarget::Expr(x) = x {
                p.expr(x);
            }
        };
        match &s.inner {
            StmtInner::Label { .. } | StmtInner::NoOp => {}
            StmtInner::Assignment { dst, src } => {
                // ``_handle_Assignment``: the dst subtree is a def; save and
                // restore the outer context because MultiStatementExpression
                // can nest assignments inside ``src``.
                let prev = (
                    self.walking_assignment_dst,
                    self.assignment_dst_varid,
                    self.assignment_src_is_phi,
                );
                self.assignment_dst_varid = match &dst.inner {
                    ExprInner::VirtualVariable { varid, .. } => Some(*varid),
                    _ => None,
                };
                self.assignment_src_is_phi = matches!(src.inner, ExprInner::Phi { .. });
                self.walking_assignment_dst = true;
                self.expr(dst);
                self.walking_assignment_dst = false;
                self.expr(src);
                self.walking_assignment_dst = prev.0;
                self.assignment_dst_varid = prev.1;
                self.assignment_src_is_phi = prev.2;
            }
            StmtInner::WeakAssignment { dst, src } => {
                self.expr(dst);
                self.expr(src);
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.expr(addr);
                self.expr(data);
                if let Some(g) = guard {
                    self.expr(g);
                }
            }
            StmtInner::Jump { target, .. } => t(self, target),
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.expr(condition);
                if let Some(x) = true_target {
                    t(self, x);
                }
                if let Some(x) = false_target {
                    t(self, x);
                }
            }
            StmtInner::SideEffectStatement { expr, .. } => self.expr(expr),
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.expr(e);
                }
            }
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
                self.expr(addr);
                self.expr(data_lo);
                if let Some(e) = data_hi {
                    self.expr(e);
                }
                self.expr(expd_lo);
                if let Some(e) = expd_hi {
                    self.expr(e);
                }
                self.expr(old_lo);
                if let Some(e) = old_hi {
                    self.expr(e);
                }
            }
            StmtInner::DirtyStatement { dirty } => self.expr(dirty),
        }
    }
}

/// ``expr.tags.get("extra_def", False)`` -- truthiness, not presence.
#[inline]
fn is_extra_def(e: &AilExpression) -> bool {
    let tags = &e.header.tags;
    if tags.extras.is_empty() {
        return false;
    }
    match tags.extras.get(&TagKey::ExtraDef) {
        None => false,
        Some(TagExtra::Bool(b)) => *b,
        Some(TagExtra::Int(i)) => *i != 0,
        Some(_) => true,
    }
}

/// ``c = VVarUsesCollector(); c.walk_statement(stmt); return c.vvars`` -- the
/// varids only, which is all the caller (``SLivenessAnalysis``) reads when it
/// walks statements without block context.
#[pyfunction]
pub fn stmt_vvar_use_ids(node: &Bound<'_, PyAny>) -> PyResult<Option<Py<PySet>>> {
    let Ok(cell) = node.cast::<Statement>() else {
        return Ok(None);
    };
    let mut c = VvarUses {
        out: Vec::new(),
        walking_assignment_dst: false,
        assignment_dst_varid: None,
        assignment_src_is_phi: false,
    };
    c.stmt(&cell.borrow().stmt);
    let set = PySet::empty(node.py())?;
    for v in c.out {
        set.add(v)?;
    }
    Ok(Some(set.unbind()))
}
