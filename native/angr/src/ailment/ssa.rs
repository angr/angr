//! Per-block SSA def/use lists.
//!
//! Each [`Block`] memoizes the vvar/tmp definitions and uses of its statements (`BlockDefUse`), as finished
//! Python objects. `Block.statements` is a [`StatementList`], which takes a new version on every mutation, and
//! statements are immutable from Python, so the memo is valid for as long as the list keeps the version it was
//! scanned at: a read checks one integer.
//!
//! `collect_uses_defs` merges the per-block lists of a block sequence into the caller's containers with exactly
//! the insertion order and overwrite semantics of the original whole-graph scan in `angr.utils.ssa`.

use std::sync::Arc;

use pyo3::exceptions::{PyAssertionError, PyTypeError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyList, PySet, PyTuple};

use crate::ailment::ail_expr::{
    AilExpression, CFGTarget, ExprHeader, ExprInner, Expression, OIdent,
};
use crate::ailment::ail_stmt::{AilStatement, Statement, StmtInner};
use crate::ailment::block::Block;
use crate::ailment::enums::VirtualVariableCategory;
use crate::ailment::stmt_list::StatementList;
use crate::ailment::tags::{TagExtra, TagKey, Tags};

fn py_class<'py>(
    py: Python<'py>,
    cell: &'static PyOnceLock<Py<PyAny>>,
    module: &str,
    name: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let cls = cell.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        Ok(py.import(module)?.getattr(name)?.unbind())
    })?;
    Ok(cls.bind(py).clone())
}

fn ail_code_location(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    static CLS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    py_class(py, &CLS, "angr.code_location", "AILCodeLocation")
}

fn tmp_atom(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    static CLS: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
    py_class(
        py,
        &CLS,
        "angr.knowledge_plugins.key_definitions.atoms",
        "Tmp",
    )
}

fn tag_extra<'a>(tags: &'a Tags, key: &TagKey) -> Option<&'a TagExtra> {
    tags.extras.as_ref().and_then(|m| m.get(key))
}

/// Python truthiness of ``tags.get(key, False)``.
fn tag_truthy(py: Python<'_>, tags: &Tags, key: &TagKey) -> bool {
    match tag_extra(tags, key) {
        None => false,
        Some(TagExtra::Bool(b)) => *b,
        Some(TagExtra::Int(i)) => *i != 0,
        Some(TagExtra::Float(f)) => *f != 0.0,
        Some(TagExtra::Str(s)) => !s.is_empty(),
        Some(TagExtra::IntList(v)) => !v.is_empty(),
        Some(TagExtra::StrList(v)) => !v.is_empty(),
        Some(TagExtra::Opaque(o)) => o.bind(py).is_truthy().unwrap_or(false),
    }
}

/// An int-list tag (``extra_defs`` / ``clobber_defs``); ``None`` when absent or falsy.
fn tag_int_list(py: Python<'_>, tags: &Tags, key: &TagKey) -> PyResult<Option<Vec<i64>>> {
    Ok(match tag_extra(tags, key) {
        Some(TagExtra::IntList(v)) if !v.is_empty() => Some(v.clone()),
        Some(TagExtra::Opaque(o)) => {
            let o = o.bind(py);
            if o.is_truthy()? {
                Some(o.extract::<Vec<i64>>()?)
            } else {
                None
            }
        }
        _ => None,
    })
}

fn varid_of(expr: &AilExpression) -> Option<i64> {
    match &expr.inner {
        ExprInner::VirtualVariable { varid, .. } => Some(*varid),
        _ => None,
    }
}

/// ``VirtualVariable(None, varid, bits, REGISTER, oident=reg_offset)`` -- see ``angr.utils.ssa.clobber_def_vvars``.
fn clobber_vvar(varid: i64, reg_offset: i64, bits: i64) -> AilExpression {
    AilExpression {
        header: ExprHeader::new(0, 0, bits as u32, Tags::default()),
        inner: ExprInner::VirtualVariable {
            varid,
            category: VirtualVariableCategory::Register,
            oident: OIdent::Int(reg_offset),
            reg_vvars: None,
        },
    }
}

// ---------------------------------------------------------------------------
// Raw scan (pure Rust walk; mirrors the AILBlockViewer traversal order)
// ---------------------------------------------------------------------------

struct VVarSite {
    varid: i64,
    stmt_idx: usize,
    expr: AilExpression,
}

struct TmpSite {
    tmp_idx: i64,
    bits: u32,
    stmt_idx: usize,
    expr: AilExpression,
}

#[derive(Default)]
struct Raw {
    vvar_defs: Vec<VVarSite>,
    phis: Vec<(i64, Vec<Option<i64>>)>,
    /// varids every ``extra_defs`` statement tag declares (checked against the merged defs by the caller)
    extra_declared: Vec<i64>,
    vvar_uses: Vec<VVarSite>,
    tmp_defs: Vec<(i64, u32, usize)>,
    tmp_uses: Vec<TmpSite>,
}

/// Port of ``VVarAndTmpUsesCollector``: explicit vvar uses (skipped inside nested ``MultiStatementExpression``
/// statements, where the Python walker has no block) and tmp uses.
struct Uses<'py> {
    py: Python<'py>,
    vvar_uses: Vec<VVarSite>,
    tmp_uses: Vec<TmpSite>,
    phi_dst_varid: Option<i64>,
}

impl Uses<'_> {
    fn stmt(&mut self, stmt_idx: usize, stmt: &AilStatement, in_block: bool) {
        match &stmt.inner {
            StmtInner::Assignment { dst, src } => {
                let prev = self.phi_dst_varid;
                self.phi_dst_varid = match (varid_of(dst), &src.inner) {
                    (Some(v), ExprInner::Phi { .. }) => Some(v),
                    _ => None,
                };
                self.expr(src, stmt_idx, in_block);
                self.phi_dst_varid = prev;
            }
            StmtInner::WeakAssignment { dst, src } => {
                self.expr(dst, stmt_idx, in_block);
                self.expr(src, stmt_idx, in_block);
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
                self.expr(addr, stmt_idx, in_block);
                self.expr(data_lo, stmt_idx, in_block);
                if let Some(e) = data_hi {
                    self.expr(e, stmt_idx, in_block);
                }
                self.expr(expd_lo, stmt_idx, in_block);
                if let Some(e) = expd_hi {
                    self.expr(e, stmt_idx, in_block);
                }
                self.expr(old_lo, stmt_idx, in_block);
                if let Some(e) = old_hi {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::SideEffectStatement { expr, .. } => self.expr(expr, stmt_idx, in_block),
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.expr(addr, stmt_idx, in_block);
                self.expr(data, stmt_idx, in_block);
                if let Some(e) = guard {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::Jump { target, .. } => {
                if let CFGTarget::Expr(e) = target {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.expr(condition, stmt_idx, in_block);
                if let Some(CFGTarget::Expr(e)) = true_target {
                    self.expr(e, stmt_idx, in_block);
                }
                if let Some(CFGTarget::Expr(e)) = false_target {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::DirtyStatement { dirty } => self.expr(dirty, stmt_idx, in_block),
            StmtInner::Label { .. }
            | StmtInner::NoOp
            | StmtInner::IncompleteSwitchCaseHeadStatement { .. } => {}
        }
    }

    fn expr(&mut self, e: &AilExpression, stmt_idx: usize, in_block: bool) {
        if tag_truthy(self.py, &e.header.tags, &TagKey::ExtraDef) {
            return;
        }
        match &e.inner {
            ExprInner::VirtualVariable { varid, .. } => {
                if Some(*varid) == self.phi_dst_varid {
                    return;
                }
                if in_block {
                    self.vvar_uses.push(VVarSite {
                        varid: *varid,
                        stmt_idx,
                        expr: e.clone(),
                    });
                }
            }
            ExprInner::Tmp { tmp_idx } => {
                self.tmp_uses.push(TmpSite {
                    tmp_idx: *tmp_idx,
                    bits: e.header.bits,
                    stmt_idx,
                    expr: e.clone(),
                });
            }
            ExprInner::Const { .. }
            | ExprInner::Register { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. }
            | ExprInner::Macro { .. }
            | ExprInner::Let { .. } => {}
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.expr(r, stmt_idx, in_block);
                }
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(v) = &entry.vvar {
                        self.expr(v, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => self.expr(operand, stmt_idx, in_block),
            ExprInner::BinaryOp { operands, .. } => {
                self.expr(&operands[0], stmt_idx, in_block);
                self.expr(&operands[1], stmt_idx, in_block);
            }
            ExprInner::Load { addr, .. } => self.expr(addr, stmt_idx, in_block),
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t, stmt_idx, in_block);
                }
                if let Some(args) = args {
                    for a in args {
                        self.expr(a, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::DirtyExpression(d) => {
                for o in &d.operands {
                    self.expr(o, stmt_idx, in_block);
                }
                if let Some(g) = &d.guard {
                    self.expr(g, stmt_idx, in_block);
                }
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.expr(o, stmt_idx, in_block);
                }
            }
            ExprInner::MultiStatementExpression { stmts, expr } => {
                // nested statements are walked without a block: their vvar uses are not recorded and their tmp
                // uses carry the nested statement index
                for (i, s) in stmts.iter().enumerate() {
                    self.stmt(i, s, false);
                }
                self.expr(expr, stmt_idx, in_block);
            }
            ExprInner::Struct(s) => {
                for f in s.fields.values() {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::Array { elements } => {
                for f in elements {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                if let Some(args) = args {
                    for a in args {
                        self.expr(a, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.expr(cond, stmt_idx, in_block);
                self.expr(iftrue, stmt_idx, in_block);
                self.expr(iffalse, stmt_idx, in_block);
            }
            ExprInner::Extract { base, offset, .. } => {
                self.expr(base, stmt_idx, in_block);
                self.expr(offset, stmt_idx, in_block);
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.expr(base, stmt_idx, in_block);
                self.expr(offset, stmt_idx, in_block);
                self.expr(value, stmt_idx, in_block);
            }
            ExprInner::IRegister { reg_offset, .. } => self.expr(reg_offset, stmt_idx, in_block),
        }
    }
}

/// Port of ``FindExtraDefs``: default viewer traversal; every ``Reference`` tagged ``extra_def`` defines its vvar.
struct ExtraDefs<'py> {
    py: Python<'py>,
    found: Vec<VVarSite>,
    error: Option<PyErr>,
}

impl ExtraDefs<'_> {
    fn stmt(&mut self, stmt_idx: usize, stmt: &AilStatement, in_block: bool) {
        match &stmt.inner {
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                self.expr(dst, stmt_idx, in_block);
                self.expr(src, stmt_idx, in_block);
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
                for e in [
                    Some(addr),
                    Some(data_lo),
                    data_hi.as_ref(),
                    Some(expd_lo),
                    expd_hi.as_ref(),
                    Some(old_lo),
                    old_hi.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::SideEffectStatement { expr, .. } => self.expr(expr, stmt_idx, in_block),
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.expr(addr, stmt_idx, in_block);
                self.expr(data, stmt_idx, in_block);
                if let Some(e) = guard {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::Jump { target, .. } => {
                if let CFGTarget::Expr(e) = target {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.expr(condition, stmt_idx, in_block);
                if let Some(CFGTarget::Expr(e)) = true_target {
                    self.expr(e, stmt_idx, in_block);
                }
                if let Some(CFGTarget::Expr(e)) = false_target {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.expr(e, stmt_idx, in_block);
                }
            }
            StmtInner::DirtyStatement { dirty } => self.expr(dirty, stmt_idx, in_block),
            StmtInner::Label { .. }
            | StmtInner::NoOp
            | StmtInner::IncompleteSwitchCaseHeadStatement { .. } => {}
        }
    }

    fn expr(&mut self, e: &AilExpression, stmt_idx: usize, in_block: bool) {
        match &e.inner {
            ExprInner::UnaryOp { op, operand, .. } => {
                if op == "Reference" && tag_truthy(self.py, &e.header.tags, &TagKey::ExtraDef) {
                    if !in_block {
                        self.error = Some(PyAssertionError::new_err(
                            "extra_def Reference inside a nested statement",
                        ));
                        return;
                    }
                    match varid_of(operand) {
                        Some(varid) => self.found.push(VVarSite {
                            varid,
                            stmt_idx,
                            expr: (**operand).clone(),
                        }),
                        None => {
                            self.error = Some(PyAssertionError::new_err(
                                "extra_def Reference operand is not a vvar",
                            ));
                            return;
                        }
                    }
                }
                self.expr(operand, stmt_idx, in_block);
            }
            ExprInner::VirtualVariable { .. }
            | ExprInner::Tmp { .. }
            | ExprInner::Const { .. }
            | ExprInner::Register { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. }
            | ExprInner::Macro { .. }
            | ExprInner::Let { .. } => {}
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.expr(r, stmt_idx, in_block);
                }
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(v) = &entry.vvar {
                        self.expr(v, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::Convert { operand, .. } | ExprInner::Reinterpret { operand, .. } => {
                self.expr(operand, stmt_idx, in_block)
            }
            ExprInner::BinaryOp { operands, .. } => {
                self.expr(&operands[0], stmt_idx, in_block);
                self.expr(&operands[1], stmt_idx, in_block);
            }
            ExprInner::Load { addr, .. } => self.expr(addr, stmt_idx, in_block),
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t, stmt_idx, in_block);
                }
                if let Some(args) = args {
                    for a in args {
                        self.expr(a, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::DirtyExpression(d) => {
                for o in &d.operands {
                    self.expr(o, stmt_idx, in_block);
                }
                if let Some(g) = &d.guard {
                    self.expr(g, stmt_idx, in_block);
                }
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.expr(o, stmt_idx, in_block);
                }
            }
            ExprInner::MultiStatementExpression { stmts, expr } => {
                for (i, s) in stmts.iter().enumerate() {
                    self.stmt(i, s, false);
                }
                self.expr(expr, stmt_idx, in_block);
            }
            ExprInner::Struct(s) => {
                for f in s.fields.values() {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::Array { elements } => {
                for f in elements {
                    self.expr(f, stmt_idx, in_block);
                }
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                if let Some(args) = args {
                    for a in args {
                        self.expr(a, stmt_idx, in_block);
                    }
                }
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.expr(cond, stmt_idx, in_block);
                self.expr(iftrue, stmt_idx, in_block);
                self.expr(iffalse, stmt_idx, in_block);
            }
            ExprInner::Extract { base, offset, .. } => {
                self.expr(base, stmt_idx, in_block);
                self.expr(offset, stmt_idx, in_block);
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.expr(base, stmt_idx, in_block);
                self.expr(offset, stmt_idx, in_block);
                self.expr(value, stmt_idx, in_block);
            }
            ExprInner::IRegister { reg_offset, .. } => self.expr(reg_offset, stmt_idx, in_block),
        }
    }
}

/// Statement-level definitions, in the order the Python scan records them: primary def(s), extra defs, clobber
/// defs.
fn stmt_defs(py: Python<'_>, raw: &mut Raw, stmt_idx: usize, stmt: &AilStatement) -> PyResult<()> {
    match &stmt.inner {
        StmtInner::Assignment { dst, src } => {
            if let Some(varid) = varid_of(dst) {
                raw.vvar_defs.push(VVarSite {
                    varid,
                    stmt_idx,
                    expr: (**dst).clone(),
                });
                if let ExprInner::Phi { src_and_vvars } = &src.inner {
                    raw.phis.push((
                        varid,
                        src_and_vvars
                            .iter()
                            .map(|e| e.vvar.as_ref().and_then(|v| varid_of(v)))
                            .collect(),
                    ));
                }
            } else if let ExprInner::Tmp { tmp_idx } = &dst.inner {
                raw.tmp_defs.push((*tmp_idx, dst.header.bits, stmt_idx));
            }
        }
        StmtInner::SideEffectStatement {
            ret_expr,
            fp_ret_expr,
            ..
        } => {
            for slot in [ret_expr, fp_ret_expr].into_iter().flatten() {
                if let Some(varid) = varid_of(slot) {
                    raw.vvar_defs.push(VVarSite {
                        varid,
                        stmt_idx,
                        expr: (**slot).clone(),
                    });
                }
            }
        }
        StmtInner::CAS { old_lo, old_hi, .. } => {
            for slot in [Some(old_lo), old_hi.as_ref()].into_iter().flatten() {
                if let ExprInner::Tmp { tmp_idx } = &slot.inner {
                    raw.tmp_defs.push((*tmp_idx, slot.header.bits, stmt_idx));
                }
            }
        }
        _ => {}
    }
    let tags = &stmt.header.tags;
    if let Some(declared) = tag_int_list(py, tags, &TagKey::ExtraDefs)? {
        let mut w = ExtraDefs {
            py,
            found: Vec::new(),
            error: None,
        };
        w.stmt(stmt_idx, stmt, true);
        if let Some(e) = w.error {
            return Err(e);
        }
        raw.vvar_defs.append(&mut w.found);
        raw.extra_declared.extend(declared);
    }
    if tags.has("clobber_defs")
        && let Some(triples) = tag_int_list(py, tags, &TagKey::from_key("clobber_defs"))?
    {
        for t in triples.as_chunks::<3>().0 {
            raw.vvar_defs.push(VVarSite {
                varid: t[0],
                stmt_idx,
                expr: clobber_vvar(t[0], t[1], t[2]),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Memoized per-block result
// ---------------------------------------------------------------------------

/// The def/use lists of one block as finished Python objects (shared across reads; callers must not mutate).
#[derive(Debug)]
pub struct BlockDefUse {
    addr: i64,
    idx: i64,
    /// version of the statements list the lists were taken from
    version: u64,
    /// ``{varid: (VirtualVariable, AILCodeLocation)}``
    pub vvar_deflocs: Py<PyDict>,
    /// ``{varid: [(VirtualVariable, AILCodeLocation), ...]}`` in traversal order
    pub vvar_uselocs: Py<PyDict>,
    /// ``{phi varid: [src varid or None, ...]}`` in phi-entry order
    pub phi_vvars: Py<PyDict>,
    /// varids declared by ``extra_defs`` tags
    pub extra_declared: Vec<i64>,
    /// ``{atoms.Tmp: stmt_idx}``
    pub tmp_deflocs: Py<PyDict>,
    /// ``[(atoms.Tmp, [(Tmp, stmt_idx), ...]), ...]`` grouped by ``(tmp_idx, bits)`` in first-use order
    pub tmp_use_groups: Py<PyList>,
}

impl BlockDefUse {
    /// True iff the block still holds the statements that were scanned.
    fn matches(&self, addr: i64, idx: i64, stmts: &Bound<'_, PyList>) -> bool {
        addr == self.addr && idx == self.idx && StatementList::version_of(stmts) == self.version
    }
}

/// Scan a block from scratch. ``cacheable`` is false for a statements list that has no version. A non-``Statement``
/// entry contributes nothing.
fn scan_block(
    py: Python<'_>,
    addr: i64,
    idx: i64,
    stmts: &Bound<'_, PyList>,
) -> PyResult<(BlockDefUse, bool)> {
    let version = StatementList::version_of(stmts);
    let mut raw = Raw::default();
    let mut uses = Uses {
        py,
        vvar_uses: Vec::new(),
        tmp_uses: Vec::new(),
        phi_dst_varid: None,
    };
    let cacheable = version != 0;
    let mut ins_addrs: Vec<Option<i64>> = Vec::with_capacity(stmts.len());
    for (stmt_idx, item) in stmts.iter().enumerate() {
        let Ok(cell) = item.cast::<Statement>() else {
            ins_addrs.push(None);
            continue;
        };
        let guard = cell.borrow();
        let stmt = &guard.stmt;
        ins_addrs.push(stmt.header.tags.ins_addr);
        stmt_defs(py, &mut raw, stmt_idx, stmt)?;
        uses.stmt(stmt_idx, stmt, true);
    }
    raw.vvar_uses = uses.vvar_uses;
    raw.tmp_uses = uses.tmp_uses;

    // one AILCodeLocation per referenced statement, shared by every site in it
    let loc_cls = ail_code_location(py)?;
    let mut locs: Vec<Option<Py<PyAny>>> = vec![None; stmts.len()];
    let mut loc_for = |stmt_idx: usize| -> PyResult<Py<PyAny>> {
        if let Some(l) = &locs[stmt_idx] {
            return Ok(l.clone_ref(py));
        }
        let loc = loc_cls
            .call1((addr, idx, stmt_idx, ins_addrs[stmt_idx]))?
            .unbind();
        locs[stmt_idx] = Some(loc.clone_ref(py));
        Ok(loc)
    };

    let vvar_deflocs = PyDict::new(py);
    for site in raw.vvar_defs {
        let loc = loc_for(site.stmt_idx)?;
        let vvar = Bound::new(py, Expression::wrap(site.expr))?;
        vvar_deflocs.set_item(
            site.varid,
            PyTuple::new(py, [vvar.into_any(), loc.into_bound(py)])?,
        )?;
    }
    let vvar_uselocs = PyDict::new(py);
    for site in raw.vvar_uses {
        let loc = loc_for(site.stmt_idx)?;
        let vvar = Bound::new(py, Expression::wrap(site.expr))?;
        let entry = PyTuple::new(py, [vvar.into_any(), loc.into_bound(py)])?;
        match vvar_uselocs.get_item(site.varid)? {
            Some(l) => l.cast_into::<PyList>()?.append(entry)?,
            None => {
                let l = PyList::empty(py);
                l.append(entry)?;
                vvar_uselocs.set_item(site.varid, l)?;
            }
        }
    }
    let phi_vvars = PyDict::new(py);
    for (dst, srcs) in raw.phis {
        phi_vvars.set_item(dst, PyList::new(py, srcs)?)?;
    }
    let tmp_cls = tmp_atom(py)?;
    let tmp_deflocs = PyDict::new(py);
    for (tmp_idx, bits, stmt_idx) in raw.tmp_defs {
        tmp_deflocs.set_item(tmp_cls.call1((tmp_idx, bits))?, stmt_idx)?;
    }
    // group tmp uses by (tmp_idx, bits), first-use order, like the ``defaultdict(set)`` of the Python collector
    let mut groups: Vec<((i64, u32), Vec<TmpSite>)> = Vec::new();
    for site in raw.tmp_uses {
        let key = (site.tmp_idx, site.bits);
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(site),
            None => groups.push((key, vec![site])),
        }
    }
    let tmp_use_groups = PyList::empty(py);
    for ((tmp_idx, bits), sites) in groups {
        let entries = PyList::empty(py);
        for site in sites {
            let tmp = Bound::new(py, Expression::wrap(site.expr))?;
            entries.append(PyTuple::new(
                py,
                [
                    tmp.into_any(),
                    (site.stmt_idx).into_pyobject(py)?.into_any(),
                ],
            )?)?;
        }
        tmp_use_groups.append(PyTuple::new(
            py,
            [tmp_cls.call1((tmp_idx, bits))?, entries.into_any()],
        )?)?;
    }

    Ok((
        BlockDefUse {
            addr,
            idx,
            version,
            vvar_deflocs: vvar_deflocs.unbind(),
            vvar_uselocs: vvar_uselocs.unbind(),
            phi_vvars: phi_vvars.unbind(),
            extra_declared: raw.extra_declared,
            tmp_deflocs: tmp_deflocs.unbind(),
            tmp_use_groups: tmp_use_groups.unbind(),
        },
        cacheable,
    ))
}

/// The block's current def/use lists: the memo when the statements list is unchanged, else a fresh scan.
pub fn block_defuse(block: &Bound<'_, Block>) -> PyResult<Arc<BlockDefUse>> {
    let py = block.py();
    let b = block.borrow();
    let stmts = b.statements.bind(py);
    {
        let cached = b.defuse.lock().expect("defuse lock");
        if let Some(c) = cached.as_ref()
            && c.matches(b.addr, b.idx, stmts)
        {
            return Ok(c.clone());
        }
    }
    let (scan, cacheable) = scan_block(py, b.addr, b.idx, stmts)?;
    let scan = Arc::new(scan);
    if cacheable {
        *b.defuse.lock().expect("defuse lock") = Some(scan.clone());
    }
    Ok(scan)
}

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

/// How tmp uses are regrouped by ``atoms.Tmp`` (which compares on ``tmp_idx`` only):
/// 0 -- ``get_uses_defs``: union into an existing entry, and every block gets a (possibly empty) entry;
/// 1 -- ``get_tmp_uselocs``: a later group replaces an existing entry, blocks without tmp uses get no entry.
const TMP_MODE_USES_DEFS: u8 = 0;

/// Merge the per-block def/use lists of ``blocks`` into whichever containers are given, reproducing the insertion
/// order and overwrite semantics of the original whole-graph scan.
#[pyfunction]
#[pyo3(signature = (blocks, vvar_deflocs=None, phi_vvars=None, vvar_uselocs=None, tmp_deflocs=None, tmp_uselocs=None, tmp_mode=0))]
#[allow(clippy::too_many_arguments)]
pub fn collect_uses_defs<'py>(
    py: Python<'py>,
    blocks: &Bound<'py, PyAny>,
    vvar_deflocs: Option<&Bound<'py, PyDict>>,
    phi_vvars: Option<&Bound<'py, PyDict>>,
    vvar_uselocs: Option<&Bound<'py, PyDict>>,
    tmp_deflocs: Option<&Bound<'py, PyDict>>,
    tmp_uselocs: Option<&Bound<'py, PyDict>>,
    tmp_mode: u8,
) -> PyResult<()> {
    for item in blocks.try_iter()? {
        let item = item?;
        let block = item.cast::<Block>().map_err(|_| {
            PyTypeError::new_err(format!(
                "collect_uses_defs: expected Block, got {}",
                item.get_type()
            ))
        })?;
        let du = block_defuse(block)?;
        if let Some(d) = vvar_deflocs {
            let block_defs = du.vvar_deflocs.bind(py);
            d.update(block_defs.as_mapping())?;
            for varid in &du.extra_declared {
                if !d.contains(*varid)? {
                    return Err(PyAssertionError::new_err("extra_def tag was dropped"));
                }
            }
            if let Some(p) = phi_vvars {
                for (dst, srcs) in du.phi_vvars.bind(py).iter() {
                    let s = PySet::empty(py)?;
                    for v in srcs.cast::<PyList>()?.iter() {
                        s.add(v)?;
                    }
                    p.set_item(dst, s)?;
                }
            }
        }
        if let Some(u) = vvar_uselocs {
            for (varid, entries) in du.vvar_uselocs.bind(py).iter() {
                let entries = entries.cast::<PyList>()?;
                match u.get_item(&varid)? {
                    Some(existing) => existing
                        .cast::<PyList>()?
                        .call_method1("extend", (entries,))
                        .map(|_| ())?,
                    None => u.set_item(varid, PyList::new(py, entries.iter())?)?,
                }
            }
        }
        if tmp_deflocs.is_some() || tmp_uselocs.is_some() {
            let b = block.borrow();
            let block_loc = PyTuple::new(py, [b.addr, b.idx])?;
            drop(b);
            if let Some(td) = tmp_deflocs {
                let defs = du.tmp_deflocs.bind(py);
                if !defs.is_empty() {
                    td.set_item(&block_loc, defs.copy()?)?;
                }
            }
            if let Some(tu) = tmp_uselocs {
                let groups = du.tmp_use_groups.bind(py);
                if tmp_mode == TMP_MODE_USES_DEFS || !groups.is_empty() {
                    let block_map = match tu.get_item(&block_loc)? {
                        Some(m) => m.cast_into::<PyDict>()?,
                        None => {
                            let m = PyDict::new(py);
                            tu.set_item(&block_loc, &m)?;
                            m
                        }
                    };
                    for group in groups.iter() {
                        let group = group.cast::<PyTuple>()?;
                        let key = group.get_item(0)?;
                        let entries = group.get_item(1)?;
                        let s = PySet::empty(py)?;
                        for e in entries.cast::<PyList>()?.iter() {
                            s.add(e)?;
                        }
                        match (tmp_mode, block_map.get_item(&key)?) {
                            (TMP_MODE_USES_DEFS, Some(existing)) => {
                                existing
                                    .cast::<PySet>()?
                                    .call_method1("__ior__", (s,))
                                    .map(|_| ())?;
                            }
                            _ => block_map.set_item(key, s)?,
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// ``(vvar_deflocs, vvar_uselocs)`` of one block -- the memoized dicts themselves; read-only.
#[pyfunction]
pub fn block_vvar_defs_uses<'py>(
    block: &Bound<'py, Block>,
) -> PyResult<(Bound<'py, PyDict>, Bound<'py, PyDict>)> {
    let py = block.py();
    let du = block_defuse(block)?;
    Ok((
        du.vvar_deflocs.bind(py).clone(),
        du.vvar_uselocs.bind(py).clone(),
    ))
}

/// Whether the block's memoized def/use lists are present and still valid (test hook).
#[pyfunction]
pub fn block_defuse_is_cached(block: &Bound<'_, Block>) -> bool {
    let py = block.py();
    let b = block.borrow();
    let cached = b.defuse.lock().expect("defuse lock");
    cached
        .as_ref()
        .is_some_and(|c| c.matches(b.addr, b.idx, b.statements.bind(py)))
}
