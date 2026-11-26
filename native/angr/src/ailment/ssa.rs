//! Per-block SSA def/use lists.
//!
//! Each [`Block`] memoizes the vvar/tmp definitions and uses of its statements (`BlockDefUse`) as plain Rust
//! data. `Block.statements` is a [`StatementList`], which takes a new version on every mutation, and
//! statements are immutable from Python, so the memo is valid for as long as the list keeps the version it was
//! scanned at: a read checks one integer.
//!
//! `collect_uses_defs` builds the Python values of a block sequence into the caller's containers with exactly
//! the insertion order and overwrite semantics of the original whole-graph scan in `angr.utils.ssa`.
//!
//! [`UsesDefs`] holds the sites of a block sequence for consumers to query, and builds Python values only for
//! what a query returns.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use indexmap::IndexMap;
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

#[derive(Debug)]
struct VVarSite {
    varid: i64,
    stmt_idx: usize,
    expr: AilExpression,
}

#[derive(Debug)]
struct TmpSite {
    tmp_idx: i64,
    stmt_idx: usize,
    /// header of the ``Tmp`` expression; with ``tmp_idx`` it is the whole expression
    header: ExprHeader,
}

impl TmpSite {
    fn expr(&self) -> AilExpression {
        AilExpression {
            header: self.header.clone(),
            inner: ExprInner::Tmp {
                tmp_idx: self.tmp_idx,
            },
        }
    }
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
                    stmt_idx,
                    header: e.header.clone(),
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

/// The def/use sites of one block, as plain data: nothing here is a Python object, so a memo adds nothing for the
/// garbage collector to track. ``collect_uses_defs`` builds the Python values on each request.
#[derive(Debug)]
pub struct BlockDefUse {
    addr: i64,
    idx: i64,
    /// version of the statements list the sites were taken from
    version: u64,
    /// ``ins_addr`` of every statement
    ins_addrs: Vec<Option<i64>>,
    /// vvar definitions in traversal order
    vvar_defs: Vec<VVarSite>,
    /// vvar uses in traversal order
    vvar_uses: Vec<VVarSite>,
    /// ``(phi varid, [src varid or None, ...])`` in phi-entry order
    phis: Vec<(i64, Vec<Option<i64>>)>,
    /// varids declared by ``extra_defs`` tags
    extra_declared: Vec<i64>,
    /// ``(tmp_idx, bits, stmt_idx)`` of every tmp definition
    tmp_defs: Vec<(i64, u32, usize)>,
    /// tmp uses grouped by ``(tmp_idx, bits)`` in first-use order
    tmp_use_groups: Vec<((i64, u32), Vec<TmpSite>)>,
}

impl BlockDefUse {
    /// True iff the block still holds the statements that were scanned.
    fn matches(&self, addr: i64, idx: i64, stmts: &Bound<'_, PyList>) -> bool {
        addr == self.addr && idx == self.idx && StatementList::version_of(stmts) == self.version
    }
}

/// The ``AILCodeLocation`` of each statement of one block: built on first use, shared by every site in the statement.
struct Locs<'a, 'py> {
    du: &'a BlockDefUse,
    cls: Bound<'py, PyAny>,
    locs: Vec<Option<Bound<'py, PyAny>>>,
}

impl<'a, 'py> Locs<'a, 'py> {
    fn new(py: Python<'py>, du: &'a BlockDefUse) -> PyResult<Self> {
        Ok(Self {
            du,
            cls: ail_code_location(py)?,
            locs: vec![None; du.ins_addrs.len()],
        })
    }

    fn get(&mut self, stmt_idx: usize) -> PyResult<Bound<'py, PyAny>> {
        if let Some(l) = &self.locs[stmt_idx] {
            return Ok(l.clone());
        }
        let loc = self.cls.call1((
            self.du.addr,
            self.du.idx,
            stmt_idx,
            self.du.ins_addrs[stmt_idx],
        ))?;
        self.locs[stmt_idx] = Some(loc.clone());
        Ok(loc)
    }

    /// ``(VirtualVariable, AILCodeLocation)`` of a site.
    fn entry(&mut self, site: &VVarSite) -> PyResult<Bound<'py, PyTuple>> {
        let loc = self.get(site.stmt_idx)?;
        let py = loc.py();
        let vvar = Bound::new(py, Expression::wrap(site.expr.clone()))?;
        PyTuple::new(py, [vvar.into_any(), loc])
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

    // group tmp uses by (tmp_idx, bits), first-use order, like the ``defaultdict(set)`` of the Python collector
    let mut tmp_use_groups: Vec<((i64, u32), Vec<TmpSite>)> = Vec::new();
    for site in raw.tmp_uses {
        let key = (site.tmp_idx, site.header.bits);
        match tmp_use_groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(site),
            None => tmp_use_groups.push((key, vec![site])),
        }
    }

    Ok((
        BlockDefUse {
            addr,
            idx,
            version,
            ins_addrs,
            vvar_defs: raw.vvar_defs,
            vvar_uses: raw.vvar_uses,
            phis: raw.phis,
            extra_declared: raw.extra_declared,
            tmp_defs: raw.tmp_defs,
            tmp_use_groups,
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
        let mut locs = Locs::new(py, &du)?;
        if let Some(d) = vvar_deflocs {
            for site in &du.vvar_defs {
                d.set_item(site.varid, locs.entry(site)?)?;
            }
            for varid in &du.extra_declared {
                if !d.contains(*varid)? {
                    return Err(PyAssertionError::new_err("extra_def tag was dropped"));
                }
            }
            if let Some(p) = phi_vvars {
                for (dst, srcs) in &du.phis {
                    let s = PySet::empty(py)?;
                    for v in srcs {
                        s.add(*v)?;
                    }
                    p.set_item(*dst, s)?;
                }
            }
        }
        if let Some(u) = vvar_uselocs {
            for site in &du.vvar_uses {
                let entry = locs.entry(site)?;
                match u.get_item(site.varid)? {
                    Some(existing) => existing.cast::<PyList>()?.append(entry)?,
                    None => u.set_item(site.varid, PyList::new(py, [entry])?)?,
                }
            }
        }
        if tmp_deflocs.is_some() || tmp_uselocs.is_some() {
            let tmp_cls = tmp_atom(py)?;
            let block_loc = PyTuple::new(py, [du.addr, du.idx])?;
            if let Some(td) = tmp_deflocs
                && !du.tmp_defs.is_empty()
            {
                let defs = PyDict::new(py);
                for (tmp_idx, bits, stmt_idx) in &du.tmp_defs {
                    defs.set_item(tmp_cls.call1((*tmp_idx, *bits))?, *stmt_idx)?;
                }
                td.set_item(&block_loc, defs)?;
            }
            if let Some(tu) = tmp_uselocs
                && (tmp_mode == TMP_MODE_USES_DEFS || !du.tmp_use_groups.is_empty())
            {
                let block_map = match tu.get_item(&block_loc)? {
                    Some(m) => m.cast_into::<PyDict>()?,
                    None => {
                        let m = PyDict::new(py);
                        tu.set_item(&block_loc, &m)?;
                        m
                    }
                };
                for ((tmp_idx, bits), sites) in &du.tmp_use_groups {
                    let key = tmp_cls.call1((*tmp_idx, *bits))?;
                    let s = tmp_use_set(py, sites)?;
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
    Ok(())
}

/// The ``set`` of ``(Tmp, stmt_idx)`` of one tmp-use group.
fn tmp_use_set<'py>(py: Python<'py>, sites: &[TmpSite]) -> PyResult<Bound<'py, PySet>> {
    let s = PySet::empty(py)?;
    for site in sites {
        let tmp = Bound::new(py, Expression::wrap(site.expr()))?;
        s.add((tmp, site.stmt_idx))?;
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// ``(block, site)`` position of a vvar site.
type SiteRef = (u32, u32);

/// The def/use sites of a sequence of blocks, merged like ``collect_uses_defs`` merges them (a later definition of
/// a vvar replaces an earlier one; uses are in block order). It is a snapshot: editing the blocks afterwards does
/// not change it. Blocks are expected to have distinct ``(addr, idx)``.
#[pyclass(name = "UsesDefs", module = "angr.rustylib.ailment")]
pub struct UsesDefs {
    blocks: Vec<Arc<BlockDefUse>>,
    defs: IndexMap<i64, SiteRef>,
    uses: IndexMap<i64, Vec<SiteRef>>,
    /// ``AILCodeLocation`` of the statements asked about so far, per block
    locs: Vec<Vec<Option<Py<PyAny>>>>,
    /// varid -> the list ``vvar_uses`` returned
    use_lists: Py<PyDict>,
}

impl UsesDefs {
    fn loc<'py>(
        &mut self,
        py: Python<'py>,
        block: u32,
        stmt_idx: usize,
    ) -> PyResult<Bound<'py, PyAny>> {
        let du = &self.blocks[block as usize];
        let locs = &mut self.locs[block as usize];
        if locs.is_empty() {
            locs.resize_with(du.ins_addrs.len(), || None);
        }
        if let Some(l) = &locs[stmt_idx] {
            return Ok(l.bind(py).clone());
        }
        let loc =
            ail_code_location(py)?.call1((du.addr, du.idx, stmt_idx, du.ins_addrs[stmt_idx]))?;
        locs[stmt_idx] = Some(loc.clone().unbind());
        Ok(loc)
    }

    /// ``(VirtualVariable, AILCodeLocation)`` of a site.
    fn entry<'py>(
        &mut self,
        py: Python<'py>,
        at: SiteRef,
        is_def: bool,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let du = self.blocks[at.0 as usize].clone();
        let site = if is_def {
            &du.vvar_defs[at.1 as usize]
        } else {
            &du.vvar_uses[at.1 as usize]
        };
        let loc = self.loc(py, at.0, site.stmt_idx)?;
        let vvar = Bound::new(py, Expression::wrap(site.expr.clone()))?;
        PyTuple::new(py, [vvar.into_any(), loc])
    }

    fn use_list<'py>(
        &mut self,
        py: Python<'py>,
        sites: &[SiteRef],
    ) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for at in sites {
            list.append(self.entry(py, *at, false)?)?;
        }
        Ok(list)
    }
}

#[pymethods]
impl UsesDefs {
    #[new]
    fn new(py: Python<'_>, blocks: &Bound<'_, PyAny>) -> PyResult<Self> {
        let mut this = Self {
            blocks: Vec::new(),
            defs: IndexMap::new(),
            uses: IndexMap::new(),
            locs: Vec::new(),
            use_lists: PyDict::new(py).unbind(),
        };
        for item in blocks.try_iter()? {
            let item = item?;
            let block = item.cast::<Block>().map_err(|_| {
                PyTypeError::new_err(format!("UsesDefs: expected Block, got {}", item.get_type()))
            })?;
            let du = block_defuse(block)?;
            let bi = this.blocks.len() as u32;
            for (i, site) in du.vvar_defs.iter().enumerate() {
                this.defs.insert(site.varid, (bi, i as u32));
            }
            if du
                .extra_declared
                .iter()
                .any(|varid| !this.defs.contains_key(varid))
            {
                return Err(PyAssertionError::new_err("extra_def tag was dropped"));
            }
            for (i, site) in du.vvar_uses.iter().enumerate() {
                this.uses
                    .entry(site.varid)
                    .or_default()
                    .push((bi, i as u32));
            }
            this.blocks.push(du);
        }
        this.locs.resize_with(this.blocks.len(), Vec::new);
        Ok(this)
    }

    /// ``{varid: (VirtualVariable, AILCodeLocation)}`` of every definition; fills ``phi_vvars`` with
    /// ``{phi varid: {source varid or None}}`` when given.
    #[pyo3(signature = (phi_vvars=None))]
    fn vvar_defs<'py>(
        &mut self,
        py: Python<'py>,
        phi_vvars: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for i in 0..self.defs.len() {
            let (varid, at) = self
                .defs
                .get_index(i)
                .map(|(k, v)| (*k, *v))
                .expect("in range");
            d.set_item(varid, self.entry(py, at, true)?)?;
        }
        if let Some(p) = phi_vvars {
            for du in &self.blocks {
                for (dst, srcs) in &du.phis {
                    let s = PySet::empty(py)?;
                    for v in srcs {
                        s.add(*v)?;
                    }
                    p.set_item(*dst, s)?;
                }
            }
        }
        Ok(d)
    }

    fn has_vvar_uses(&self, varid: i64) -> bool {
        self.uses.contains_key(&varid)
    }

    /// ``[(VirtualVariable, AILCodeLocation)]`` of the uses of one vvar; the same list on every call.
    fn vvar_uses<'py>(&mut self, py: Python<'py>, varid: i64) -> PyResult<Bound<'py, PyList>> {
        if let Some(list) = self.use_lists.bind(py).get_item(varid)? {
            return Ok(list.cast_into::<PyList>()?);
        }
        let sites = self.uses.get(&varid).cloned().unwrap_or_default();
        let list = self.use_list(py, &sites)?;
        self.use_lists.bind(py).set_item(varid, &list)?;
        Ok(list)
    }

    /// ``{varid: [(VirtualVariable, AILCodeLocation)]}`` of every use.
    fn all_vvar_uses<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for i in 0..self.uses.len() {
            let (varid, sites) = self
                .uses
                .get_index(i)
                .map(|(k, v)| (*k, v.clone()))
                .expect("in range");
            d.set_item(varid, self.use_list(py, &sites)?)?;
        }
        Ok(d)
    }

    /// The used varids, in first-use order, that are in ``also`` or whose definition or first use is a register vvar
    /// of one of ``reg_offsets``.
    fn register_use_ids(&self, reg_offsets: Vec<i64>, also: HashSet<i64>) -> Vec<i64> {
        let is_reg = |site: &VVarSite| {
            matches!(
                &site.expr.inner,
                ExprInner::VirtualVariable {
                    category: VirtualVariableCategory::Register,
                    oident: OIdent::Int(offset),
                    ..
                } if reg_offsets.contains(offset)
            )
        };
        let mut ids = Vec::new();
        for (varid, sites) in &self.uses {
            let (bi, i) = sites[0];
            let hit = also.contains(varid)
                || is_reg(&self.blocks[bi as usize].vvar_uses[i as usize])
                || self.defs.get(varid).is_some_and(|(bi, i)| {
                    is_reg(&self.blocks[*bi as usize].vvar_defs[*i as usize])
                });
            if hit {
                ids.push(*varid);
            }
        }
        ids
    }

    /// ``[((addr, idx), def stmt_idx, {(Tmp, use stmt_idx)})]`` of every tmp that is defined and used in the same
    /// block. ``Tmp`` atoms compare on ``tmp_idx`` alone: the last definition counts, and uses of every width are
    /// one entry.
    fn tmp_defs_uses<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for du in &self.blocks {
            if du.tmp_defs.is_empty() || du.tmp_use_groups.is_empty() {
                continue;
            }
            let defs: HashMap<i64, usize> = du.tmp_defs.iter().map(|(t, _, s)| (*t, *s)).collect();
            let mut merged: IndexMap<i64, Bound<'py, PySet>> = IndexMap::new();
            for ((tmp_idx, _), sites) in &du.tmp_use_groups {
                if !defs.contains_key(tmp_idx) {
                    continue;
                }
                let s = tmp_use_set(py, sites)?;
                match merged.get(tmp_idx) {
                    Some(existing) => {
                        existing.call_method1("__ior__", (s,))?;
                    }
                    None => {
                        merged.insert(*tmp_idx, s);
                    }
                }
            }
            let block_loc = PyTuple::new(py, [du.addr, du.idx])?;
            for (tmp_idx, s) in merged {
                out.append((&block_loc, defs[&tmp_idx], s))?;
            }
        }
        Ok(out)
    }
}

/// ``({tmp_idx: def stmt_idx}, {tmp_idx: {use stmt_idx}})`` of one block; None when it defines no tmp. Matches
/// ``get_tmp_deflocs`` / ``get_tmp_uselocs``: the last definition of a tmp counts, and of the uses of a tmp at
/// several widths, those of the last width.
#[pyfunction]
pub fn block_tmp_defs_uses<'py>(
    block: &Bound<'py, Block>,
) -> PyResult<Option<(Bound<'py, PyDict>, Bound<'py, PyDict>)>> {
    let py = block.py();
    let du = block_defuse(block)?;
    if du.tmp_defs.is_empty() {
        return Ok(None);
    }
    let defs = PyDict::new(py);
    for (tmp_idx, _, stmt_idx) in &du.tmp_defs {
        defs.set_item(*tmp_idx, *stmt_idx)?;
    }
    let uses = PyDict::new(py);
    for ((tmp_idx, _), sites) in &du.tmp_use_groups {
        let s = PySet::empty(py)?;
        for site in sites {
            s.add(site.stmt_idx)?;
        }
        uses.set_item(*tmp_idx, s)?;
    }
    Ok(Some((defs, uses)))
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
