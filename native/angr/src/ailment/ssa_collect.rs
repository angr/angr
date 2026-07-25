//! Native SSA use/def collectors.
//!
//! The Python implementations in ``angr/utils/ssa`` walk AIL blocks through
//! [`AILBlockViewer`](../../../../angr/ailment/block_walker.py) subclasses.
//! Every visited node costs two-to-three Python frames plus a `Bound`
//! allocation and an `AilExpression` clone for each child accessor (the
//! attribute getters materialize a fresh ``Expression`` wrapper per read).
//! On a mid-size function that is upwards of 130k visits per decompile.
//!
//! The AIL tree is already pure Rust below the ``Expression`` /
//! ``Statement`` wrappers, so the walk can run entirely natively and only
//! materialize Python objects for the handful of nodes that end up in the
//! result. These functions are drop-in replacements for
//! ``get_vvar_uselocs`` / ``get_tmp_uselocs`` / ``get_uses_defs``; each one
//! returns ``None`` when it encounters a node that is not a native AIL
//! object, in which case the caller falls back to the Python walker.
//!
//! Traversal order, the ``extra_def`` skip, the assignment-destination
//! suppression and the ``block is None`` suppression inside
//! ``MultiStatementExpression`` all mirror the Python collectors exactly --
//! consumers depend on both the contents and the ordering of the results.

use indexmap::IndexMap;
use pyo3::exceptions::PyAssertionError;
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyDict, PyList, PySet, PyTuple};
use pyo3::IntoPyObjectExt;

use crate::ailment::ail_expr::{AilExpression, CFGTarget, ExprInner, Expression};
use crate::ailment::ail_stmt::{AilStatement, Statement, StmtInner};
use crate::ailment::block::Block;
use crate::ailment::tags::{TagExtra, TagKey, Tags};

// ---------------------------------------------------------------------------
// Cached Python handles
// ---------------------------------------------------------------------------

static AIL_CODE_LOCATION: PyOnceLock<Py<PyAny>> = PyOnceLock::new();
static TMP_ATOM: PyOnceLock<Py<PyAny>> = PyOnceLock::new();

fn ail_code_location(py: Python<'_>) -> PyResult<&Py<PyAny>> {
    AIL_CODE_LOCATION.get_or_try_init(py, || {
        Ok(PyModule::import(py, "angr.code_location")?
            .getattr("AILCodeLocation")?
            .unbind())
    })
}

fn tmp_atom(py: Python<'_>) -> PyResult<&Py<PyAny>> {
    TMP_ATOM.get_or_try_init(py, || {
        Ok(
            PyModule::import(py, "angr.knowledge_plugins.key_definitions.atoms")?
                .getattr("Tmp")?
                .unbind(),
        )
    })
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// ``expr.tags.get("extra_def", False)`` -- truthiness, not presence.
#[inline]
fn is_extra_def(tags: &Tags) -> bool {
    if tags.extras.is_empty() {
        return false;
    }
    match tags.extras.get(&TagKey::ExtraDef) {
        None => false,
        Some(TagExtra::Bool(b)) => *b,
        Some(TagExtra::Int(i)) => *i != 0,
        // The tag is declared ``bool``; anything else is a non-empty value
        // and therefore truthy.
        Some(_) => true,
    }
}

/// ``stmt.tags.get("extra_defs", None)`` -- the varid list, if any.
#[inline]
fn extra_defs(tags: &Tags) -> Option<&[i64]> {
    if tags.extras.is_empty() {
        return None;
    }
    match tags.extras.get(&TagKey::ExtraDefs) {
        Some(TagExtra::IntList(l)) => Some(l.as_slice()),
        _ => None,
    }
}

#[inline]
fn wrap_expr(py: Python<'_>, expr: &AilExpression) -> PyResult<Py<PyAny>> {
    Ok(Py::new(py, Expression::wrap(expr.clone()))?.into_any())
}

/// Which use-collector semantics to apply. The three Python collectors
/// differ only in how ``Assignment`` and the leaf handlers behave; the rest
/// of the traversal is shared.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// ``VVarUsesCollector``
    Vvar,
    /// ``TmpUsesCollector``
    Tmp,
    /// ``VVarAndTmpUsesCollector``
    VvarAndTmp,
}

// ---------------------------------------------------------------------------
// Walker
// ---------------------------------------------------------------------------

struct Walker<'py> {
    py: Python<'py>,
    mode: Mode,
    codeloc_cls: Bound<'py, PyAny>,

    /// varid -> [(VirtualVariable, AILCodeLocation)], in visit order.
    vvar_uses: IndexMap<i64, Vec<Py<PyAny>>>,
    /// (tmp_idx, bits) -> {(Tmp, stmt_idx)}, in first-visit order.
    tmp_uses: IndexMap<(i64, u32), Bound<'py, PySet>>,

    // ``VVarUsesCollector`` / ``TmpUsesCollector`` assignment state.
    walking_assignment_dst: bool,
    assignment_dst_varid: Option<i64>,
    assignment_src_is_phi: bool,
    // ``VVarAndTmpUsesCollector`` assignment state.
    dst_varid_for_current_stmt: Option<i64>,

    // Current block context. ``in_block`` is false while walking the
    // statements nested inside a MultiStatementExpression, matching the
    // ``block=None`` the Python walker passes there.
    block_addr: i64,
    block_idx: Option<i64>,
    in_block: bool,
}

impl<'py> Walker<'py> {
    fn new(py: Python<'py>, mode: Mode) -> PyResult<Self> {
        Ok(Self {
            py,
            mode,
            codeloc_cls: ail_code_location(py)?.bind(py).clone(),
            vvar_uses: IndexMap::new(),
            tmp_uses: IndexMap::new(),
            walking_assignment_dst: false,
            assignment_dst_varid: None,
            assignment_src_is_phi: false,
            dst_varid_for_current_stmt: None,
            block_addr: 0,
            block_idx: None,
            in_block: false,
        })
    }

    #[inline]
    fn codeloc(&self, stmt_idx: usize, ins_addr: Option<i64>) -> PyResult<Py<PyAny>> {
        Ok(self
            .codeloc_cls
            .call1((self.block_addr, self.block_idx, stmt_idx, ins_addr))?
            .unbind())
    }

    fn walk_block(&mut self, block: &Block, stmts: &Bound<'py, PyList>) -> PyResult<bool> {
        self.block_addr = block.addr;
        self.block_idx = block.idx;
        self.in_block = true;
        for (stmt_idx, obj) in stmts.iter().enumerate() {
            let Ok(cell) = obj.cast::<Statement>() else {
                return Ok(false);
            };
            let borrowed = cell.borrow();
            self.handle_stmt(stmt_idx, &borrowed.stmt)?;
        }
        Ok(true)
    }

    // --- statements ------------------------------------------------------

    fn handle_stmt(&mut self, stmt_idx: usize, stmt: &AilStatement) -> PyResult<()> {
        let ins_addr = stmt.header.tags.ins_addr;
        match &stmt.inner {
            StmtInner::Assignment { dst, src } => self.handle_assignment(stmt_idx, ins_addr, dst, src),
            StmtInner::WeakAssignment { dst, src } => {
                self.handle_expr(dst, stmt_idx, ins_addr)?;
                self.handle_expr(src, stmt_idx, ins_addr)
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.handle_expr(addr, stmt_idx, ins_addr)?;
                self.handle_expr(data, stmt_idx, ins_addr)?;
                if let Some(g) = guard {
                    self.handle_expr(g, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            StmtInner::Jump { target, .. } => self.handle_target(target, stmt_idx, ins_addr),
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.handle_expr(condition, stmt_idx, ins_addr)?;
                if let Some(t) = true_target {
                    self.handle_target(t, stmt_idx, ins_addr)?;
                }
                if let Some(t) = false_target {
                    self.handle_target(t, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            // Note: the viewer only descends into ``expr``; ``ret_expr`` and
            // ``fp_ret_expr`` are definitions, not uses.
            StmtInner::SideEffectStatement { expr, .. } => self.handle_expr(expr, stmt_idx, ins_addr),
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.handle_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
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
                self.handle_expr(addr, stmt_idx, ins_addr)?;
                self.handle_expr(data_lo, stmt_idx, ins_addr)?;
                if let Some(e) = data_hi {
                    self.handle_expr(e, stmt_idx, ins_addr)?;
                }
                self.handle_expr(expd_lo, stmt_idx, ins_addr)?;
                if let Some(e) = expd_hi {
                    self.handle_expr(e, stmt_idx, ins_addr)?;
                }
                self.handle_expr(old_lo, stmt_idx, ins_addr)?;
                if let Some(e) = old_hi {
                    self.handle_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            StmtInner::DirtyStatement { dirty } => self.handle_expr(dirty, stmt_idx, ins_addr),
            // No handler registered on the viewer -> ``_stmt_top`` -> None.
            StmtInner::Label { .. } | StmtInner::NoOp => Ok(()),
        }
    }

    fn handle_assignment(
        &mut self,
        stmt_idx: usize,
        ins_addr: Option<i64>,
        dst: &AilExpression,
        src: &AilExpression,
    ) -> PyResult<()> {
        match self.mode {
            Mode::Vvar => {
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
                let r = (|| {
                    self.handle_expr(dst, stmt_idx, ins_addr)?;
                    self.walking_assignment_dst = false;
                    self.handle_expr(src, stmt_idx, ins_addr)
                })();
                self.walking_assignment_dst = prev.0;
                self.assignment_dst_varid = prev.1;
                self.assignment_src_is_phi = prev.2;
                r
            }
            Mode::Tmp => {
                let prev = self.walking_assignment_dst;
                self.walking_assignment_dst = true;
                let r = (|| {
                    self.handle_expr(dst, stmt_idx, ins_addr)?;
                    self.walking_assignment_dst = false;
                    self.handle_expr(src, stmt_idx, ins_addr)
                })();
                self.walking_assignment_dst = prev;
                r
            }
            Mode::VvarAndTmp => {
                // The dst subtree is skipped outright (it is a def, not a use).
                self.dst_varid_for_current_stmt = match (&dst.inner, &src.inner) {
                    (ExprInner::VirtualVariable { varid, .. }, ExprInner::Phi { .. }) => Some(*varid),
                    _ => None,
                };
                let r = self.handle_expr(src, stmt_idx, ins_addr);
                self.dst_varid_for_current_stmt = None;
                r
            }
        }
    }

    #[inline]
    fn handle_target(
        &mut self,
        target: &CFGTarget,
        stmt_idx: usize,
        ins_addr: Option<i64>,
    ) -> PyResult<()> {
        match target {
            CFGTarget::Expr(e) => self.handle_expr(e, stmt_idx, ins_addr),
            // A ``str`` target dispatches to ``_top`` on the Python side.
            CFGTarget::Symbol(_) => Ok(()),
        }
    }

    // --- expressions -----------------------------------------------------

    fn handle_expr(
        &mut self,
        expr: &AilExpression,
        stmt_idx: usize,
        ins_addr: Option<i64>,
    ) -> PyResult<()> {
        // ``VVarUsesCollector`` and ``VVarAndTmpUsesCollector`` override
        // ``_handle_expr`` to prune ``extra_def``-tagged subtrees;
        // ``TmpUsesCollector`` does not.
        if self.mode != Mode::Tmp && is_extra_def(&expr.header.tags) {
            return Ok(());
        }
        match &expr.inner {
            ExprInner::VirtualVariable { varid, .. } => {
                self.visit_vvar(expr, *varid, stmt_idx, ins_addr)
            }
            ExprInner::Tmp { tmp_idx } => self.visit_tmp(expr, *tmp_idx, stmt_idx),
            ExprInner::Const { .. } | ExprInner::Register { .. } => Ok(()),
            ExprInner::Load { addr, .. } => self.handle_expr(addr, stmt_idx, ins_addr),
            ExprInner::BinaryOp { operands, .. } => {
                self.handle_expr(&operands[0], stmt_idx, ins_addr)?;
                self.handle_expr(&operands[1], stmt_idx, ins_addr)
            }
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => self.handle_expr(operand, stmt_idx, ins_addr),
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.handle_expr(t, stmt_idx, ins_addr)?;
                }
                if let Some(args) = args {
                    for a in args {
                        self.handle_expr(a, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.handle_expr(cond, stmt_idx, ins_addr)?;
                self.handle_expr(iftrue, stmt_idx, ins_addr)?;
                self.handle_expr(iffalse, stmt_idx, ins_addr)
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(vvar) = &entry.vvar {
                        self.handle_expr(vvar, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.handle_expr(r, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::MultiStatementExpression { stmts, expr: tail } => {
                // Nested statements are walked with ``block=None``.
                let prev = self.in_block;
                self.in_block = false;
                for (idx, s) in stmts.iter().enumerate() {
                    self.handle_stmt(idx, s)?;
                }
                self.in_block = prev;
                self.handle_expr(tail, stmt_idx, ins_addr)
            }
            ExprInner::DirtyExpression {
                operands, guard, ..
            } => {
                for o in operands {
                    self.handle_expr(o, stmt_idx, ins_addr)?;
                }
                if let Some(g) = guard {
                    self.handle_expr(g, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.handle_expr(o, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Extract { base, offset, .. } => {
                self.handle_expr(base, stmt_idx, ins_addr)?;
                self.handle_expr(offset, stmt_idx, ins_addr)
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.handle_expr(base, stmt_idx, ins_addr)?;
                self.handle_expr(offset, stmt_idx, ins_addr)?;
                self.handle_expr(value, stmt_idx, ins_addr)
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.handle_expr(f, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Struct { fields, .. } => {
                for f in fields.values() {
                    self.handle_expr(f, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Array { elements } => {
                for e in elements {
                    self.handle_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                if let Some(args) = args {
                    for a in args {
                        self.handle_expr(a, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
            // ``StringLiteral`` has an explicit no-op handler; ``Let``,
            // ``Macro``, ``BasePointerOffset`` and ``StackBaseOffset`` have
            // no default handler at all and fall through to ``_top``.
            ExprInner::StringLiteral { .. }
            | ExprInner::Let { .. }
            | ExprInner::Macro { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. } => Ok(()),
        }
    }

    #[inline]
    fn visit_vvar(
        &mut self,
        expr: &AilExpression,
        varid: i64,
        stmt_idx: usize,
        ins_addr: Option<i64>,
    ) -> PyResult<()> {
        match self.mode {
            Mode::Tmp => return Ok(()),
            Mode::Vvar => {
                if self.walking_assignment_dst {
                    return Ok(());
                }
                if self.assignment_src_is_phi
                    && self.assignment_dst_varid == Some(varid)
                {
                    // avoid phi loops
                    return Ok(());
                }
            }
            Mode::VvarAndTmp => {
                if self.dst_varid_for_current_stmt == Some(varid) {
                    return Ok(());
                }
            }
        }
        if !self.in_block {
            // ``block is None`` -> the Python collectors record nothing.
            return Ok(());
        }
        let py = self.py;
        let entry = PyTuple::new(
            py,
            [wrap_expr(py, expr)?, self.codeloc(stmt_idx, ins_addr)?],
        )?;
        self.vvar_uses.entry(varid).or_default().push(entry.unbind().into_any());
        Ok(())
    }

    #[inline]
    fn visit_tmp(&mut self, expr: &AilExpression, tmp_idx: i64, stmt_idx: usize) -> PyResult<()> {
        match self.mode {
            Mode::Vvar => return Ok(()),
            Mode::Tmp => {
                if self.walking_assignment_dst {
                    return Ok(());
                }
            }
            Mode::VvarAndTmp => {}
        }
        let py = self.py;
        let key = (tmp_idx, expr.header.bits);
        let entry = PyTuple::new(py, [wrap_expr(py, expr)?, stmt_idx.into_py_any(py)?])?;
        match self.tmp_uses.get(&key) {
            Some(s) => s.add(entry)?,
            None => {
                let s = PySet::empty(py)?;
                s.add(entry)?;
                self.tmp_uses.insert(key, s);
            }
        }
        Ok(())
    }

    fn take_vvar_uses(&mut self) -> PyResult<Bound<'py, PyDict>> {
        let py = self.py;
        let d = PyDict::new(py);
        for (varid, entries) in std::mem::take(&mut self.vvar_uses) {
            d.set_item(varid, PyList::new(py, entries)?)?;
        }
        Ok(d)
    }
}

// ---------------------------------------------------------------------------
// extra-def scanner (``FindExtraDefs``)
// ---------------------------------------------------------------------------

/// Walk a statement looking for ``Reference`` unary ops tagged ``extra_def``
/// and record ``(operand, codeloc)`` for each. Mirrors
/// ``angr/utils/ssa/vvar_extra_defs_collector.py``.
struct ExtraDefScanner<'py> {
    py: Python<'py>,
    codeloc_cls: Bound<'py, PyAny>,
    block_addr: i64,
    block_idx: Option<i64>,
    out: Vec<(i64, Py<PyAny>)>,
}

impl<'py> ExtraDefScanner<'py> {
    fn scan_stmt(&mut self, stmt_idx: usize, stmt: &AilStatement) -> PyResult<()> {
        let ins_addr = stmt.header.tags.ins_addr;
        match &stmt.inner {
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                self.scan_expr(dst, stmt_idx, ins_addr)?;
                self.scan_expr(src, stmt_idx, ins_addr)
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.scan_expr(addr, stmt_idx, ins_addr)?;
                self.scan_expr(data, stmt_idx, ins_addr)?;
                if let Some(g) = guard {
                    self.scan_expr(g, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            StmtInner::Jump { target, .. } => self.scan_target(target, stmt_idx, ins_addr),
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.scan_expr(condition, stmt_idx, ins_addr)?;
                if let Some(t) = true_target {
                    self.scan_target(t, stmt_idx, ins_addr)?;
                }
                if let Some(t) = false_target {
                    self.scan_target(t, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            StmtInner::SideEffectStatement { expr, .. } => self.scan_expr(expr, stmt_idx, ins_addr),
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.scan_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
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
                self.scan_expr(addr, stmt_idx, ins_addr)?;
                self.scan_expr(data_lo, stmt_idx, ins_addr)?;
                if let Some(e) = data_hi {
                    self.scan_expr(e, stmt_idx, ins_addr)?;
                }
                self.scan_expr(expd_lo, stmt_idx, ins_addr)?;
                if let Some(e) = expd_hi {
                    self.scan_expr(e, stmt_idx, ins_addr)?;
                }
                self.scan_expr(old_lo, stmt_idx, ins_addr)?;
                if let Some(e) = old_hi {
                    self.scan_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            StmtInner::DirtyStatement { dirty } => self.scan_expr(dirty, stmt_idx, ins_addr),
            StmtInner::Label { .. } | StmtInner::NoOp => Ok(()),
        }
    }

    #[inline]
    fn scan_target(
        &mut self,
        target: &CFGTarget,
        stmt_idx: usize,
        ins_addr: Option<i64>,
    ) -> PyResult<()> {
        match target {
            CFGTarget::Expr(e) => self.scan_expr(e, stmt_idx, ins_addr),
            CFGTarget::Symbol(_) => Ok(()),
        }
    }

    fn scan_expr(
        &mut self,
        expr: &AilExpression,
        stmt_idx: usize,
        ins_addr: Option<i64>,
    ) -> PyResult<()> {
        match &expr.inner {
            ExprInner::UnaryOp { op, operand } => {
                if op == "Reference" && is_extra_def(&expr.header.tags) {
                    let ExprInner::VirtualVariable { varid, .. } = &operand.inner else {
                        return Err(PyAssertionError::new_err(
                            "extra_def Reference operand is not a VirtualVariable",
                        ));
                    };
                    let loc = self
                        .codeloc_cls
                        .call1((self.block_addr, self.block_idx, stmt_idx, ins_addr))?
                        .unbind();
                    let pair = PyTuple::new(
                        self.py,
                        [wrap_expr(self.py, operand)?, loc],
                    )?;
                    self.out.push((*varid, pair.unbind().into_any()));
                }
                self.scan_expr(operand, stmt_idx, ins_addr)
            }
            ExprInner::VirtualVariable { .. }
            | ExprInner::Tmp { .. }
            | ExprInner::Const { .. }
            | ExprInner::Register { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::Let { .. }
            | ExprInner::Macro { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. } => Ok(()),
            ExprInner::Load { addr, .. } => self.scan_expr(addr, stmt_idx, ins_addr),
            ExprInner::BinaryOp { operands, .. } => {
                self.scan_expr(&operands[0], stmt_idx, ins_addr)?;
                self.scan_expr(&operands[1], stmt_idx, ins_addr)
            }
            ExprInner::Convert { operand, .. } | ExprInner::Reinterpret { operand, .. } => {
                self.scan_expr(operand, stmt_idx, ins_addr)
            }
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.scan_expr(t, stmt_idx, ins_addr)?;
                }
                if let Some(args) = args {
                    for a in args {
                        self.scan_expr(a, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.scan_expr(cond, stmt_idx, ins_addr)?;
                self.scan_expr(iftrue, stmt_idx, ins_addr)?;
                self.scan_expr(iffalse, stmt_idx, ins_addr)
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(vvar) = &entry.vvar {
                        self.scan_expr(vvar, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.scan_expr(r, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::MultiStatementExpression { stmts, expr: tail } => {
                for (idx, s) in stmts.iter().enumerate() {
                    self.scan_stmt(idx, s)?;
                }
                self.scan_expr(tail, stmt_idx, ins_addr)
            }
            ExprInner::DirtyExpression {
                operands, guard, ..
            } => {
                for o in operands {
                    self.scan_expr(o, stmt_idx, ins_addr)?;
                }
                if let Some(g) = guard {
                    self.scan_expr(g, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.scan_expr(o, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Extract { base, offset, .. } => {
                self.scan_expr(base, stmt_idx, ins_addr)?;
                self.scan_expr(offset, stmt_idx, ins_addr)
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.scan_expr(base, stmt_idx, ins_addr)?;
                self.scan_expr(offset, stmt_idx, ins_addr)?;
                self.scan_expr(value, stmt_idx, ins_addr)
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.scan_expr(f, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Struct { fields, .. } => {
                for f in fields.values() {
                    self.scan_expr(f, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::Array { elements } => {
                for e in elements {
                    self.scan_expr(e, stmt_idx, ins_addr)?;
                }
                Ok(())
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                if let Some(args) = args {
                    for a in args {
                        self.scan_expr(a, stmt_idx, ins_addr)?;
                    }
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Block-list access
// ---------------------------------------------------------------------------

/// Materialize ``blocks`` as ``(Block, statements)`` pairs. Returns ``None``
/// if any element is not a native ``Block``.
fn extract_blocks<'py>(
    blocks: &Bound<'py, PyAny>,
) -> PyResult<Option<Vec<(Bound<'py, Block>, Bound<'py, PyList>)>>> {
    let py = blocks.py();
    let mut out = Vec::new();
    for obj in blocks.try_iter()? {
        let obj = obj?;
        let Ok(cell) = obj.cast_into::<Block>() else {
            return Ok(None);
        };
        let stmts = cell.borrow().statements.bind(py).clone();
        out.push((cell, stmts));
    }
    Ok(Some(out))
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Native ``angr.utils.ssa.get_vvar_uselocs``. Returns ``None`` when the
/// input contains non-native AIL objects (caller falls back to Python).
#[pyfunction]
pub fn collect_vvar_uselocs<'py>(
    py: Python<'py>,
    blocks: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(blocks) = extract_blocks(blocks)? else {
        return Ok(None);
    };
    let mut walker = Walker::new(py, Mode::Vvar)?;
    for (block, stmts) in &blocks {
        if !walker.walk_block(&block.borrow(), stmts)? {
            return Ok(None);
        }
    }
    Ok(Some(walker.take_vvar_uses()?))
}

/// Native ``angr.utils.ssa.get_tmp_uselocs``. The result maps
/// ``(block_addr, block_idx)`` to ``{atoms.Tmp: {(Tmp, stmt_idx)}}``.
#[pyfunction]
pub fn collect_tmp_uselocs<'py>(
    py: Python<'py>,
    blocks: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(blocks) = extract_blocks(blocks)? else {
        return Ok(None);
    };
    let tmp_cls = tmp_atom(py)?.bind(py);
    let out = PyDict::new(py);
    let mut walker = Walker::new(py, Mode::Tmp)?;
    for (block, stmts) in &blocks {
        walker.tmp_uses.clear();
        let b = block.borrow();
        let loc = (b.addr, b.idx);
        if !walker.walk_block(&b, stmts)? {
            return Ok(None);
        }
        drop(b);
        if walker.tmp_uses.is_empty() {
            // The Python version only touches ``tmp_to_loc[block_loc]``
            // inside the per-tmp loop, so a block with no tmp uses adds no
            // entry to the (default)dict.
            continue;
        }
        let block_loc = PyTuple::new(py, [loc.0.into_py_any(py)?, loc.1.into_py_any(py)?])?;
        let inner = match out.get_item(&block_loc)? {
            Some(d) => d.cast_into::<PyDict>()?,
            None => {
                let d = PyDict::new(py);
                out.set_item(&block_loc, &d)?;
                d
            }
        };
        for ((tmp_idx, bits), entries) in std::mem::take(&mut walker.tmp_uses) {
            // ``atoms.Tmp`` hashes/compares on ``tmp_idx`` alone, ignoring
            // the size -- and the Python guard (``if tmp_idx not in ...``,
            // an int against a Tmp-keyed dict) never matches, so a second
            // width for the same index overwrites rather than unions.
            inner.set_item(tmp_cls.call1((tmp_idx, bits))?, entries)?;
        }
    }
    Ok(Some(out))
}

/// Native ``angr.utils.ssa.get_uses_defs``. Returns
/// ``(vvar_deflocs, vvar_uselocs, tmp_deflocs, tmp_uselocs)`` as plain
/// dicts; the Python wrapper re-wraps the two block-keyed ones in
/// ``defaultdict(dict)``.
#[pyfunction]
#[pyo3(signature = (blocks, phi_vvars=None, check_extra_defs=true))]
pub fn collect_uses_defs<'py>(
    py: Python<'py>,
    blocks: &Bound<'py, PyAny>,
    phi_vvars: Option<&Bound<'py, PyDict>>,
    check_extra_defs: bool,
) -> PyResult<Option<Bound<'py, PyTuple>>> {
    let Some(blocks) = extract_blocks(blocks)? else {
        return Ok(None);
    };
    let tmp_cls = tmp_atom(py)?.bind(py);
    let codeloc_cls = ail_code_location(py)?.bind(py).clone();

    let vvar_deflocs = PyDict::new(py);
    let tmp_deflocs = PyDict::new(py);
    let tmp_uselocs = PyDict::new(py);

    let mut walker = Walker::new(py, Mode::VvarAndTmp)?;
    let mut scanner = ExtraDefScanner {
        py,
        codeloc_cls: codeloc_cls.clone(),
        block_addr: 0,
        block_idx: None,
        out: Vec::new(),
    };

    for (block, stmts) in &blocks {
        let (block_addr, block_idx) = {
            let b = block.borrow();
            (b.addr, b.idx)
        };
        let block_loc = PyTuple::new(py, [block_addr.into_py_any(py)?, block_idx.into_py_any(py)?])?;
        scanner.block_addr = block_addr;
        scanner.block_idx = block_idx;

        walker.tmp_uses.clear();

        // --- definition scan (mirrors the Python statement loop) ---
        for (stmt_idx, obj) in stmts.iter().enumerate() {
            let Ok(cell) = obj.cast::<Statement>() else {
                return Ok(None);
            };
            let borrowed = cell.borrow();
            let stmt = &borrowed.stmt;
            let ins_addr = stmt.header.tags.ins_addr;
            match &stmt.inner {
                StmtInner::Assignment { dst, src } => match &dst.inner {
                    ExprInner::VirtualVariable { varid, .. } => {
                        let loc = codeloc_cls.call1((block_addr, block_idx, stmt_idx, ins_addr))?;
                        vvar_deflocs
                            .set_item(*varid, PyTuple::new(py, [wrap_expr(py, dst)?, loc.unbind()])?)?;
                        if let Some(phi_vvars) = phi_vvars
                            && let ExprInner::Phi { src_and_vvars } = &src.inner
                        {
                            phi_vvars.set_item(*varid, phi_src_varids(py, src_and_vvars)?)?;
                        }
                    }
                    ExprInner::Tmp { tmp_idx } => {
                        let atom = tmp_cls.call1((*tmp_idx, dst.header.bits))?;
                        dict_of_dict_set(py, &tmp_deflocs, &block_loc, &atom, stmt_idx)?;
                    }
                    _ => {}
                },
                StmtInner::SideEffectStatement {
                    ret_expr,
                    fp_ret_expr,
                    ..
                } => {
                    for e in [ret_expr, fp_ret_expr].into_iter().flatten() {
                        if let ExprInner::VirtualVariable { varid, .. } = &e.inner {
                            let loc =
                                codeloc_cls.call1((block_addr, block_idx, stmt_idx, ins_addr))?;
                            vvar_deflocs.set_item(
                                *varid,
                                PyTuple::new(py, [wrap_expr(py, e)?, loc.unbind()])?,
                            )?;
                        }
                    }
                }
                StmtInner::CAS { old_lo, old_hi, .. } => {
                    if let ExprInner::Tmp { tmp_idx } = &old_lo.inner {
                        let atom = tmp_cls.call1((*tmp_idx, old_lo.header.bits))?;
                        dict_of_dict_set(py, &tmp_deflocs, &block_loc, &atom, stmt_idx)?;
                    }
                    if let Some(old_hi) = old_hi {
                        if let ExprInner::Tmp { tmp_idx } = &old_hi.inner {
                            let atom = tmp_cls.call1((*tmp_idx, old_hi.header.bits))?;
                            dict_of_dict_set(py, &tmp_deflocs, &block_loc, &atom, stmt_idx)?;
                        }
                    }
                }
                _ => {}
            }

            if let Some(varids) = extra_defs(&stmt.header.tags) {
                scanner.out.clear();
                scanner.scan_stmt(stmt_idx, stmt)?;
                for (varid, pair) in scanner.out.drain(..) {
                    vvar_deflocs.set_item(varid, pair)?;
                }
                if check_extra_defs {
                    for varid in varids {
                        if !vvar_deflocs.contains(*varid)? {
                            return Err(PyAssertionError::new_err("extra_def tag was dropped"));
                        }
                    }
                }
            }
        }

        // --- use scan ---
        if !walker.walk_block(&block.borrow(), stmts)? {
            return Ok(None);
        }

        let inner = match tmp_uselocs.get_item(&block_loc)? {
            Some(d) => d.cast_into::<PyDict>()?,
            None => {
                let d = PyDict::new(py);
                tmp_uselocs.set_item(&block_loc, &d)?;
                d
            }
        };
        for ((tmp_idx, bits), entries) in std::mem::take(&mut walker.tmp_uses) {
            let atom = tmp_cls.call1((tmp_idx, bits))?;
            match inner.get_item(&atom)? {
                Some(existing) => {
                    existing.cast_into::<PySet>()?.call_method1("update", (entries,))?;
                }
                None => inner.set_item(&atom, entries)?,
            }
        }
    }

    let vvar_uselocs = walker.take_vvar_uses()?;
    Ok(Some(PyTuple::new(
        py,
        [
            vvar_deflocs.into_any(),
            vvar_uselocs.into_any(),
            tmp_deflocs.into_any(),
            tmp_uselocs.into_any(),
        ],
    )?))
}

/// Native ``angr.utils.ssa.get_vvar_deflocs``. Same statement scan as
/// ``collect_uses_defs`` minus the tmp side and the use collection.
#[pyfunction]
#[pyo3(signature = (blocks, phi_vvars=None, check_extra_defs=true))]
pub fn collect_vvar_deflocs<'py>(
    py: Python<'py>,
    blocks: &Bound<'py, PyAny>,
    phi_vvars: Option<&Bound<'py, PyDict>>,
    check_extra_defs: bool,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let Some(blocks) = extract_blocks(blocks)? else {
        return Ok(None);
    };
    let codeloc_cls = ail_code_location(py)?.bind(py).clone();
    let vvar_deflocs = PyDict::new(py);
    let mut scanner = ExtraDefScanner {
        py,
        codeloc_cls: codeloc_cls.clone(),
        block_addr: 0,
        block_idx: None,
        out: Vec::new(),
    };

    for (block, stmts) in &blocks {
        let (block_addr, block_idx) = {
            let b = block.borrow();
            (b.addr, b.idx)
        };
        scanner.block_addr = block_addr;
        scanner.block_idx = block_idx;

        for (stmt_idx, obj) in stmts.iter().enumerate() {
            let Ok(cell) = obj.cast::<Statement>() else {
                return Ok(None);
            };
            let borrowed = cell.borrow();
            let stmt = &borrowed.stmt;
            let ins_addr = stmt.header.tags.ins_addr;
            match &stmt.inner {
                StmtInner::Assignment { dst, src } => {
                    if let ExprInner::VirtualVariable { varid, .. } = &dst.inner {
                        let loc = codeloc_cls.call1((block_addr, block_idx, stmt_idx, ins_addr))?;
                        vvar_deflocs
                            .set_item(*varid, PyTuple::new(py, [wrap_expr(py, dst)?, loc.unbind()])?)?;
                        if let Some(phi_vvars) = phi_vvars
                            && let ExprInner::Phi { src_and_vvars } = &src.inner
                        {
                            phi_vvars.set_item(*varid, phi_src_varids(py, src_and_vvars)?)?;
                        }
                    }
                }
                StmtInner::SideEffectStatement {
                    ret_expr,
                    fp_ret_expr,
                    ..
                } => {
                    for e in [ret_expr, fp_ret_expr].into_iter().flatten() {
                        if let ExprInner::VirtualVariable { varid, .. } = &e.inner {
                            let loc =
                                codeloc_cls.call1((block_addr, block_idx, stmt_idx, ins_addr))?;
                            vvar_deflocs
                                .set_item(*varid, PyTuple::new(py, [wrap_expr(py, e)?, loc.unbind()])?)?;
                        }
                    }
                }
                _ => {}
            }

            if let Some(varids) = extra_defs(&stmt.header.tags) {
                scanner.out.clear();
                scanner.scan_stmt(stmt_idx, stmt)?;
                for (varid, pair) in scanner.out.drain(..) {
                    vvar_deflocs.set_item(varid, pair)?;
                }
                if check_extra_defs {
                    for varid in varids {
                        if !vvar_deflocs.contains(*varid)? {
                            return Err(PyAssertionError::new_err("extra_def tag was dropped"));
                        }
                    }
                }
            }
        }
    }
    Ok(Some(vvar_deflocs))
}

/// ``{vvar_.varid if vvar_ is not None else None for _, vvar_ in phi.src_and_vvars}``
fn phi_src_varids<'py>(
    py: Python<'py>,
    src_and_vvars: &[crate::ailment::ail_expr::PhiEntry],
) -> PyResult<Bound<'py, PySet>> {
    let s = PySet::empty(py)?;
    for entry in src_and_vvars {
        match &entry.vvar {
            Some(v) => match &v.inner {
                ExprInner::VirtualVariable { varid, .. } => s.add(*varid)?,
                _ => s.add(py.None())?,
            },
            None => s.add(py.None())?,
        }
    }
    Ok(s)
}

#[inline]
fn dict_of_dict_set(
    py: Python<'_>,
    outer: &Bound<'_, PyDict>,
    outer_key: &Bound<'_, PyTuple>,
    inner_key: &Bound<'_, PyAny>,
    value: usize,
) -> PyResult<()> {
    let inner = match outer.get_item(outer_key)? {
        Some(d) => d.cast_into::<PyDict>()?,
        None => {
            let d = PyDict::new(py);
            outer.set_item(outer_key, &d)?;
            d
        }
    };
    inner.set_item(inner_key, value)
}
