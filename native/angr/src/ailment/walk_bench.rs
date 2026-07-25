//! Microbenchmark harness for "how expensive is it to drive an AIL walk from
//! Rust and call back into Python per node?".
//!
//! Not part of the public API; used by the walker-port feasibility study to
//! separate the three costs that a Rust-driven walker would pay:
//!
//! * the native traversal itself (mode 0),
//! * materializing a Python ``Expression`` wrapper per node (mode 1),
//! * the Python call itself, in the two argument shapes the real peephole
//!   walker uses (modes 2 and 3),
//! * the same, but only for nodes whose kind bit is set in a mask -- the
//!   "hybrid" design where Rust drives and only crosses the boundary for
//!   nodes some optimizer registered interest in (mode 4).

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::ailment::ail_expr::{AilExpression, CFGTarget, ExprInner, Expression};
use crate::ailment::ail_stmt::{AilStatement, Statement, StmtInner};
use crate::ailment::block::Block;

pub const MODE_TRAVERSE: u8 = 0;
pub const MODE_WRAP: u8 = 1;
pub const MODE_CALL1: u8 = 2;
pub const MODE_CALL_KWARGS: u8 = 3;
pub const MODE_MASKED_CALL: u8 = 4;

struct Bench<'py> {
    py: Python<'py>,
    mode: u8,
    mask: u32,
    callback: Option<Bound<'py, PyAny>>,
    kwargs: Option<Bound<'py, PyDict>>,
    visits: u64,
    calls: u64,
}

impl<'py> Bench<'py> {
    #[inline]
    fn visit(&mut self, expr: &AilExpression) -> PyResult<()> {
        self.visits += 1;
        match self.mode {
            MODE_TRAVERSE => {}
            MODE_WRAP => {
                let _ = Py::new(self.py, Expression::wrap(expr.clone()))?;
            }
            MODE_CALL1 => {
                let w = Py::new(self.py, Expression::wrap(expr.clone()))?;
                let cb = self.callback.as_ref().unwrap();
                cb.call1((w,))?;
                self.calls += 1;
            }
            MODE_CALL_KWARGS => {
                let w = Py::new(self.py, Expression::wrap(expr.clone()))?;
                let cb = self.callback.as_ref().unwrap();
                cb.call((w,), self.kwargs.as_ref())?;
                self.calls += 1;
            }
            MODE_MASKED_CALL => {
                if self.mask & (1u32 << (expr.kind() as u8)) != 0 {
                    let w = Py::new(self.py, Expression::wrap(expr.clone()))?;
                    let cb = self.callback.as_ref().unwrap();
                    cb.call((w,), self.kwargs.as_ref())?;
                    self.calls += 1;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn expr(&mut self, expr: &AilExpression) -> PyResult<()> {
        // Children first, then the node itself -- the post-order the peephole
        // walker uses.
        match &expr.inner {
            ExprInner::Const { .. }
            | ExprInner::Tmp { .. }
            | ExprInner::Register { .. }
            | ExprInner::VirtualVariable { .. }
            | ExprInner::Macro { .. }
            | ExprInner::StringLiteral { .. }
            | ExprInner::BasePointerOffset { .. }
            | ExprInner::StackBaseOffset { .. } => {}
            ExprInner::UnaryOp { operand, .. }
            | ExprInner::Convert { operand, .. }
            | ExprInner::Reinterpret { operand, .. } => self.expr(operand)?,
            ExprInner::BinaryOp { operands, .. } => {
                self.expr(&operands[0])?;
                self.expr(&operands[1])?;
            }
            ExprInner::Load { addr, .. } => self.expr(addr)?,
            ExprInner::Call { target, args, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t)?;
                }
                for a in args.iter().flatten() {
                    self.expr(a)?;
                }
            }
            ExprInner::ITE {
                cond,
                iftrue,
                iffalse,
            } => {
                self.expr(cond)?;
                self.expr(iftrue)?;
                self.expr(iffalse)?;
            }
            ExprInner::Phi { src_and_vvars } => {
                for entry in src_and_vvars {
                    if let Some(v) = entry.vvar.as_deref() {
                        self.expr(v)?;
                    }
                }
            }
            ExprInner::ComboRegister { registers } => {
                for r in registers {
                    self.expr(r)?;
                }
            }
            ExprInner::MultiStatementExpression { stmts, expr: e } => {
                for s in stmts {
                    self.stmt(s)?;
                }
                self.expr(e)?;
            }
            ExprInner::DirtyExpression {
                operands, guard, ..
            } => {
                for o in operands {
                    self.expr(o)?;
                }
                if let Some(g) = guard.as_deref() {
                    self.expr(g)?;
                }
            }
            ExprInner::VEXCCallExpression { operands, .. } => {
                for o in operands {
                    self.expr(o)?;
                }
            }
            ExprInner::Extract { base, offset, .. } => {
                self.expr(base)?;
                self.expr(offset)?;
            }
            ExprInner::Insert {
                base,
                offset,
                value,
                ..
            } => {
                self.expr(base)?;
                self.expr(offset)?;
                self.expr(value)?;
            }
            ExprInner::RustEnum { fields, .. } => {
                for f in fields {
                    self.expr(f)?;
                }
            }
            ExprInner::Struct { fields, .. } => {
                for f in fields.values() {
                    self.expr(f)?;
                }
            }
            ExprInner::Array { elements } => {
                for x in elements {
                    self.expr(x)?;
                }
            }
            ExprInner::FunctionLikeMacro { args, .. } => {
                for a in args.iter().flatten() {
                    self.expr(a)?;
                }
            }
            ExprInner::Let { defs, src } => {
                for d in defs {
                    self.stmt(d)?;
                }
                self.expr(src)?;
            }
        }
        self.visit(expr)
    }

    fn stmt(&mut self, stmt: &AilStatement) -> PyResult<()> {
        match &stmt.inner {
            StmtInner::Label { .. } | StmtInner::NoOp => {}
            StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
                self.expr(dst)?;
                self.expr(src)?;
            }
            StmtInner::Store {
                addr, data, guard, ..
            } => {
                self.expr(addr)?;
                self.expr(data)?;
                if let Some(g) = guard {
                    self.expr(g)?;
                }
            }
            StmtInner::Jump { target, .. } => {
                if let CFGTarget::Expr(t) = target {
                    self.expr(t)?;
                }
            }
            StmtInner::ConditionalJump {
                condition,
                true_target,
                false_target,
                ..
            } => {
                self.expr(condition)?;
                for t in [true_target, false_target].into_iter().flatten() {
                    if let CFGTarget::Expr(t) = t {
                        self.expr(t)?;
                    }
                }
            }
            StmtInner::SideEffectStatement { expr, .. } => self.expr(expr)?,
            StmtInner::Return { ret_exprs } => {
                for e in ret_exprs {
                    self.expr(e)?;
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
                self.expr(addr)?;
                self.expr(data_lo)?;
                if let Some(e) = data_hi {
                    self.expr(e)?;
                }
                self.expr(expd_lo)?;
                if let Some(e) = expd_hi {
                    self.expr(e)?;
                }
                self.expr(old_lo)?;
                if let Some(e) = old_hi {
                    self.expr(e)?;
                }
            }
            StmtInner::DirtyStatement { dirty } => self.expr(dirty)?,
        }
        Ok(())
    }
}

/// Walk ``block`` ``reps`` times in the given mode. Returns
/// ``(expr_visits, python_calls)`` for a single rep.
///
/// Returns ``None`` if the block (or any statement in it) is not a native AIL
/// object.
#[pyfunction]
#[pyo3(signature = (block, mode, reps, callback=None, mask=0))]
pub fn _bench_walk(
    py: Python<'_>,
    block: &Bound<'_, PyAny>,
    mode: u8,
    reps: u64,
    callback: Option<Bound<'_, PyAny>>,
    mask: u32,
) -> PyResult<Option<(u64, u64)>> {
    let Ok(cell) = block.cast::<Block>() else {
        return Ok(None);
    };
    let stmts: Bound<'_, PyList> = cell.borrow().statements.bind(py).clone();

    let kwargs = if mode == MODE_CALL_KWARGS || mode == MODE_MASKED_CALL {
        let d = PyDict::new(py);
        d.set_item("stmt_idx", 0usize)?;
        d.set_item("block", block)?;
        Some(d)
    } else {
        None
    };

    let mut b = Bench {
        py,
        mode,
        mask,
        callback,
        kwargs,
        visits: 0,
        calls: 0,
    };

    for _ in 0..reps {
        for obj in stmts.iter() {
            let Ok(cell) = obj.cast::<Statement>() else {
                return Ok(None);
            };
            let borrowed = cell.borrow();
            b.stmt(&borrowed.stmt)?;
        }
    }
    let reps = reps.max(1);
    Ok(Some((b.visits / reps, b.calls / reps)))
}
