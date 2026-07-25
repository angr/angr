//! Native "does this block contain a node of kind X" predicate.
//!
//! Several decompiler passes drive an [`AILBlockRewriter`] over every block
//! in a function purely to find and rewrite one node kind -- VEX ccalls and
//! dirty helpers, for instance. The overwhelming majority of blocks contain
//! no such node, so the whole Python walk is a no-op that still pays two to
//! three frames per visited node.
//!
//! This scan answers "could a walk possibly find one?" natively, over the
//! full structural tree. It is deliberately *conservative*: it descends into
//! every child of every variant, including positions the viewer/rewriter
//! walkers skip, and it answers ``true`` for anything that is not a native
//! AIL object. A ``false`` therefore guarantees the Python walk would visit
//! no matching node, so skipping it cannot change behaviour.

use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::ailment::ail_expr::{AilExpression, CFGTarget, ExprInner};
use crate::ailment::ail_stmt::{AilStatement, StmtInner, Statement};
use crate::ailment::block::Block;

#[inline]
fn bit(kind: u8) -> u32 {
    1u32 << kind
}

fn expr_has(expr: &AilExpression, expr_mask: u32, stmt_mask: u32) -> bool {
    if expr_mask & bit(expr.kind() as u8) != 0 {
        return true;
    }
    let e = |x: &AilExpression| expr_has(x, expr_mask, stmt_mask);
    match &expr.inner {
        ExprInner::Const { .. }
        | ExprInner::Tmp { .. }
        | ExprInner::Register { .. }
        | ExprInner::VirtualVariable { .. }
        | ExprInner::Macro { .. }
        | ExprInner::StringLiteral { .. }
        | ExprInner::BasePointerOffset { .. }
        | ExprInner::StackBaseOffset { .. } => false,
        ExprInner::UnaryOp { operand, .. }
        | ExprInner::Convert { operand, .. }
        | ExprInner::Reinterpret { operand, .. } => e(operand),
        ExprInner::BinaryOp { operands, .. } => e(&operands[0]) || e(&operands[1]),
        ExprInner::Load { addr, guard, alt, .. } => {
            e(addr)
                || guard.as_deref().is_some_and(&e)
                || alt.as_deref().is_some_and(&e)
        }
        ExprInner::Call {
            target,
            args,
            arg_vvars,
        } => {
            matches!(target, CFGTarget::Expr(t) if e(t))
                || args.iter().flatten().any(&e)
                || arg_vvars.iter().flatten().any(&e)
        }
        ExprInner::ITE {
            cond,
            iftrue,
            iffalse,
        } => e(cond) || e(iftrue) || e(iffalse),
        ExprInner::Phi { src_and_vvars } => src_and_vvars
            .iter()
            .any(|entry| entry.vvar.as_deref().is_some_and(&e)),
        ExprInner::ComboRegister { registers } => registers.iter().any(&e),
        ExprInner::MultiStatementExpression { stmts, expr } => {
            stmts.iter().any(|s| stmt_has(s, expr_mask, stmt_mask)) || e(expr)
        }
        ExprInner::DirtyExpression {
            operands,
            guard,
            maddr,
            ..
        } => {
            operands.iter().any(&e)
                || guard.as_deref().is_some_and(&e)
                || maddr.as_deref().is_some_and(&e)
        }
        ExprInner::VEXCCallExpression { operands, .. } => operands.iter().any(&e),
        ExprInner::Extract { base, offset, .. } => e(base) || e(offset),
        ExprInner::Insert {
            base,
            offset,
            value,
            ..
        } => e(base) || e(offset) || e(value),
        ExprInner::RustEnum { fields, .. } => fields.iter().any(|f| e(f)),
        ExprInner::Struct { fields, .. } => fields.values().any(|f| e(f)),
        ExprInner::Array { elements } => elements.iter().any(|x| e(x)),
        ExprInner::FunctionLikeMacro { args, .. } => args.iter().flatten().any(|a| e(a)),
        ExprInner::Let { defs, src } => {
            defs.iter().any(|d| stmt_has(d, expr_mask, stmt_mask)) || e(src)
        }
    }
}

fn stmt_has(stmt: &AilStatement, expr_mask: u32, stmt_mask: u32) -> bool {
    if stmt_mask & bit(stmt.kind() as u8) != 0 {
        return true;
    }
    let e = |x: &AilExpression| expr_has(x, expr_mask, stmt_mask);
    let t = |x: &CFGTarget| matches!(x, CFGTarget::Expr(x) if e(x));
    match &stmt.inner {
        StmtInner::Label { .. } | StmtInner::NoOp => false,
        StmtInner::Assignment { dst, src } | StmtInner::WeakAssignment { dst, src } => {
            e(dst) || e(src)
        }
        StmtInner::Store {
            addr, data, guard, ..
        } => e(addr) || e(data) || guard.as_deref().is_some_and(&e),
        StmtInner::Jump { target, .. } => t(target),
        StmtInner::ConditionalJump {
            condition,
            true_target,
            false_target,
            ..
        } => {
            e(condition)
                || true_target.as_ref().is_some_and(&t)
                || false_target.as_ref().is_some_and(&t)
        }
        StmtInner::SideEffectStatement {
            expr,
            ret_expr,
            fp_ret_expr,
        } => e(expr) || ret_expr.as_deref().is_some_and(&e) || fp_ret_expr.as_deref().is_some_and(&e),
        StmtInner::Return { ret_exprs } => ret_exprs.iter().any(&e),
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
            e(addr)
                || e(data_lo)
                || data_hi.as_deref().is_some_and(&e)
                || e(expd_lo)
                || expd_hi.as_deref().is_some_and(&e)
                || e(old_lo)
                || old_hi.as_deref().is_some_and(&e)
        }
        StmtInner::DirtyStatement { dirty } => e(dirty),
    }
}

/// Does ``block`` contain any expression whose kind bit is set in
/// ``expr_mask`` or any statement whose kind bit is set in ``stmt_mask``?
///
/// Bit ``n`` corresponds to ``ExpressionKind`` / ``StatementKind`` value
/// ``n`` (the same integer the marker classes expose as ``_kind``).
/// Returns ``True`` for anything that is not a native AIL object, so a
/// ``False`` result is always safe to act on.
#[pyfunction]
pub fn block_contains_kinds(
    block: &Bound<'_, PyAny>,
    expr_mask: u32,
    stmt_mask: u32,
) -> PyResult<bool> {
    let Ok(cell) = block.cast::<Block>() else {
        return Ok(true);
    };
    let stmts: Bound<'_, PyList> = cell.borrow().statements.bind(block.py()).clone();
    for obj in stmts.iter() {
        let Ok(cell) = obj.cast::<Statement>() else {
            return Ok(true);
        };
        if stmt_has(&cell.borrow().stmt, expr_mask, stmt_mask) {
            return Ok(true);
        }
    }
    Ok(false)
}
