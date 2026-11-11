//! `MemoryLoadResolver`: a jump or call through a pointer loaded from a constant address.

use pyo3::prelude::*;

use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::vexir::{Expr, Stmt};
use crate::vexlift::jumpkind_name;

pub struct MemoryLoadResolver;

pub(crate) fn is_boring_or_call(jk: u32) -> bool {
    matches!(jumpkind_name(jk), "Ijk_Boring" | "Ijk_Call")
}

/// `vex_block.statements[tmp_stmt_idx]` is `WrTmp(Load(Const))` of a full word: the load address.
pub(crate) fn const_word_load(
    ir: &crate::vexir::VexIrsb,
    stmt_idx: usize,
    arch_bits: u32,
) -> Option<u64> {
    let Stmt::WrTmp { data, .. } = ir.stmts[stmt_idx] else {
        return None;
    };
    let Some(Expr::Load { addr, .. }) = ir.expr(data) else {
        return None;
    };
    let Some(Expr::Const(c)) = ir.expr(*addr) else {
        return None;
    };
    if ir.result_bits(data) != arch_bits {
        return None;
    }
    c.int_value()
}

impl Resolver for MemoryLoadResolver {
    fn kind(&self) -> &'static str {
        "MemoryLoadResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        Ok(Decision::Done(is_boring_or_call(j.jumpkind)))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let ir = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        let Some(tmp) = ir.next_tmp() else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        let Some((stmt_idx, _)) = ir.find_tmp_write_stmt_and_ins(tmp) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        let Some(load_addr) = const_word_load(&ir, stmt_idx, cx.arch.bits) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        // unpack_word raises KeyError on unmapped memory
        let Some(value) = cx.snap.load_word(load_addr, cx.arch.bytes as usize) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        if cx.is_target_valid(py, value)? {
            return Ok(Decision::Done(Outcome::Resolved(vec![value])));
        }
        Ok(Decision::Done(Outcome::Unresolved))
    }
}
