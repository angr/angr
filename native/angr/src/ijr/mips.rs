//! MIPS ELF resolvers: `MipsElfFastResolver` (t9-based calls through gp) and the filter of `MipsElfGotResolver`.

use pyo3::prelude::*;

use super::blade::{BladeParams, DEFAULT_STATEMENT, blade};
use super::cx::IrSpec;
use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::vexir::{Expr, Stmt, VexIrsb};
use crate::vexlift::{LiftOptions, VEX_IRSB_MAX_SIZE, VEX_MAX_INSTRUCTIONS, jumpkind_name};

/// `MipsElfGotResolver`: the filter in Rust (GOT stubs are rare); resolving reads capstone operands, so it declines.
pub struct MipsElfGotResolver;

impl Resolver for MipsElfGotResolver {
    fn kind(&self) -> &'static str {
        "MipsElfGotResolver"
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
        Ok(Decision::Done(
            jumpkind_name(j.jumpkind) == "Ijk_Call" && j.addr == j.func_addr,
        ))
    }

    fn resolve(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        Ok(Decision::Python("got_stub"))
    }
}

pub struct MipsElfFastResolver {
    /// `isinstance(project.arch, (ArchMIPS32, ArchMIPS64))`
    pub is_mips: bool,
}

enum Case2 {
    Success(u64),
    Failure,
    Resume,
}

/// `_get_jump_target_reg`
fn jump_target_reg(ir: &VexIrsb) -> Option<i32> {
    if jumpkind_name(ir.jumpkind) != "Ijk_Call" {
        return None;
    }
    let next_tmp = ir.next_tmp()?;
    for s in ir.stmts.iter().rev() {
        match s {
            Stmt::Put { offset, data } if matches!(ir.expr(*data), Some(Expr::RdTmp(t)) if *t == next_tmp) =>
            {
                return Some(*offset);
            }
            Stmt::WrTmp { tmp, data } if *tmp == next_tmp => {
                if let Some(Expr::Get { offset, .. }) = ir.expr(*data) {
                    return Some(*offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// `_get_last_reg_setting_tmp`
fn last_reg_setting_tmp(ir: &VexIrsb, reg: i32) -> Option<u32> {
    for s in ir.stmts.iter().rev() {
        if let Stmt::Put { offset, data } = s
            && *offset == reg
        {
            return match ir.expr(*data) {
                Some(Expr::RdTmp(t)) => Some(*t),
                _ => None,
            };
        }
    }
    None
}

impl MipsElfFastResolver {
    fn const_prop_opts(cx: &ResolveCx) -> LiftOptions {
        LiftOptions {
            opt_level: cx.default_opt_level,
            traceflags: 0,
            strict_block_end: cx.strict_block_end,
            collect_data_refs: false,
            load_from_ro_regions: true,
            const_prop: true,
            cross_insn_opt: false,
            max_inst: VEX_MAX_INSTRUCTIONS,
        }
    }

    fn initial_regs(
        cx: &ResolveCx,
        func_addr: u64,
        gp: Option<u64>,
    ) -> Option<Vec<(u32, u32, u64)>> {
        let (t9_off, t9_size) = *cx.arch.registers.get("t9")?;
        let mut regs = vec![(t9_off as u32, t9_size, func_addr)];
        if let Some(gp) = gp {
            let (gp_off, gp_size) = *cx.arch.registers.get("gp")?;
            regs.push((gp_off as u32, gp_size, gp));
        }
        Some(regs)
    }

    /// `_resolve_case_1`; Err when Python must decide.
    fn case_1(
        py: Python<'_>,
        cx: &mut ResolveCx,
        j: &JumpSite,
        block_size: u32,
        gp: Option<u64>,
    ) -> PyResult<Result<Option<u64>, &'static str>> {
        let Some(regs) = Self::initial_regs(cx, j.func_addr, gp) else {
            return Ok(Err("registers"));
        };
        let opts = Self::const_prop_opts(cx);
        let s = match cx.lift_nostmt_with(py, j.addr, block_size as i64, &regs, &opts)? {
            Ok(s) => s,
            Err(fb) => return Ok(Err(fb.name())),
        };
        let crate::vexlift::NextExpr::Tmp(target_tmp) = s.next else {
            return Ok(Ok(None));
        };
        if let Some(cv) = s
            .const_vals
            .iter()
            .find(|cv| cv.tmp as i64 == target_tmp as i64)
            && cx.is_target_valid(py, cv.value)?
        {
            return Ok(Ok(Some(cv.value)));
        }
        Ok(Ok(None))
    }

    /// `_resolve_case_2`
    fn case_2(
        py: Python<'_>,
        cx: &mut ResolveCx,
        first_block_addr: u64,
        second: &VexIrsb,
        func_addr: u64,
        gp: Option<u64>,
    ) -> PyResult<Result<Case2, &'static str>> {
        let Some(reg) = jump_target_reg(second) else {
            return Ok(Ok(Case2::Failure));
        };
        if last_reg_setting_tmp(second, reg).is_some() {
            return Ok(Ok(Case2::Resume));
        }
        let Some(regs) = Self::initial_regs(cx, func_addr, gp) else {
            return Ok(Err("registers"));
        };
        let opts = Self::const_prop_opts(cx);
        let first =
            match cx.ir_with(py, first_block_addr, VEX_IRSB_MAX_SIZE as i64, &regs, &opts)? {
                Ok(ir) => ir,
                Err(fb) => return Ok(Err(fb.name())),
            };
        let Some(tmp) = last_reg_setting_tmp(&first, reg) else {
            return Ok(Ok(Case2::Failure));
        };
        if let Some(&(_, v)) = first
            .const_vals
            .iter()
            .find(|(t, _)| *t as i64 == tmp as i64)
            && cx.is_target_valid(py, v)?
        {
            return Ok(Ok(Case2::Success(v)));
        }
        Ok(Ok(Case2::Failure))
    }
}

impl Resolver for MipsElfFastResolver {
    fn kind(&self) -> &'static str {
        "MipsElfFastResolver"
    }

    fn timeless(&self) -> bool {
        true
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        _j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        Ok(Decision::Done(self.is_mips))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let Some(store) = cx.functions(py, cfg)? else {
            return Ok(Decision::Python("no_store"));
        };
        let gp: Option<u64> = {
            let st = store.bind(py).borrow();
            if !st.contains(j.func_addr) {
                return Ok(Decision::Python("no_function"));
            }
            match st.info_get(py, j.func_addr, "gp")? {
                None => None,
                Some(v) => {
                    let v = v.bind(py);
                    if v.is_none() {
                        None
                    } else {
                        match v.extract::<u64>() {
                            Ok(x) => Some(x),
                            Err(_) => return Ok(Decision::Python("gp_type")),
                        }
                    }
                }
            }
        };
        let Some(&(gp_off, _)) = cx.arch.registers.get("gp") else {
            return Ok(Decision::Python("registers"));
        };
        let params = BladeParams {
            ignore_sp: true,
            ignore_bp: true,
            ignored_regs: vec![gp_off],
            max_level: 2,
            stop_at_calls: true,
            cross_insn_opt: false,
            max_predecessors: 10,
            include_imarks: false,
            control_dependence: true,
        };
        let slice = match blade(py, cx, j.addr, -1, &params)? {
            Ok(s) => s,
            Err(d) => return Ok(Decision::Python(d)),
        };

        // _is_gp_used_on_slice
        let mut gp_used = false;
        for &(block_addr, stmt_idx) in slice.nodes.keys() {
            let spec = IrSpec {
                addr: block_addr,
                max_size: VEX_IRSB_MAX_SIZE as i64,
                opt_level: cx.default_opt_level,
                cross_insn_opt: false,
                extra_stops: false,
            };
            let ir = match cx.ir(py, &spec)? {
                Ok(ir) => ir,
                Err(fb) => return Ok(Decision::Python(fb.name())),
            };
            if stmt_idx == DEFAULT_STATEMENT {
                if matches!(ir.expr(ir.next), Some(Expr::Get { offset, .. }) if *offset == gp_off) {
                    gp_used = true;
                    break;
                }
            } else {
                let Some(stmt) = ir.stmts.get(stmt_idx as usize) else {
                    return Ok(Decision::Python("stmt_index"));
                };
                if let Stmt::WrTmp { data, .. } = stmt
                    && matches!(ir.expr(*data), Some(Expr::Get { offset, .. }) if *offset == gp_off)
                {
                    gp_used = true;
                    break;
                }
            }
        }
        if gp_used && gp.is_none() {
            return Ok(Decision::Done(Outcome::Unresolved));
        }

        let block = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        let mut block_addrs: Vec<u64> = Vec::new();
        for &(a, _) in slice.nodes.keys() {
            if !block_addrs.contains(&a) {
                block_addrs.push(a);
            }
        }
        if block_addrs.len() == 2 && block_addrs.contains(&j.addr) {
            let first = *block_addrs.iter().find(|&&a| a != j.addr).unwrap();
            match Self::case_2(py, cx, first, &block, j.func_addr, gp)? {
                Ok(Case2::Success(t)) => return Ok(Decision::Done(Outcome::Resolved(vec![t]))),
                Ok(Case2::Failure) => return Ok(Decision::Done(Outcome::Unresolved)),
                Ok(Case2::Resume) => {}
                Err(d) => return Ok(Decision::Python(d)),
            }
        }
        match Self::case_1(py, cx, j, block.size, gp)? {
            Ok(Some(t)) => Ok(Decision::Done(Outcome::Resolved(vec![t]))),
            Ok(None) => Ok(Decision::Done(Outcome::Unresolved)),
            Err(d) => Ok(Decision::Python(d)),
        }
    }
}
