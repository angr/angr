//! `ArmElfFastResolver`: constant-pool loads (`ldr r3, [pc, #x]; blx r3`) and the `add ip, pc, ...; ldr pc, [ip, #x]!`
//! PLT pattern. Its one side effect, marking the loaded word as a pointer, goes through `Effects`.

use pyo3::prelude::*;

use super::blade::{BladeParams, DEFAULT_STATEMENT, SliceLoc, blade};
use super::effects::Effect;
use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver};
use crate::ailment::vex_ffi::IEND_BE;
use crate::vexir::{Expr, Stmt, VexIrsb, op_name};
use crate::vexlift::jumpkind_name;

pub struct ArmElfFastResolver {
    /// `isinstance(project.arch, ArchARM)`
    pub is_arm: bool,
    /// `cfg.tag == "CFGFast"`
    pub occupy: bool,
}

const PARAMS: BladeParams = BladeParams {
    ignore_sp: true,
    ignore_bp: true,
    ignored_regs: Vec::new(),
    max_level: 2,
    stop_at_calls: false,
    cross_insn_opt: false,
    max_predecessors: 10,
    include_imarks: true,
    control_dependence: false,
};

impl ArmElfFastResolver {
    fn load(
        cx: &ResolveCx,
        addr: u64,
        size: u32,
        big_endian: bool,
    ) -> Result<Option<u64>, &'static str> {
        if !matches!(size, 1 | 2 | 4 | 8) {
            return Err("load_size");
        }
        Ok(cx.snap.load_word_endian(addr, size as usize, big_endian))
    }

    fn resolve_default(
        &self,
        cx: &ResolveCx,
        block: &VexIrsb,
        stmt_tmp: u32,
        data: u32,
        first_succ: Option<SliceLoc>,
        fx: &mut Effects,
    ) -> Result<Outcome, &'static str> {
        let Some(Expr::Load { end, addr, .. }) = block.expr(data) else {
            return Ok(Outcome::Unresolved);
        };
        let Some(Expr::Const(c)) = block.expr(*addr) else {
            return Ok(Outcome::Unresolved);
        };
        let load_addr = c.int_value().ok_or("const")?;
        let load_size = block.result_bits(data) / 8;
        let Some(next) = first_succ else {
            return Err("no_successor");
        };
        if next != (block.addr, DEFAULT_STATEMENT) {
            return Ok(Outcome::Unresolved);
        }
        let Some(next_tmp) = block.next_tmp() else {
            return Err("next_not_tmp");
        };
        if next_tmp != stmt_tmp {
            return Ok(Outcome::Unresolved);
        }
        let Some(target) = Self::load(cx, load_addr, load_size, *end == IEND_BE)? else {
            return Ok(Outcome::Unresolved);
        };
        if self.occupy {
            fx.push(Effect::SegOccupy {
                addr: load_addr,
                size: load_size as u64,
                sort: "pointer-array",
            });
        }
        Ok(Outcome::Resolved(vec![target]))
    }

    fn resolve_put(
        &self,
        cx: &ResolveCx,
        block: &VexIrsb,
        offset: i32,
        data: u32,
        first_succ: Option<SliceLoc>,
        fx: &mut Effects,
    ) -> Result<Outcome, &'static str> {
        let Some(Expr::Const(c)) = block.expr(data) else {
            return Ok(Outcome::Unresolved);
        };
        match cx.arch.register_names.get(&offset) {
            Some(n) if n == "r12" => {}
            Some(_) => return Ok(Outcome::Unresolved),
            None => return Err("register_name"),
        }
        let mut load_addr = c.int_value().ok_or("const")? as u128;
        let load_size = block.result_bits(data) / 8;
        let mut count = 0;
        for s in &block.stmts {
            if let Stmt::WrTmp { data: d, .. } = s
                && let Some(Expr::Binop { op, args }) = block.expr(*d)
                && op_name(*op).contains("Add")
            {
                // next_stmt.constants[0]: the first constant operand
                let k = args.iter().find_map(|&a| match block.expr(a) {
                    Some(Expr::Const(k)) => Some(k),
                    _ => None,
                });
                let Some(k) = k else {
                    return Err("no_constant");
                };
                load_addr += k.int_value().ok_or("const")? as u128;
                count += 1;
            }
        }
        if count != 2 {
            return Ok(Outcome::Unresolved);
        }
        let Some(next) = first_succ else {
            return Err("no_successor");
        };
        if next.0 != block.addr {
            return Ok(Outcome::Unresolved);
        }
        let Ok(load_addr) = u64::try_from(load_addr) else {
            return Ok(Outcome::Unresolved);
        };
        let Some(target) = Self::load(cx, load_addr, load_size, cx.arch.memory_be)? else {
            return Ok(Outcome::Unresolved);
        };
        if self.occupy {
            fx.push(Effect::SegOccupy {
                addr: load_addr,
                size: load_size as u64,
                sort: "pointer-array",
            });
        }
        Ok(Outcome::Resolved(vec![target]))
    }
}

impl Resolver for ArmElfFastResolver {
    fn kind(&self) -> &'static str {
        "ArmElfFastResolver"
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
            self.is_arm && matches!(jumpkind_name(j.jumpkind), "Ijk_Boring" | "Ijk_Call"),
        ))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        let slice = match blade(py, cx, j.addr, -1, &PARAMS)? {
            Ok(s) => s,
            Err(d) => return Ok(Decision::Python(d)),
        };
        let sources: Vec<SliceLoc> = slice
            .nodes
            .iter()
            .filter(|(_, n)| n.preds.is_empty())
            .map(|(k, _)| *k)
            .collect();
        if sources.len() != 1 {
            return Ok(Decision::Done(Outcome::Unresolved));
        }
        let source = sources[0];
        let block = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        if source.0 != block.addr {
            return Ok(Decision::Done(Outcome::Unresolved));
        }
        let first_succ = slice.nodes[&source].succs.first().copied();
        let Some(stmt) = usize::try_from(source.1)
            .ok()
            .and_then(|i| block.stmts.get(i))
        else {
            return Ok(Decision::Python("stmt_index"));
        };
        let r = match stmt {
            Stmt::WrTmp { tmp, data } => {
                self.resolve_default(cx, &block, *tmp, *data, first_succ, fx)
            }
            Stmt::Put { offset, data } => {
                self.resolve_put(cx, &block, *offset, *data, first_succ, fx)
            }
            _ => Ok(Outcome::Unresolved),
        };
        Ok(match r {
            Ok(o) => Decision::Done(o),
            Err(d) => Decision::Python(d),
        })
    }
}
