//! `Blade` and `SimSlicer` (angr/blade.py, angr/slicer.py): backward slicing over CFG nodes and VEX statements.
//!
//! The slice graph keeps networkx DiGraph insertion orders, so `predecessors()` and node order match Python.

use std::rc::Rc;

use indexmap::{IndexMap, IndexSet};
use pyo3::prelude::*;
use rustc_hash::FxHashSet;

use super::cx::{IrSpec, ResolveCx};
use super::fcp::Decline;
use super::u256::U256;
use crate::ailment::vex_ffi::{
    ICO_F32, ICO_F32I, ICO_F64, ICO_F64I, ICO_U128, ICO_V128, ICO_V256, ICO_V512,
};
use crate::vexir::{Expr, ExprId, Stmt, VexIrsb, op_name};
use crate::vexlift::{IJK_NODECODE, VEX_IRSB_MAX_SIZE, jumpkind_name};

/// `angr.utils.constants.DEFAULT_STATEMENT`.
pub const DEFAULT_STATEMENT: i64 = -2;

/// `(block address, statement index)`.
pub type SliceLoc = (u64, i64);

#[derive(Clone, Debug, Default)]
pub struct SliceNode {
    pub preds: IndexSet<SliceLoc>,
    pub succs: IndexSet<SliceLoc>,
}

/// `networkx.DiGraph` restricted to what Blade builds.
#[derive(Clone, Debug, Default)]
pub struct SliceGraph {
    pub nodes: IndexMap<SliceLoc, SliceNode>,
}

impl SliceGraph {
    pub fn add_node(&mut self, n: SliceLoc) {
        self.nodes.entry(n).or_default();
    }

    pub fn add_edge(&mut self, u: SliceLoc, v: SliceLoc) {
        self.add_node(u);
        self.add_node(v);
        self.nodes[&u].succs.insert(v);
        self.nodes[&v].preds.insert(u);
    }

    /// `slice.predecessors(n)`; None when `n` is not in the graph (networkx raises).
    pub fn predecessors(&self, n: &SliceLoc) -> Option<&IndexSet<SliceLoc>> {
        self.nodes.get(n).map(|x| &x.preds)
    }

    /// Edges in `networkx.DiGraph.edges()` order.
    pub fn edges(&self) -> Vec<(SliceLoc, SliceLoc)> {
        self.nodes
            .iter()
            .flat_map(|(u, n)| n.succs.iter().map(move |v| (*u, *v)))
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct BladeParams {
    pub ignore_sp: bool,
    pub ignore_bp: bool,
    pub ignored_regs: Vec<i32>,
    pub max_level: i32,
    pub stop_at_calls: bool,
    pub cross_insn_opt: bool,
    pub max_predecessors: usize,
    pub include_imarks: bool,
    pub control_dependence: bool,
}

/// A value of the slicer's alias analysis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Alias {
    Int(U256),
    /// A float constant; using one as a stack offset is not reproduced.
    Float,
}

pub struct SlicerResult {
    pub final_regs: FxHashSet<i32>,
    pub final_stack_offsets: FxHashSet<U256>,
}

/// `SimSlicer(arch, statements, target_tmps, target_regs, target_stack_offsets, inslice_callback, include_imarks)`;
/// `on_stmt(stmt_idx)` is the in-slice callback, called in reverse statement order.
pub fn sim_slicer(
    cx: &ResolveCx,
    ir: &VexIrsb,
    target_tmps: FxHashSet<u32>,
    target_regs: &FxHashSet<i32>,
    target_stack_offsets: &FxHashSet<U256>,
    include_imarks: bool,
    on_stmt: &mut dyn FnMut(i64),
) -> Result<SlicerResult, Decline> {
    let arch = &cx.arch;
    if target_tmps.is_empty() && target_regs.is_empty() && target_stack_offsets.is_empty() {
        return Err("slicer_no_targets");
    }
    let mut regs: FxHashSet<i32> = target_regs.iter().map(|&r| arch.base_register(r)).collect();
    let mut tmps = target_tmps;
    let mut stack: FxHashSet<U256> = target_stack_offsets.clone();

    // alias analysis: a forward pass with sp and bp mocked
    let sp = U256::from_u64(arch.initial_sp);
    let bp = sp.wrapping_add(U256::from_u64(0x2000));
    let mut temps: rustc_hash::FxHashMap<u32, Alias> = Default::default();
    let mut aliases: rustc_hash::FxHashMap<u32, Alias> = Default::default();
    fn fwd(
        ir: &VexIrsb,
        e: ExprId,
        temps: &rustc_hash::FxHashMap<u32, Alias>,
        sp_off: i32,
        bp_off: i32,
        sp: U256,
        bp: U256,
    ) -> Result<Option<Alias>, Decline> {
        Ok(match ir.expr(e) {
            Some(Expr::Get { offset, .. }) => {
                if *offset == sp_off {
                    Some(Alias::Int(sp))
                } else if *offset == bp_off {
                    Some(Alias::Int(bp))
                } else {
                    None
                }
            }
            Some(Expr::RdTmp(t)) => temps.get(t).copied(),
            Some(Expr::Const(c)) => Some(match c.tag {
                ICO_F32 | ICO_F32I | ICO_F64 | ICO_F64I => Alias::Float,
                ICO_V128 | ICO_V256 => {
                    let n = c.bits() as usize / 8;
                    let bytes: Vec<u8> = (0..n)
                        .map(|i| if (c.raw >> i) & 1 == 1 { 0xff } else { 0 })
                        .collect();
                    Alias::Int(U256::from_le_bytes(&bytes).ok_or("wide_const")?)
                }
                ICO_V512 | ICO_U128 => return Err("wide_const"),
                _ => Alias::Int(U256::from_u64(c.raw)),
            }),
            Some(Expr::Binop { op, args }) => {
                let bits = match op_name(*op) {
                    "Iop_Add64" => 64,
                    "Iop_Add32" => 32,
                    _ => return Ok(None),
                };
                let a = fwd(ir, args[0], temps, sp_off, bp_off, sp, bp)?;
                let b = fwd(ir, args[1], temps, sp_off, bp_off, sp, bp)?;
                match (a, b) {
                    (Some(Alias::Int(a)), Some(Alias::Int(b))) => {
                        Some(Alias::Int(a.wrapping_add(b).masked(bits)))
                    }
                    (Some(_), Some(_)) => return Err("float_alias"),
                    _ => None,
                }
            }
            _ => None,
        })
    }
    for s in &ir.stmts {
        if let Stmt::WrTmp { tmp, data } = s
            && let Some(v) = fwd(ir, *data, &temps, arch.sp_offset, arch.bp_offset, sp, bp)?
        {
            temps.insert(*tmp, v);
            aliases.insert(*tmp, v);
        }
    }

    fn bwd(
        ir: &VexIrsb,
        e: ExprId,
        cx: &ResolveCx,
        aliases: &rustc_hash::FxHashMap<u32, Alias>,
        tmps: &mut FxHashSet<u32>,
        regs: &mut FxHashSet<i32>,
        stack: &mut FxHashSet<U256>,
    ) -> Result<(), Decline> {
        let rdtmp = |id: ExprId| match ir.expr(id) {
            Some(Expr::RdTmp(t)) => Some(*t),
            _ => None,
        };
        match ir.expr(e) {
            Some(Expr::RdTmp(t)) => {
                tmps.insert(*t);
            }
            Some(Expr::Get { offset, .. }) => {
                regs.insert(cx.arch.base_register(*offset));
            }
            Some(Expr::Load { addr, .. }) => {
                if let Some(t) = rdtmp(*addr) {
                    tmps.insert(t);
                    match aliases.get(&t) {
                        Some(Alias::Int(v)) => {
                            stack.insert(*v);
                        }
                        Some(Alias::Float) => return Err("float_alias"),
                        None => {}
                    }
                }
            }
            Some(Expr::Unop { arg, .. }) => {
                if let Some(t) = rdtmp(*arg) {
                    tmps.insert(t);
                }
            }
            Some(Expr::CCall { args, .. }) => {
                for &a in ir.arg_ids(*args) {
                    if let Some(t) = rdtmp(a) {
                        tmps.insert(t);
                    }
                }
            }
            Some(Expr::Binop { args, .. }) => {
                for &a in args {
                    if let Some(t) = rdtmp(a) {
                        tmps.insert(t);
                    }
                }
            }
            Some(Expr::Ite {
                cond,
                iftrue,
                iffalse,
            }) => {
                bwd(ir, *cond, cx, aliases, tmps, regs, stack)?;
                bwd(ir, *iftrue, cx, aliases, tmps, regs, stack)?;
                bwd(ir, *iffalse, cx, aliases, tmps, regs, stack)?;
            }
            _ => {}
        }
        Ok(())
    }

    for (idx, s) in ir.stmts.iter().enumerate().rev() {
        let in_slice = match s {
            Stmt::IMark { .. } => include_imarks,
            Stmt::WrTmp { tmp, data } => {
                if tmps.remove(tmp) {
                    bwd(ir, *data, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                    true
                } else {
                    false
                }
            }
            Stmt::Put { offset, data } => {
                if regs.remove(&arch.base_register(*offset)) {
                    bwd(ir, *data, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                    true
                } else {
                    false
                }
            }
            Stmt::Store { addr, data, .. } => match ir.expr(*addr) {
                Some(Expr::RdTmp(t)) => match aliases.get(t) {
                    Some(Alias::Int(v)) if stack.contains(v) => {
                        stack.remove(v);
                        bwd(ir, *addr, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                        bwd(ir, *data, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                        true
                    }
                    Some(Alias::Float) => return Err("float_alias"),
                    _ => false,
                },
                _ => false,
            },
            Stmt::LoadG {
                dst,
                guard,
                addr,
                alt,
                ..
            } if tmps.contains(dst) => {
                tmps.remove(dst);
                bwd(ir, *guard, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                bwd(ir, *addr, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                bwd(ir, *alt, cx, &aliases, &mut tmps, &mut regs, &mut stack)?;
                true
            }
            _ => false,
        };
        if in_slice {
            on_stmt(idx as i64);
        }
        if regs.is_empty() && tmps.is_empty() && stack.is_empty() {
            break;
        }
    }
    Ok(SlicerResult {
        final_regs: regs,
        final_stack_offsets: stack,
    })
}

/// An in-edge of a CFG node: (pred id, pred addr, jumpkind, stmt_idx).
type PredEdge = (u64, u64, Option<String>, Option<i64>);

struct Blade<'a> {
    py: Python<'a>,
    cx: &'a mut ResolveCx,
    p: &'a BladeParams,
    slice: SliceGraph,
    traced: FxHashSet<u64>,
}

impl Blade<'_> {
    /// `Blade.get_block(addr).vex`; Ok(None) for a NoDecode block (`BadJumpkindNotification`).
    fn irsb(&mut self, addr: u64) -> PyResult<Result<Option<Rc<VexIrsb>>, Decline>> {
        let spec = IrSpec {
            addr,
            max_size: VEX_IRSB_MAX_SIZE as i64,
            opt_level: self.cx.default_opt_level,
            cross_insn_opt: self.p.cross_insn_opt,
            extra_stops: false,
        };
        Ok(match self.cx.ir(self.py, &spec)? {
            Ok(ir) if ir.jumpkind == IJK_NODECODE => Ok(None),
            Ok(ir) => Ok(Some(ir)),
            Err(fb) => Err(fb.name()),
        })
    }

    /// `self._graph.in_edges(get_any_node(addr), data=True)`, first `max_predecessors`, as (pred id, pred addr,
    /// jumpkind, stmt_idx).
    fn in_edges(&self, addr: u64) -> PyResult<Vec<PredEdge>> {
        let g = self.cx.graph.bind(self.py).borrow();
        let Some(id) = g.first_node_at_addr(addr)? else {
            return Ok(Vec::new());
        };
        let edges = g.with_store(|s| {
            let mut out = Vec::new();
            for (src, rec) in s
                .in_edges_rec(id)?
                .into_iter()
                .take(self.p.max_predecessors)
            {
                let jk = rec
                    .jumpkind_code()
                    .and_then(|c| s.jumpkind_str(c))
                    .map(str::to_owned);
                out.push((src, s.node_key(src)?.0, jk, rec.stmt_idx_opt()));
            }
            Ok(out)
        })?;
        Ok(edges)
    }

    fn skip_pred(&self, pred_addr: u64, jk: &Option<String>) -> PyResult<bool> {
        if self.p.stop_at_calls && matches!(jk.as_deref(), Some("Ijk_Call" | "Ijk_Ret")) {
            return Ok(true);
        }
        self.cx.is_hooked(self.py, pred_addr)
    }

    fn drop_ignored(&self, regs: &mut FxHashSet<i32>, with_ignored: bool) {
        if self.p.ignore_sp {
            regs.remove(&self.cx.arch.sp_offset);
        }
        if self.p.ignore_bp {
            regs.remove(&self.cx.arch.bp_offset);
        }
        if with_ignored {
            for r in &self.p.ignored_regs {
                regs.remove(r);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn slicer(
        &mut self,
        ir: &VexIrsb,
        tmps: FxHashSet<u32>,
        regs: &FxHashSet<i32>,
        stack: &FxHashSet<U256>,
        irsb_addr: u64,
        prev: &mut SliceLoc,
        has_statement: &mut bool,
    ) -> Result<SlicerResult, Decline> {
        let slice = &mut self.slice;
        let mut cb = |idx: i64| {
            let tpl = (irsb_addr, idx);
            slice.add_edge(tpl, *prev);
            *prev = tpl;
            *has_statement = true;
        };
        sim_slicer(
            self.cx,
            ir,
            tmps,
            regs,
            stack,
            self.p.include_imarks,
            &mut cb,
        )
    }

    fn backward(&mut self, dst_run: u64, dst_stmt_idx: i64) -> PyResult<Result<(), Decline>> {
        let ir = match self.irsb(dst_run)? {
            Ok(Some(ir)) => ir,
            Ok(None) => return Ok(Ok(())),
            Err(d) => return Ok(Err(d)),
        };
        let mut temps = FxHashSet::default();
        let mut regs = FxHashSet::default();
        let mut prev;
        if dst_stmt_idx != -1 {
            match ir.stmts.get(dst_stmt_idx as usize) {
                Some(Stmt::Put { offset, .. }) => {
                    regs.insert(*offset);
                }
                Some(Stmt::WrTmp { tmp, .. }) => {
                    temps.insert(*tmp);
                }
                _ => return Ok(Err("blade_target_stmt")),
            }
            prev = (dst_run, dst_stmt_idx);
        } else {
            match ir.expr(ir.next) {
                Some(Expr::RdTmp(t)) => {
                    temps.insert(*t);
                }
                Some(Expr::Const(_)) => {}
                _ => return Ok(Err("blade_next")),
            }
            prev = (dst_run, DEFAULT_STATEMENT);
        }
        if temps.is_empty() && regs.is_empty() {
            return Ok(Ok(()));
        }
        let mut has_statement = false;
        let res = match self.slicer(
            &ir,
            temps,
            &regs,
            &FxHashSet::default(),
            ir.addr,
            &mut prev,
            &mut has_statement,
        ) {
            Ok(r) => r,
            Err(d) => return Ok(Err(d)),
        };
        let mut regs = res.final_regs;
        self.drop_ignored(&mut regs, true);
        let stack = res.final_stack_offsets;
        if !regs.is_empty() || !stack.is_empty() {
            for (pred, pred_addr, jk, stmt_idx) in self.in_edges(dst_run)? {
                if self.skip_pred(pred_addr, &jk)? {
                    continue;
                }
                if let Err(d) = self.recursive(
                    self.p.max_level - 1,
                    pred,
                    pred_addr,
                    &regs,
                    &stack,
                    prev,
                    stmt_idx,
                )? {
                    return Ok(Err(d));
                }
            }
        }
        Ok(Ok(()))
    }

    #[allow(clippy::too_many_arguments)]
    fn recursive(
        &mut self,
        level: i32,
        run: u64,
        run_addr: u64,
        regs: &FxHashSet<i32>,
        stack: &FxHashSet<U256>,
        prev: SliceLoc,
        exit_stmt_idx: Option<i64>,
    ) -> PyResult<Result<(), Decline>> {
        if level <= 0 {
            return Ok(Ok(()));
        }
        let ir = match self.irsb(run_addr)? {
            Ok(Some(ir)) => ir,
            Ok(None) => return Ok(Ok(())),
            Err(d) => return Ok(Err(d)),
        };
        let mut temps = FxHashSet::default();
        if self.p.control_dependence
            && matches!(exit_stmt_idx, None | Some(DEFAULT_STATEMENT))
            && let Some(Expr::RdTmp(t)) = ir.expr(ir.next)
        {
            temps.insert(*t);
        }
        // the default exit
        let tpl = (run_addr, DEFAULT_STATEMENT);
        self.slice.add_edge(tpl, prev);
        let mut prev = tpl;
        if self.p.control_dependence {
            for (i, s) in ir.stmts.iter().enumerate() {
                let Stmt::Exit { guard, jk, .. } = s else {
                    continue;
                };
                if jumpkind_name(*jk) != "Ijk_Boring" {
                    continue;
                }
                if let Some(Expr::RdTmp(t)) = ir.expr(*guard) {
                    temps.insert(*t);
                }
                let tpl = (run_addr, i as i64);
                self.slice.add_edge(tpl, prev);
                prev = tpl;
            }
        }
        let mut has_statement = false;
        let res = match self.slicer(
            &ir,
            temps,
            regs,
            stack,
            run_addr,
            &mut prev,
            &mut has_statement,
        ) {
            Ok(r) => r,
            Err(d) => return Ok(Err(d)),
        };
        if !has_statement {
            let tpl = (run_addr, 0);
            self.slice.add_edge(tpl, prev);
            prev = tpl;
        }
        if !self.traced.insert(run) {
            return Ok(Ok(()));
        }
        let mut regs = res.final_regs;
        self.drop_ignored(&mut regs, false);
        let stack = res.final_stack_offsets;
        if !regs.is_empty() || !stack.is_empty() {
            for (pred, pred_addr, jk, stmt_idx) in self.in_edges(run_addr)? {
                if self.skip_pred(pred_addr, &jk)? {
                    continue;
                }
                if let Err(d) =
                    self.recursive(level - 1, pred, pred_addr, &regs, &stack, prev, stmt_idx)?
                {
                    return Ok(Err(d));
                }
            }
        }
        Ok(Ok(()))
    }
}

/// `Blade(cfg.graph, dst_run, dst_stmt_idx, cfg=cfg, project=..., **params).slice`.
pub fn blade(
    py: Python<'_>,
    cx: &mut ResolveCx,
    dst_run: u64,
    dst_stmt_idx: i64,
    p: &BladeParams,
) -> PyResult<Result<SliceGraph, Decline>> {
    // AngrBladeError when the target is not in the graph
    if cx
        .graph
        .bind(py)
        .borrow()
        .first_node_at_addr(dst_run)?
        .is_none()
    {
        return Ok(Err("blade_no_node"));
    }
    let mut b = Blade {
        py,
        cx,
        p,
        slice: SliceGraph::default(),
        traced: FxHashSet::default(),
    };
    Ok(b.backward(dst_run, dst_stmt_idx)?.map(|()| b.slice))
}
