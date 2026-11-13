//! The context Rust resolvers read: loader memory, lifting, hooks and per-run caches.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use indexmap::IndexMap;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::cfg_graph::CfgGraph;
use crate::cfg_scan::{Snapshot, addr_in_regions};
use crate::recovery_functions::RecoveryFunctions;
use crate::vexir::VexIrsb;
use crate::vexlift::{Fallback, LiftOptions, LiftSummary, VEX_MAX_INSTRUCTIONS, VexLifter};

/// The parameters of a statement lift: `factory.block(addr, size=max_size, opt_level=..., cross_insn_opt=...,
/// extra_stop_points=known_thunks if extra_stops else None).vex`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrSpec {
    pub addr: u64,
    pub max_size: i64,
    pub opt_level: i32,
    pub cross_insn_opt: bool,
    pub extra_stops: bool,
}

/// A bounded two-generation cache: lookups promote from the old generation, and the old one is dropped when the
/// new one fills up.
struct IrCache {
    cur: HashMap<IrSpec, Rc<VexIrsb>>,
    old: HashMap<IrSpec, Rc<VexIrsb>>,
    cap: usize,
    hits: u64,
    misses: u64,
}

impl IrCache {
    fn get(&mut self, k: &IrSpec) -> Option<Rc<VexIrsb>> {
        if let Some(v) = self.cur.get(k) {
            self.hits += 1;
            return Some(v.clone());
        }
        if let Some(v) = self.old.remove(k) {
            self.hits += 1;
            self.put(*k, v.clone());
            return Some(v);
        }
        self.misses += 1;
        None
    }

    fn put(&mut self, k: IrSpec, v: Rc<VexIrsb>) {
        if self.cur.len() >= self.cap {
            self.old = std::mem::take(&mut self.cur);
        }
        self.cur.insert(k, v);
    }
}

/// The architecture constants the resolvers read (from `project.arch`).
#[derive(Clone, Debug, Default)]
pub struct ArchConsts {
    pub bits: u32,
    pub bytes: u32,
    pub byte_width: u32,
    pub sp_offset: i32,
    pub bp_offset: i32,
    pub ip_offset: i32,
    pub ret_offset: i32,
    pub call_pushes_ret: bool,
    /// `registers["ftop"]` on X86/AMD64 (FCP's initial state writes it).
    pub ftop: Option<(i32, u32)>,
    pub initial_sp: u64,
    /// `memory_endness` is big-endian.
    pub memory_be: bool,
    /// `subregister_map` restricted to offset keys: offset -> base register offset.
    pub base_reg: HashMap<i32, i32>,
    /// `registers`: name -> (offset, size).
    pub registers: HashMap<String, (i32, u32)>,
    /// `register_names`: offset -> name.
    pub register_names: HashMap<i32, String>,
    /// `factory.cc().CALLER_SAVED_REGS` as (offset, size).
    pub default_clobbers: Option<Vec<(i32, u32)>>,
}

impl ArchConsts {
    fn from_py(d: &Bound<'_, PyDict>) -> PyResult<Self> {
        let get = |k: &str| -> PyResult<Bound<'_, PyAny>> {
            d.get_item(k)?
                .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(k.to_owned()))
        };
        Ok(ArchConsts {
            bits: get("bits")?.extract()?,
            bytes: get("bytes")?.extract()?,
            byte_width: get("byte_width")?.extract()?,
            sp_offset: get("sp_offset")?.extract()?,
            bp_offset: get("bp_offset")?.extract()?,
            ip_offset: get("ip_offset")?.extract()?,
            ret_offset: get("ret_offset")?.extract()?,
            call_pushes_ret: get("call_pushes_ret")?.extract()?,
            ftop: get("ftop")?.extract()?,
            initial_sp: get("initial_sp")?.extract()?,
            memory_be: get("memory_be")?.extract()?,
            base_reg: get("base_reg")?.extract()?,
            registers: get("registers")?.extract()?,
            register_names: get("register_names")?.extract()?,
            default_clobbers: get("default_clobbers")?.extract()?,
        })
    }

    /// `arch.get_base_register(offset)[0]`, or the offset itself.
    pub fn base_register(&self, offset: i32) -> i32 {
        self.base_reg.get(&offset).copied().unwrap_or(offset)
    }
}

pub struct ResolveCx {
    pub snap: Arc<Snapshot>,
    pub lifter: Py<VexLifter>,
    /// `project._sim_procedures`.
    pub sim_procedures: Py<PyDict>,
    /// `cfg._known_thunks`: `CFGFast._lift`'s extra stop points.
    pub extra_stop_points: Py<PyAny>,
    /// `cfg._exec_mem_regions`.
    pub exec_regions: Vec<(u64, u64)>,
    pub arch: ArchConsts,
    /// The default engine's `default_strict_block_end` and `_default_opt_level`.
    pub strict_block_end: bool,
    pub default_opt_level: i32,
    /// `cfg.model.graph._graph`.
    pub graph: Py<CfgGraph>,
    /// The scan's `RecoveryFunctionManager` and its store, when `kb.functions` is one at chain set-up.
    pub functions: Option<(Py<PyAny>, Py<RecoveryFunctions>)>,
    /// `callee_caller_saved(addr)`: a callee's CALLER_SAVED_REGS as (offset, size), None for the default (Python).
    pub callee_cc: Py<PyAny>,
    ir_cache: IrCache,
    pub stats: IndexMap<String, u64>,
}

impl ResolveCx {
    /// Built from the dict `angr.analyses.cfg.indirect_jump_resolvers.rust.build_chain` passes.
    pub fn new(
        snap: Arc<Snapshot>,
        lifter: Py<VexLifter>,
        ctx: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        let item = |k: &str| -> PyResult<Bound<'_, PyAny>> {
            ctx.get_item(k)?
                .ok_or_else(|| pyo3::exceptions::PyKeyError::new_err(k.to_owned()))
        };
        let functions = match (item("functions")?, item("functions_store")?) {
            (f, s) if !f.is_none() && !s.is_none() => {
                Some((f.unbind(), s.extract::<Py<RecoveryFunctions>>()?))
            }
            _ => None,
        };
        Ok(ResolveCx {
            snap,
            lifter,
            sim_procedures: item("sim_procedures")?.extract()?,
            extra_stop_points: item("extra_stop_points")?.unbind(),
            exec_regions: item("exec_regions")?.extract()?,
            arch: ArchConsts::from_py(item("arch")?.cast::<PyDict>()?)?,
            strict_block_end: item("strict_block_end")?.extract()?,
            default_opt_level: item("default_opt_level")?.extract()?,
            graph: item("graph")?.extract()?,
            functions,
            callee_cc: item("callee_caller_saved")?.unbind(),
            ir_cache: IrCache {
                cur: HashMap::new(),
                old: HashMap::new(),
                cap: 2048,
                hits: 0,
                misses: 0,
            },
            stats: IndexMap::new(),
        })
    }

    /// The scan's function store, if `cfg.kb.functions` is still the manager the chain was built with.
    pub fn functions(
        &self,
        py: Python<'_>,
        cfg: &Bound<'_, PyAny>,
    ) -> PyResult<Option<Py<RecoveryFunctions>>> {
        let Some((mgr, store)) = &self.functions else {
            return Ok(None);
        };
        let cur = cfg
            .getattr(intern!(py, "kb"))?
            .getattr(intern!(py, "functions"))?;
        Ok(cur.is(mgr.bind(py)).then(|| store.clone_ref(py)))
    }

    pub fn count(&mut self, key: &str) {
        match self.stats.get_mut(key) {
            Some(v) => *v += 1,
            None => {
                self.stats.insert(key.to_owned(), 1);
            }
        }
    }

    pub fn ir_cache_stats(&self) -> (u64, u64) {
        (self.ir_cache.hits, self.ir_cache.misses)
    }

    /// `project.is_hooked(addr)`.
    pub fn is_hooked(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        self.sim_procedures.bind(py).contains(addr)
    }

    /// `IndirectJumpResolver._is_target_valid` without a base state (Rust resolvers never run with one).
    pub fn is_target_valid(&self, py: Python<'_>, target: u64) -> PyResult<bool> {
        Ok(addr_in_regions(&self.exec_regions, target) || self.is_hooked(py, target)?)
    }

    /// The statement-level IRSB for `spec`, cached per run.
    pub fn ir(&mut self, py: Python<'_>, spec: &IrSpec) -> PyResult<Result<Rc<VexIrsb>, Fallback>> {
        if let Some(ir) = self.ir_cache.get(spec) {
            return Ok(Ok(ir));
        }
        let opts = LiftOptions {
            opt_level: spec.opt_level,
            traceflags: 0,
            strict_block_end: self.strict_block_end,
            collect_data_refs: false,
            load_from_ro_regions: false,
            const_prop: false,
            cross_insn_opt: spec.cross_insn_opt,
            max_inst: VEX_MAX_INSTRUCTIONS,
        };
        let hooks = self.sim_procedures.bind(py);
        let extra = self.extra_stop_points.bind(py);
        let mut err: Option<PyErr> = None;
        let mut is_stop = |a: u64| -> bool {
            let r = hooks.contains(a).and_then(|h| {
                if h || !spec.extra_stops {
                    Ok(h)
                } else {
                    extra.contains(a)
                }
            });
            r.unwrap_or_else(|e| {
                err.get_or_insert(e);
                false
            })
        };
        let lifter = self.lifter.borrow(py);
        let lock = lifter.lock.bind(py);
        lock.call_method0(intern!(py, "acquire"))?;
        let result = lifter
            .core
            .lift_ir(spec.addr, spec.max_size, &[], &opts, &mut is_stop);
        lock.call_method0(intern!(py, "release"))?;
        drop(lifter);
        if let Some(e) = err {
            return Err(e);
        }
        Ok(result.map(|ir| {
            let ir = Rc::new(ir);
            self.ir_cache.put(*spec, ir.clone());
            ir
        }))
    }

    /// An uncached statement lift with explicit options and initial registers (`factory.block(..., const_prop=...,
    /// initial_regs=...)` is never cached by the engine either). Stop points: hooks only.
    pub fn ir_with(
        &mut self,
        py: Python<'_>,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
    ) -> PyResult<Result<VexIrsb, Fallback>> {
        let hooks = self.sim_procedures.bind(py);
        let mut err: Option<PyErr> = None;
        let mut is_stop = |a: u64| -> bool {
            hooks.contains(a).unwrap_or_else(|e| {
                err.get_or_insert(e);
                false
            })
        };
        let lifter = self.lifter.borrow(py);
        let lock = lifter.lock.bind(py);
        lock.call_method0(intern!(py, "acquire"))?;
        let result = lifter
            .core
            .lift_ir(addr, max_size, initial_regs, opts, &mut is_stop);
        lock.call_method0(intern!(py, "release"))?;
        drop(lifter);
        if let Some(e) = err {
            return Err(e);
        }
        Ok(result)
    }

    /// A statement-less lift with explicit options and initial registers.
    pub fn lift_nostmt_with(
        &mut self,
        py: Python<'_>,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
    ) -> PyResult<Result<LiftSummary, Fallback>> {
        let lifter = self.lifter.borrow(py);
        let lock = lifter.lock.bind(py);
        lock.call_method0(intern!(py, "acquire"))?;
        let result = lifter.core.lift_block(addr, max_size, initial_regs, opts);
        lock.call_method0(intern!(py, "release"))?;
        Ok(result)
    }

    /// The default `LiftOptions` of `factory.block` (engine defaults, no data refs, no constant propagation).
    pub fn block_opts(&self, cross_insn_opt: bool) -> LiftOptions {
        LiftOptions {
            opt_level: self.default_opt_level,
            traceflags: 0,
            strict_block_end: self.strict_block_end,
            collect_data_refs: false,
            load_from_ro_regions: false,
            const_prop: false,
            cross_insn_opt,
            max_inst: VEX_MAX_INSTRUCTIONS,
        }
    }

    /// A statement-less lift (`Block.vex_nostmt`, no stop points).
    pub fn lift_nostmt(
        &mut self,
        py: Python<'_>,
        addr: u64,
        max_size: i64,
        opt_level: i32,
        cross_insn_opt: bool,
    ) -> PyResult<Result<LiftSummary, Fallback>> {
        let opts = LiftOptions {
            opt_level,
            traceflags: 0,
            strict_block_end: self.strict_block_end,
            collect_data_refs: false,
            load_from_ro_regions: false,
            const_prop: false,
            cross_insn_opt,
            max_inst: VEX_MAX_INSTRUCTIONS,
        };
        let lifter = self.lifter.borrow(py);
        let lock = lifter.lock.bind(py);
        lock.call_method0(intern!(py, "acquire"))?;
        let result = lifter.core.lift_block(addr, max_size, &[], &opts);
        lock.call_method0(intern!(py, "release"))?;
        Ok(result)
    }
}
