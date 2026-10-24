//! The context Rust resolvers read: loader memory, lifting, hooks and per-run caches.

use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use indexmap::IndexMap;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::cfg_scan::{Snapshot, addr_in_regions};
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

pub struct ResolveCx {
    pub snap: Arc<Snapshot>,
    pub lifter: Py<VexLifter>,
    /// `project._sim_procedures`.
    pub sim_procedures: Py<PyDict>,
    /// `cfg._known_thunks`: `CFGFast._lift`'s extra stop points.
    pub extra_stop_points: Py<PyAny>,
    /// `cfg._exec_mem_regions`.
    pub exec_regions: Vec<(u64, u64)>,
    pub arch_bits: u32,
    pub arch_bytes: u32,
    /// The default engine's `default_strict_block_end` and `_default_opt_level`.
    pub strict_block_end: bool,
    pub default_opt_level: i32,
    ir_cache: IrCache,
    pub stats: IndexMap<String, u64>,
}

impl ResolveCx {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        snap: Arc<Snapshot>,
        lifter: Py<VexLifter>,
        sim_procedures: Py<PyDict>,
        extra_stop_points: Py<PyAny>,
        exec_regions: Vec<(u64, u64)>,
        arch_bits: u32,
        arch_bytes: u32,
        strict_block_end: bool,
        default_opt_level: i32,
    ) -> Self {
        ResolveCx {
            snap,
            lifter,
            sim_procedures,
            extra_stop_points,
            exec_regions,
            arch_bits,
            arch_bytes,
            strict_block_end,
            default_opt_level,
            ir_cache: IrCache {
                cur: HashMap::new(),
                old: HashMap::new(),
                cap: 2048,
                hits: 0,
                misses: 0,
            },
            stats: IndexMap::new(),
        }
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
        let result = lifter.core.lift_ir(spec.addr, spec.max_size, &[], &opts, &mut is_stop);
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
