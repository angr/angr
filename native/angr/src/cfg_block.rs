//! CFGFast's per-block scan in Rust.
//!
//! Exposed as `angr.rustylib.cfg_block`. `BlockScanner.run` pops jobs off the `ScanState` queue and processes each
//! one the way `CFGFast._scan_block` does: `_generate_cfgnode` (block-size limits, lifting, nodecode handling, node
//! record), the graph edge from the job's source, function edges and the function node, returning bookkeeping,
//! data references, successor enumeration and `_create_jobs`/`_create_job_call`. No Python object is created for
//! the common case.
//!
//! Python keeps every decision that needs its state:
//! - A job whose processing cannot start in Rust (hooked or syscall addresses, lift fallbacks, ...) is left at the
//!   front of the queue untouched and `run` returns True; CFGFast then processes it with its own code. The decision
//!   is made before the job has any side effect.
//! - A successor whose job creation needs Python (indirect exits, syscalls, hooked or PLT callees, ...) is handed to
//!   `CFGFast._create_jobs` in place, so the job order stays the same.
//! - Data references are buffered and applied by `CFGFast._apply_rust_data_refs` (MemoryData, xrefs) before any
//!   Python code runs; their SegmentList effects happen here, in order.

use std::collections::BTreeMap;
use std::time::Instant;

use indexmap::IndexMap;
use pyo3::exceptions::PyTypeError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyList, PySet, PyTuple};
use pyo3::{PyTraverseError, PyVisit};
use rustc_hash::FxHashSet;

use crate::cfg_graph::{BYTES_LOADER, BYTES_MANUAL, CfgGraph, NodeFields};
use crate::cfg_jobs::{
    FuncEdge, JK_BORING, JK_CALL, JK_EXCEPTION, JK_FAKERET, JK_RET, JobRec, JobType, NodeRef,
    ScanState, SrcNode, cpython_set_order, jk_from_vex, jk_intern, jk_name, py_hash_u64,
};
use crate::cfg_scan::{BackendKind, LinearSweep, LoaderSnapshot, addr_in_regions};
use crate::function_graph::NodeKind;
use crate::ijr::chain::{ResolverChain, TimelessScan};
use crate::recovery_functions::{NodeSpec, RecoveryFunctions};
use crate::segmentlist::SegmentList;
use crate::vexlift::{
    IJK_BORING, IJK_NODECODE, LiftOptions, LiftSummary, NextExpr, VexLifter, data_ref_type_str,
    jumpkind_from_name,
};

const DEFAULT_STATEMENT: i64 = -2;
const VEX_IRSB_MAX_SIZE: i64 = 400;

const SORT_CODE: &str = "code";
const SORT_NODECODE: &str = "nodecode";
const SORT_ALIGNMENT: &str = "alignment";
const SORT_UNKNOWN: &str = "unknown";
const SORT_INTEGER: &str = "integer";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArchKind {
    Amd64,
    X86,
    Mips,
    /// ARMEL, ARMHF, ARMCortexM: addresses carry the THUMB bit.
    Arm,
    /// No architecture-specific per-block processing (AArch64, PPC, ...).
    Other,
}

/// `project.simos.is_syscall_addr`
enum SyscallCheck {
    Never,
    /// `SimUserland`: `(addr - kernel_base) % align == 0 and (addr - kernel_base) // align <= max_number`
    Userland {
        kernel_base: u64,
        align: u64,
        max_number: u64,
    },
    /// `SimWindows`: membership in the syscall handler dict.
    Dict(Py<PyDict>),
    Callback(Py<PyAny>),
}

/// Constants of one CFGFast run.
struct Config {
    arch: ArchKind,
    bits: u32,
    arch_bytes: i64,
    instruction_alignment: u64,
    branch_delay_slot: bool,
    call_pushes_ret: bool,
    skip_unmapped_addrs: bool,
    resolve_indirect_jumps: bool,
    collect_data_ref: bool,
    fold_ro_const_loads: bool,
    repeating_threshold: u64,
    nop_byte: Option<u8>,
    padding_bytes: Vec<u8>,
    ibt_marker: Option<Vec<u8>>,
    /// `_exception_handling_by_endaddr`: end address -> handler address.
    exc_by_end: BTreeMap<u64, Option<u64>>,
    /// `MEMORY_DATA_SORTS` without None.
    memory_data_sorts: FxHashSet<String>,
    syscall: SyscallCheck,
    /// ARM `CFGArchOptions`: ret_jumpkind_heuristics, pattern_match_ifuncs, has_arm_code
    arm_ret_heuristics: bool,
    arm_pattern_match_ifuncs: bool,
    arm_has_arm_code: bool,
    check_funcret_max_job: u64,
    /// MIPS32: ($gp offset, $t9 offset) for the $gp prologue scan.
    mips32_gp: Option<(i32, i32)>,
    big_endian: bool,
}

/// A data reference to be recorded by `CFGFast._apply_rust_data_refs`.
enum DataRefRec {
    /// `_add_data_reference` of a loadable address: (irsb_addr, stmt_idx, ins_addr, data_addr, data_size, sort)
    Memory(u64, i64, u64, u64, Option<i64>, Option<String>),
    /// A reference to the end of a main-object segment: (irsb_addr, stmt_idx, ins_addr, data_addr)
    SegmentBoundary(u64, i64, u64, u64),
}

/// Python containers of the CFGFast object, fetched at the start of every `run` (CFGFast reassigns some of them).
struct Ctx<'py> {
    cfg: Bound<'py, PyAny>,
    sim_procedures: Bound<'py, PyDict>,
    blockid_to_blockkey: Bound<'py, PyDict>,
    node_addrs: Option<Bound<'py, PyAny>>,
    updated_nonreturning: Option<Bound<'py, PySet>>,
    function_exits: Bound<'py, PyAny>,
    block_addrs_with_return: Bound<'py, PySet>,
    func_addrs_from_symbols: Bound<'py, PyAny>,
    eh_frame_boundary_addrs: Bound<'py, PyAny>,
    used_prologue_addrs: Bound<'py, PyAny>,
    known_thunks: Bound<'py, PyDict>,
    seg_list: Bound<'py, SegmentList>,
    /// `(time.perf_counter, PROGRESS_NOTIFY_INTERVAL)` when CFGFast reports progress.
    progress: Option<(Bound<'py, PyAny>, f64)>,
    /// ARM: `_decoding_assumptions`, `_decoding_assumption_relations`, `_function_prologue_addrs`
    arm: Option<ArmCtx<'py>>,
}

struct ArmCtx<'py> {
    assumptions: Bound<'py, PyAny>,
    relations: Bound<'py, PyAny>,
    prologue_addrs: Bound<'py, PyAny>,
}

/// How many jobs `run` processes between two checks of its time budget.
const BUDGET_CHECK_JOBS: u64 = 64;

/// What a job needs, decided before any of its side effects.
enum Plan {
    /// Python processes the job.
    Escape(&'static str),
    /// A node exists at the job address already.
    Existing { cur: u64, id: u64, func: u64 },
    /// `_generate_cfgnode` gives up without creating a node; `occupy` is its only effect.
    NoNode {
        occupy: Option<(u64, u64, &'static str)>,
    },
    Lifted {
        cur: u64,
        summary: Box<LiftSummary>,
        next_func_addr: Option<u64>,
        next_func_adj: u64,
    },
}

/// A successor as `_scan_irsb` enumerates it.
#[derive(Clone, Copy)]
struct Succ {
    stmt_idx: i64,
    ins_addr: Option<u64>,
    target: Option<u64>,
    jk: u16,
}

/// The block being processed.
struct Block<'a> {
    addr: u64,
    id: u64,
    size: u64,
    ins_count: usize,
    last_ins: Option<u64>,
    func: u64,
    summary: &'a LiftSummary,
}

impl Block<'_> {
    fn src(&self) -> SrcNode {
        SrcNode {
            addr: self.addr,
            size: self.size as i64,
            simproc: false,
            node: NodeRef::Id(self.id),
        }
    }
}

/// What the escape-free indirect-jump path needs besides the chain.
struct IjrHook {
    chain: Py<ResolverChain>,
    /// `_resolve_plt` runs (symbolic execution) for every Boring jump: no ELF object is loaded.
    plt_all: bool,
    /// `obj.reverse_plt` addresses of the ELF objects, where `_resolve_plt` runs.
    reverse_plt: FxHashSet<u64>,
    /// `cfg.indirect_jumps`
    indirect_jumps: Py<PyDict>,
}

#[pyclass(module = "angr.rustylib.cfg_block")]
pub struct BlockScanner {
    scan: Py<ScanState>,
    graph: Py<CfgGraph>,
    store: Py<RecoveryFunctions>,
    lifter: Py<VexLifter>,
    snapshot: Py<LoaderSnapshot>,
    sweep: Py<LinearSweep>,
    resolver: Py<PyAny>,
    /// `project.arch.registers`: name -> (offset, size)
    arch_registers: Py<PyAny>,
    conf: Config,
    data_refs: Vec<DataRefRec>,
    new_node_addrs: Vec<u64>,
    /// `(addr, lifted size)` of each new node in creation order, for `cfg._cfb_add_rust_blocks`; None without a CFB.
    cfb_blocks: Option<Vec<(u64, u32)>>,
    stats: IndexMap<String, u64>,
    /// `_eh_frame_boundary_addrs_sorted` and the list object it was copied from.
    eh_sorted: Vec<u64>,
    eh_list: Option<Py<PyAny>>,
    /// The Rust resolver chain, when indirect jumps can be resolved without escaping to `_create_jobs`.
    ijr: Option<IjrHook>,
    /// Nanoseconds spent in: lifting, Python callbacks, flushes.
    t_lift: std::sync::atomic::AtomicU64,
    t_callback: std::sync::atomic::AtomicU64,
    t_flush: std::sync::atomic::AtomicU64,
}

impl BlockScanner {
    fn count(&mut self, key: &str) {
        match self.stats.get_mut(key) {
            Some(v) => *v += 1,
            None => {
                self.stats.insert(key.to_owned(), 1);
            }
        }
    }

    fn is_syscall_addr(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        Ok(match &self.conf.syscall {
            SyscallCheck::Never => false,
            SyscallCheck::Userland {
                kernel_base,
                align,
                max_number,
            } => {
                if addr < *kernel_base {
                    false
                } else {
                    let off = addr - kernel_base;
                    off.is_multiple_of(*align) && off / align <= *max_number
                }
            }
            SyscallCheck::Dict(d) => d.bind(py).contains(addr)?,
            SyscallCheck::Callback(f) => f.call1(py, (addr,))?.extract(py)?,
        })
    }

    fn fetch<'py>(&mut self, cfg: &Bound<'py, PyAny>) -> PyResult<Ctx<'py>> {
        let py = cfg.py();
        // _eh_frame_boundary_addrs_sorted is replaced, not mutated, when it changes
        let eh = cfg.getattr(intern!(py, "_eh_frame_boundary_addrs_sorted"))?;
        let eh_len = eh.len()?;
        let stale = match &self.eh_list {
            Some(l) => !l.bind(py).is(&eh) || self.eh_sorted.len() != eh_len,
            None => true,
        };
        if stale {
            self.eh_sorted = eh.extract()?;
            self.eh_list = Some(eh.unbind());
        }
        let model = cfg.getattr(intern!(py, "_model"))?;
        let node_addrs = model.getattr(intern!(py, "_node_addrs"))?;
        let updated = cfg.getattr(intern!(py, "_updated_nonreturning_functions"))?;
        let progress = if cfg.getattr(intern!(py, "_show_progressbar"))?.is_truthy()?
            || !cfg.getattr(intern!(py, "_progress_callback"))?.is_none()
        {
            let interval: f64 = py
                .import(intern!(py, "angr.analyses.cfg.cfg_fast"))?
                .getattr("PROGRESS_NOTIFY_INTERVAL")?
                .extract()?;
            Some((
                py.import(intern!(py, "time"))?
                    .getattr(intern!(py, "perf_counter"))?,
                interval,
            ))
        } else {
            None
        };
        Ok(Ctx {
            cfg: cfg.clone(),
            sim_procedures: cfg
                .getattr(intern!(py, "project"))?
                .getattr(intern!(py, "_sim_procedures"))?
                .cast_into::<PyDict>()?,
            blockid_to_blockkey: model
                .getattr(intern!(py, "_blockid_to_blockkey"))?
                .cast_into::<PyDict>()?,
            node_addrs: if node_addrs.is_none() {
                None
            } else {
                Some(node_addrs)
            },
            updated_nonreturning: if updated.is_none() {
                None
            } else {
                Some(updated.cast_into::<PySet>()?)
            },
            function_exits: cfg.getattr(intern!(py, "_function_exits"))?,
            block_addrs_with_return: model
                .getattr(intern!(py, "_block_addrs_with_return"))?
                .cast_into::<PySet>()?,
            func_addrs_from_symbols: cfg
                .getattr(intern!(py, "_function_addresses_from_symbols"))?,
            eh_frame_boundary_addrs: cfg.getattr(intern!(py, "_eh_frame_boundary_addrs"))?,
            used_prologue_addrs: cfg.getattr(intern!(py, "_used_function_prologue_addrs"))?,
            known_thunks: cfg
                .getattr(intern!(py, "_known_thunks"))?
                .cast_into::<PyDict>()?,
            seg_list: cfg
                .getattr(intern!(py, "_seg_list"))?
                .cast_into::<SegmentList>()?,
            progress,
            arm: if self.conf.arch == ArchKind::Arm {
                Some(ArmCtx {
                    assumptions: cfg.getattr(intern!(py, "_decoding_assumptions"))?,
                    relations: cfg.getattr(intern!(py, "_decoding_assumption_relations"))?,
                    prologue_addrs: cfg.getattr(intern!(py, "_function_prologue_addrs"))?,
                })
            } else {
                None
            },
        })
    }

    /// Hands buffered effects to Python; must run before any Python code that may read them.
    fn flush(&mut self, ctx: &Ctx<'_>) -> PyResult<()> {
        let t0 = Instant::now();
        let r = self.flush_inner(ctx);
        self.t_flush.fetch_add(
            t0.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        r
    }

    fn flush_inner(&mut self, ctx: &Ctx<'_>) -> PyResult<()> {
        let py = ctx.cfg.py();
        if let Some(blocks) = &mut self.cfb_blocks
            && !blocks.is_empty()
        {
            let blocks = std::mem::take(blocks);
            ctx.cfg
                .call_method1(intern!(py, "_cfb_add_rust_blocks"), (blocks,))?;
        }
        if !self.new_node_addrs.is_empty() {
            let addrs = std::mem::take(&mut self.new_node_addrs);
            if let Some(na) = &ctx.node_addrs {
                na.call_method1(intern!(py, "update"), (addrs,))?;
            }
        }
        if !self.data_refs.is_empty() {
            let recs = std::mem::take(&mut self.data_refs);
            let items = PyList::empty(py);
            for r in recs {
                let t = match r {
                    DataRefRec::Memory(irsb_addr, stmt_idx, ins_addr, data_addr, size, sort) => {
                        (false, irsb_addr, stmt_idx, ins_addr, data_addr, size, sort)
                            .into_pyobject(py)?
                    }
                    DataRefRec::SegmentBoundary(irsb_addr, stmt_idx, ins_addr, data_addr) => (
                        true,
                        irsb_addr,
                        stmt_idx,
                        ins_addr,
                        data_addr,
                        Some(0i64),
                        None::<String>,
                    )
                        .into_pyobject(py)?,
                };
                items.append(t)?;
            }
            ctx.cfg
                .call_method1(intern!(py, "_apply_rust_data_refs"), (items,))?;
        }
        Ok(())
    }

    fn py_set_contains(set: &Bound<'_, PyAny>, addr: u64) -> PyResult<bool> {
        set.contains(addr)
    }

    fn is_hooked(ctx: &Ctx<'_>, addr: u64) -> PyResult<bool> {
        ctx.sim_procedures.contains(addr)
    }

    // ------------------------------------------------------------------------------------------------------------
    // Planning (no side effects)
    // ------------------------------------------------------------------------------------------------------------

    fn plan(&self, ctx: &Ctx<'_>, rec: &JobRec) -> PyResult<Plan> {
        let py = ctx.cfg.py();
        let addr = rec.addr;
        let sweep = self.sweep.bind(py).borrow();
        let sweep = &sweep.inner;
        if !sweep.inside_regions(addr) {
            return Ok(Plan::Escape("outside_regions"));
        }
        if let Some(src) = &rec.src
            && !matches!(src.node, NodeRef::Id(_))
        {
            return Ok(Plan::Escape("orphan_source"));
        }

        // _scan_block
        let mut cur = rec.func_addr;
        if Self::py_set_contains(&ctx.func_addrs_from_symbols, addr)?
            || Self::py_set_contains(&ctx.eh_frame_boundary_addrs, addr)?
        {
            cur = addr;
        }
        if Self::is_hooked(ctx, addr)? || self.is_syscall_addr(py, addr)? {
            return Ok(Plan::Escape("hooked_or_syscall"));
        }

        // _generate_cfgnode
        let graph = self.graph.bind(py).get();
        if graph.has_addr(addr)? {
            let id = graph.first_node_at_addr(addr)?.unwrap();
            return Ok(match graph.node_func(id)? {
                Some(func) => Plan::Existing { cur, id, func },
                None => Plan::Escape("existing_node_without_function"),
            });
        }
        let is_arm = self.conf.arch == ArchKind::Arm;
        let real_addr = if is_arm { addr & !1 } else { addr };

        if is_arm && ctx.seg_list.borrow().occupied_by_sort(addr).as_deref() == Some(SORT_CODE) {
            // may split an existing node of the other mode (get_any_node(anyaddr=True))
            return Ok(Plan::Escape("arm_inside_code"));
        }

        if self.conf.repeating_threshold > 0 {
            let run = sweep.repeating_byte_run_length(
                real_addr,
                self.conf.repeating_threshold,
                self.conf.nop_byte,
            );
            if run > 0 {
                let snap = &self.snapshot.bind(py).get().inner;
                let is_padding = snap
                    .load_byte(real_addr)
                    .is_some_and(|b| self.conf.padding_bytes.contains(&b));
                let sort = if is_padding {
                    SORT_ALIGNMENT
                } else {
                    SORT_NODECODE
                };
                return Ok(Plan::NoNode {
                    occupy: Some((real_addr, run, sort)),
                });
            }
        }

        let mut distance: i64 = VEX_IRSB_MAX_SIZE;
        if !self.conf.exc_by_end.is_empty()
            && let Some((&end, _)) = self.conf.exc_by_end.range(real_addr..).next()
        {
            distance = distance.min((end - real_addr) as i64);
        }

        let snap = &self.snapshot.bind(py).get().inner;
        if let Some(oi) = snap.find_object_containing(addr, false) {
            let obj = &snap.objects[oi];
            if obj.kind == BackendKind::MachO {
                return Ok(Plan::Escape("macho"));
            }
            let has_executable_section = obj.sections.iter().any(|s| s.is_executable);
            let section = obj.find_section_containing(addr);
            let mut segment = None;
            let mut has_executable_segment = false;
            if section.is_none() {
                has_executable_segment = obj.segments.iter().any(|s| s.is_executable);
                segment = obj.find_segment_containing(addr);
            }
            if has_executable_section
                && section.is_none()
                && has_executable_segment
                && segment.is_none()
                && self.conf.skip_unmapped_addrs
            {
                return Ok(Plan::NoNode { occupy: None });
            }
            if let Some(si) = section {
                let s = &obj.sections[si];
                if !s.is_executable {
                    return Ok(Plan::NoNode { occupy: None });
                }
                distance =
                    (s.end() as i128 - real_addr as i128).min(VEX_IRSB_MAX_SIZE as i128) as i64;
            } else if let Some(si) = segment {
                let s = &obj.segments[si];
                if !s.is_executable {
                    return Ok(Plan::NoNode { occupy: None });
                }
                distance =
                    (s.end() as i128 - real_addr as i128).min(VEX_IRSB_MAX_SIZE as i128) as i64;
            }
        }

        let store = self.store.bind(py).borrow();
        let next_func_addr = store.ceiling_addr(addr + 1);
        let mut next_func_adj = 0u64;
        if let Some(nfa) = next_func_addr {
            if self.conf.instruction_alignment == 1
                && Self::py_set_contains(&ctx.used_prologue_addrs, nfa)?
            {
                next_func_adj = 15;
            }
            let nfa_real = if is_arm { nfa & !1 } else { nfa };
            let distance_to_func = (nfa_real + next_func_adj) as i64 - real_addr as i64;
            if distance_to_func != 0 {
                distance = distance.min(distance_to_func);
            }
        }
        drop(store);

        let eh = &self.eh_sorted;
        if !eh.is_empty() {
            let idx = eh.partition_point(|&a| a <= real_addr);
            if idx < eh.len() {
                distance = distance.min((eh[idx] - real_addr) as i64);
            }
        }

        if distance < 0 {
            return Ok(Plan::Escape("negative_distance"));
        }
        let next_noncode = {
            let seg = ctx.seg_list.borrow();
            let sorts: std::collections::HashSet<Option<String>> =
                [Some(SORT_CODE.to_owned())].into_iter().collect();
            seg.next_pos_with_sort_not_in(addr, sorts, Some(distance as u64))
        };
        if let Some(nc) = next_noncode {
            distance = distance.min(nc as i64 - real_addr as i64);
        }

        if let Some(arm) = &ctx.arm {
            if Self::py_set_contains(&arm.assumptions, real_addr)? {
                return Ok(Plan::Escape("arm_decoding_assumption"));
            }
            if !self.conf.arm_has_arm_code && addr.is_multiple_of(2) {
                return Ok(Plan::NoNode {
                    occupy: Some((real_addr, 2, SORT_NODECODE)),
                });
            }
            if rec.job_type == JobType::CompleteScanning {
                return Ok(Plan::Escape("arm_complete_scanning"));
            }
        }

        // _get_initial_registers: X86 seeds the PIE pc register, MIPS t9 and gp, ARM r4
        let mut initial_regs: Vec<(u32, u32, u64)> = Vec::new();
        if is_arm && addr != cur {
            let store = self.store.bind(py).borrow();
            if store.contains(cur) && store.info_contains(cur, "constant_r4")? {
                let Some(r4) = store.info_int(cur, "constant_r4")? else {
                    return Ok(Plan::Escape("arm_constant_r4_value"));
                };
                let (off, size): (u32, u32) =
                    self.arch_registers.bind(py).get_item("r4")?.extract()?;
                initial_regs.push((off, size, r4 as u64));
            }
        }
        let mut mips_gp_scan = None;
        if self.conf.arch == ArchKind::Mips {
            let regs = self.arch_registers.bind(py);
            let (t9_off, t9_size): (u32, u32) = regs.get_item("t9")?.extract()?;
            initial_regs.push((t9_off, t9_size, cur));
            let store = self.store.bind(py).borrow();
            let has_gp = store.contains(cur) && store.info_contains(cur, "gp")?;
            if let Some((gp_off, t9_off)) = self.conf.mips32_gp
                && !has_gp
                && (0..15 * 4).contains(&(addr as i128 - cur as i128))
            {
                mips_gp_scan = Some((gp_off, t9_off, cur));
            }
            if has_gp {
                let Some(gp) = store.info_int(cur, "gp")? else {
                    return Ok(Plan::Escape("mips_gp_value"));
                };
                let (gp_off, gp_size): (u32, u32) = regs.get_item("gp")?.extract()?;
                initial_regs.push((gp_off, gp_size, gp as u64));
            }
        }
        if self.conf.arch == ArchKind::X86 {
            let store = self.store.bind(py).borrow();
            if rec.jumpkind == JK_FAKERET
                && let Some(rs) = rec.returning_source
                && store.contains(rs)
                && store.info_contains(rs, "get_pc")?
            {
                return Ok(Plan::Escape("x86_get_pc_return"));
            }
            if store.contains(cur) && store.info_contains(cur, "pc_reg")? {
                let pc_reg = store.info_get(py, cur, "pc_reg")?.unwrap().into_bound(py);
                drop(store);
                let reg = pc_reg.get_item("reg")?;
                let value: u64 = pc_reg.get_item("value")?.extract()?;
                let (offset, size): (u32, u32) =
                    self.arch_registers.bind(py).get_item(reg)?.extract()?;
                initial_regs.push((offset, size, value));
            }
        }

        let lifter = self.lifter.bind(py).borrow();
        let lock = lifter.lock.bind(py);
        lock.call_method0(intern!(py, "acquire"))?;
        let t0 = Instant::now();
        let opts = LiftOptions::cfgfast_main(self.conf.fold_ro_const_loads);
        let result = match mips_gp_scan {
            Some(g) => lifter
                .core
                .lift_block_mips_gp(addr, distance, &initial_regs, &opts, g),
            None => lifter.core.lift_block(addr, distance, &initial_regs, &opts),
        };
        self.t_lift.fetch_add(
            t0.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        lock.call_method0(intern!(py, "release"))?;
        match result {
            Ok(summary) if is_arm && (summary.size == 0 || summary.jumpkind == IJK_NODECODE) => {
                Ok(Plan::Escape("arm_nodecode"))
            }
            Ok(summary) => Ok(Plan::Lifted {
                cur,
                summary: Box::new(summary),
                next_func_addr,
                next_func_adj,
            }),
            Err(fb) => Ok(Plan::Escape(match fb.name() {
                "no_backer" => "lift:no_backer",
                "unsupported_backer" => "lift:unsupported_backer",
                "empty_window" => "lift:empty_window",
                "offset_overflow" => "lift:offset_overflow",
                "lift_failed" => "lift:lift_failed",
                "no_instructions" => "lift:no_instructions",
                "too_many_exits" => "lift:too_many_exits",
                "partial_nodecode" => "lift:partial_nodecode",
                "unsupported_const" => "lift:unsupported_const",
                _ => "lift:other",
            })),
        }
    }

    // ------------------------------------------------------------------------------------------------------------
    // Committing a job
    // ------------------------------------------------------------------------------------------------------------

    fn seg_occupy(ctx: &Ctx<'_>, addr: u64, size: u64, sort: &str) {
        ctx.seg_list
            .borrow_mut()
            .occupy(addr, size, Some(sort.to_owned()));
    }

    /// The rest of `_generate_cfgnode` after the lift: returns the new node's id, or None.
    fn create_node(
        &mut self,
        ctx: &Ctx<'_>,
        rec: &JobRec,
        cur: u64,
        summary: &mut LiftSummary,
        next_func_addr: Option<u64>,
        next_func_adj: u64,
    ) -> PyResult<Option<u64>> {
        let py = ctx.cfg.py();
        let addr = rec.addr;
        let is_arm = self.conf.arch == ArchKind::Arm;
        let is_thumb = is_arm && addr % 2 == 1;
        let real_addr = if is_arm { addr & !1 } else { addr };
        if let Some(arm) = &ctx.arm {
            // track the decoding assumption of the block
            let src_realaddr = match &rec.src {
                Some(src) => {
                    let a = src.addr & 0xFFFF_FFFE;
                    Self::py_set_contains(&arm.assumptions, a)?.then_some(Some(a))
                }
                None => matches!(
                    rec.job_type,
                    JobType::FunctionPrologue | JobType::CompleteScanning
                )
                .then_some(None),
            };
            if let Some(src_realaddr) = src_realaddr {
                self.flush(ctx)?;
                ctx.cfg.call_method1(
                    intern!(py, "_rust_decoding_assumption"),
                    (
                        src_realaddr,
                        real_addr,
                        summary.size.max(1),
                        is_thumb,
                        jk_name(rec.jumpkind),
                    ),
                )?;
            }
        }
        let is_nodecode = summary.size == 0 || summary.jumpkind == IJK_NODECODE;
        if is_nodecode {
            let occupied = ctx.seg_list.borrow().occupied_by_sort(real_addr);
            if let Some(s) = &occupied
                && !s.is_empty()
                && s != SORT_CODE
            {
                return Ok(None);
            }
            let irsb_size = summary.size as u64;
            let mut valid_ins = false;
            let mut nodecode_size = 1u64;
            // ud2 is decoded by VEX and counted towards the block size
            let snap = &self.snapshot.bind(py).get().inner;
            if let Some(b) = snap.load_bytes(real_addr, irsb_size as usize)
                && b.len() >= 2
                && b[b.len() - 2..] == [0x0f, 0x0b]
            {
                valid_ins = true;
                nodecode_size = 0;
            }
            if !valid_ins {
                Self::seg_occupy(ctx, real_addr, irsb_size, SORT_CODE);
                Self::seg_occupy(ctx, real_addr + irsb_size, nodecode_size, SORT_NODECODE);
                if irsb_size == 0 {
                    return Ok(None);
                }
            }
            Self::seg_occupy(ctx, real_addr, irsb_size, SORT_CODE);
            if nodecode_size > 0 {
                Self::seg_occupy(ctx, real_addr + irsb_size, nodecode_size, SORT_NODECODE);
            }
        }

        // the CFB gets the block as lifted, before the shrink below
        let lifted_size = summary.size;
        if let Some(nfa) = next_func_addr
            && next_func_adj > 0
            && summary.addr + summary.size as u64 >= nfa
            && summary.instruction_addresses.contains(&nfa)
        {
            summary.size = ((if is_arm { nfa & !1 } else { nfa }) - real_addr) as u32;
            summary.instruction_addresses.retain(|&a| a < nfa);
            summary.data_refs.retain(|d| d.ins_addr < nfa);
            summary.exits.retain(|e| e.ins_addr < nfa);
            summary.next = NextExpr::Const(nfa);
        }

        if rec.job_type == JobType::CompleteScanning
            && addr == cur
            && summary.jumpkind == IJK_NODECODE
        {
            Self::seg_occupy(ctx, real_addr, (summary.size as u64).max(1), SORT_NODECODE);
            return Ok(None);
        }

        if summary.size > 0 {
            Self::seg_occupy(ctx, real_addr, summary.size as u64, SORT_CODE);
        }

        // CFGNode(addr, size, ..., function_address=cur, irsb=summary, byte_string=<loader bytes>) + model.add_node
        let ia = &summary.instruction_addresses;
        let (ins_base, ins_sizes) = if ia.is_empty() {
            (0, Vec::new())
        } else {
            let mut sizes = Vec::with_capacity(ia.len());
            for w in ia.windows(2) {
                let d = w[1].wrapping_sub(w[0]);
                if d > 255 {
                    return Err(PyTypeError::new_err(
                        "instruction size does not fit in a byte",
                    ));
                }
                sizes.push(d as u8);
            }
            sizes.push(0);
            (ia[0], sizes)
        };
        let fields = NodeFields {
            func: Some(cur),
            ins_base,
            ins_sizes,
            thumb: is_thumb,
            is_syscall: false,
            no_ret: Some(false),
            bytes_mode: BYTES_LOADER,
            manual_bytes: None,
            name: None,
            simprocedure_name: None,
        };
        let size = summary.size as i64;
        let id = self
            .graph
            .bind(py)
            .get()
            .add_node_fields(addr, size, &fields)?;
        ctx.blockid_to_blockkey.set_item(addr, (addr, size))?;
        self.new_node_addrs.push(addr);
        if let Some(blocks) = &mut self.cfb_blocks {
            blocks.push((addr, lifted_size));
        }
        Ok(Some(id))
    }

    fn node_spec(&self, ctx: &Ctx<'_>, id: u64) -> PyResult<NodeSpec> {
        let py = ctx.cfg.py();
        let g = self.graph.bind(py).get();
        let (addr, size, simprocedure_name) = g.node_view(id)?;
        if let Some(hooker) = ctx.sim_procedures.get_item(addr)? {
            let length = hooker
                .getattr(intern!(py, "kwargs"))?
                .call_method1(intern!(py, "get"), (intern!(py, "length"), 0))?;
            let length: u32 = if length.is_truthy()? {
                length.extract()?
            } else {
                0
            };
            return Ok((NodeKind::Hook, addr, length, false));
        }
        if simprocedure_name.is_none() && !g.node_is_syscall(id)? {
            return Ok((NodeKind::Block, addr, size as u32, g.node_thumb(id)?));
        }
        let kwargs = PyDict::new(py);
        kwargs.set_item(
            intern!(py, "cfg_node"),
            self.resolver.bind(py).call1((id,))?,
        )?;
        ctx.cfg
            .call_method(intern!(py, "_snippet_spec"), (), Some(&kwargs))?
            .extract()
    }

    fn set_returning_true(&self, py: Python<'_>, func: u64) -> PyResult<()> {
        let mut store = self.store.bind(py).borrow_mut();
        if store.returning(func)? != Some(true) {
            store.set_returning(func, Some(true))?;
        }
        Ok(())
    }

    /// One job, already planned; returns the jobs `_scan_block` returns.
    fn commit(&mut self, ctx: &Ctx<'_>, rec: &JobRec, plan: Plan) -> PyResult<Vec<JobRec>> {
        let py = ctx.cfg.py();
        match plan {
            Plan::Escape(_) => unreachable!(),
            Plan::NoNode { occupy } => {
                if let Some((a, s, sort)) = occupy {
                    Self::seg_occupy(ctx, a, s, sort);
                }
                Ok(Vec::new())
            }
            Plan::Existing { cur, id, func } => {
                let func = self.cxx_frame_handler3(ctx, rec.addr, id, func)?;
                self.scan_tail(ctx, rec, cur, id, func, None)?;
                Ok(Vec::new())
            }
            Plan::Lifted {
                cur,
                mut summary,
                next_func_addr,
                next_func_adj,
            } => {
                let Some(id) =
                    self.create_node(ctx, rec, cur, &mut summary, next_func_addr, next_func_adj)?
                else {
                    return Ok(Vec::new());
                };
                let _ = py;
                let func = self.cxx_frame_handler3(ctx, rec.addr, id, cur)?;
                self.scan_tail(ctx, rec, cur, id, func, Some(*summary))
            }
        }
    }

    /// `_scan_irsb` after `_generate_cfgnode`.
    fn scan_tail(
        &mut self,
        ctx: &Ctx<'_>,
        rec: &JobRec,
        current_func_addr: u64,
        id: u64,
        function_addr: u64,
        summary: Option<LiftSummary>,
    ) -> PyResult<Vec<JobRec>> {
        let py = ctx.cfg.py();
        let addr = rec.addr;
        let scan = self.scan.bind(py);

        // cfg_job.apply_function_edges
        if !rec.func_edges.is_empty() {
            ScanState::apply_edges(scan, &ctx.cfg, &rec.func_edges)?;
        }

        // _graph_add_edge
        if let Some(src) = &rec.src {
            let NodeRef::Id(src_id) = src.node else {
                unreachable!()
            };
            self.graph.bind(py).get().add_edge(
                py,
                src_id,
                id,
                7,
                Some(jk_name(rec.jumpkind)),
                rec.src_ins_addr,
                rec.src_stmt_idx,
            )?;
        }

        // _function_add_node
        let spec = self.node_spec(ctx, id)?;
        RecoveryFunctions::add_node(self.store.bind(py), function_addr, spec, None)?;

        let returning = self.store.bind(py).borrow().returning(function_addr)?;
        if returning != Some(true)
            && let Some(set) = &ctx.updated_nonreturning
        {
            set.add(function_addr)?;
        }

        // tail-call hack
        if current_func_addr != function_addr && returning.is_some() {
            let mut store = self.store.bind(py).borrow_mut();
            if store.contains(current_func_addr) {
                if store.returning(current_func_addr)? != returning {
                    store.set_returning(current_func_addr, returning)?;
                }
                drop(store);
                if returning == Some(true) {
                    scan.borrow_mut()
                        .pending
                        .add_returning_function(Some(current_func_addr));
                }
            }
        }

        // traced
        let is_arm = self.conf.arch == ArchKind::Arm;
        let real_addr = if is_arm { addr & !1 } else { addr };
        {
            let mut s = scan.borrow_mut();
            if s.traced.contains(&real_addr) {
                return Ok(Vec::new());
            }
            s.traced.insert(real_addr);
        }
        let Some(mut summary) = summary else {
            return Ok(Vec::new());
        };

        self.block_arch_specific(ctx, addr, id, function_addr, rec.gp, &mut summary)?;
        let summary = &summary;

        let block = Block {
            addr,
            id,
            size: summary.size as u64,
            ins_count: summary.instruction_addresses.len(),
            last_ins: summary.instruction_addresses.last().copied(),
            func: function_addr,
            summary,
        };

        if self.conf.collect_data_ref && !summary.data_refs.is_empty() {
            self.process_data_refs(ctx, summary)?;
        }

        // successors
        let mut succs: Vec<Succ> = summary
            .conditional_successors(self.conf.branch_delay_slot)
            .into_iter()
            .map(|s| Succ {
                stmt_idx: s.stmt_idx as i64,
                ins_addr: Some(s.ins_addr),
                target: Some(s.dst),
                jk: jk_from_vex(s.jumpkind),
            })
            .collect();
        let default_ins = self.block_branch_ins_addr(summary);
        let next = match summary.next {
            NextExpr::Const(v) => Some(v),
            _ => None,
        };
        succs.push(Succ {
            stmt_idx: DEFAULT_STATEMENT,
            ins_addr: default_ins,
            target: next,
            jk: jk_from_vex(summary.jumpkind),
        });
        if let Some(handler) = self.conf.exc_by_end.get(&(addr + summary.size as u64)) {
            succs.push(Succ {
                stmt_idx: DEFAULT_STATEMENT,
                ins_addr: default_ins,
                target: *handler,
                jk: JK_EXCEPTION,
            });
        }

        if is_arm {
            succs = self.arm_post_process_successors(ctx, &block, succs)?;
        }

        let mut entries = Vec::new();
        for i in 0..succs.len() {
            let n = entries.len();
            self.create_jobs(ctx, &block, &succs, i, &mut entries)?;
            if let Some(arm) = &ctx.arm {
                for e in &entries[n..] {
                    if e.jumpkind == JK_BORING || e.jumpkind == JK_FAKERET {
                        arm.relations.call_method1(
                            intern!(py, "add_edge"),
                            (real_addr, e.addr & 0xFFFF_FFFE),
                        )?;
                    }
                }
            }
        }
        Ok(entries)
    }

    fn block_branch_ins_addr(&self, s: &LiftSummary) -> Option<u64> {
        let ia = &s.instruction_addresses;
        let last = *ia.last()?;
        if !self.conf.branch_delay_slot || ia.len() == 1 {
            return Some(last);
        }
        if s.addr + s.size as u64 - last > last - ia[ia.len() - 2] {
            return Some(last);
        }
        Some(ia[ia.len() - 2])
    }

    /// `CFGFast._mips_determine_function_gp` from the lift-time scan; None when Python must decide.
    fn mips_gp_from_scan(
        &self,
        py: Python<'_>,
        func: u64,
        summary: &LiftSummary,
    ) -> Option<Option<u64>> {
        let scan = summary.mips_gp.as_ref()?;
        // a block cut short at a function start is re-lifted at its new size in Python
        if scan.func_addr != func || scan.insns != summary.instruction_addresses.len() {
            return None;
        }
        let Some((_, last_addr)) = scan.last_gp else {
            return Some(None);
        };
        let word = self
            .snapshot
            .bind(py)
            .get()
            .inner
            .load_bytes(last_addr, 4)?;
        let word: [u8; 4] = word.try_into().ok()?;
        let word = if self.conf.big_endian {
            u32::from_be_bytes(word)
        } else {
            u32::from_le_bytes(word)
        };
        // lui (opcode 0x0f with rs = 0): the block only yields the upper half of $gp
        if word & 0xFFE0_0000 == 0x3C00_0000 {
            return Some(None);
        }
        scan.value
    }

    /// The bytes of a node (`CFGNode.byte_string`).
    fn node_bytes(
        &self,
        py: Python<'_>,
        id: u64,
        addr: u64,
        size: u64,
    ) -> PyResult<Option<Vec<u8>>> {
        let (mode, manual) = self.graph.bind(py).get().node_bytes_rec(id)?;
        Ok(match mode {
            BYTES_LOADER => self
                .snapshot
                .bind(py)
                .get()
                .inner
                .load_bytes(addr, size as usize),
            BYTES_MANUAL => manual,
            _ => None,
        })
    }

    /// The X86 `___CxxFrameHandler3` check of `_scan_irsb`; returns the (possibly updated) function address.
    fn cxx_frame_handler3(
        &mut self,
        ctx: &Ctx<'_>,
        addr: u64,
        id: u64,
        func: u64,
    ) -> PyResult<u64> {
        if self.conf.arch != ArchKind::X86 {
            return Ok(func);
        }
        let py = ctx.cfg.py();
        let size = self.graph.bind(py).get().node_view(id)?.1;
        if size < 13 {
            return Ok(func);
        }
        let Some(bytes) = self.node_bytes(py, id, addr, size as u64)? else {
            return Ok(func);
        };
        if bytes.len() < 13
            || bytes[..13] != *b"\x55\x8b\xec\x83\xec\x08\x53\x56\x57\xfc\x89\x45\xfc"
        {
            return Ok(func);
        }
        self.count("callback:cxx_frame_handler3");
        self.flush(ctx)?;
        ctx.cfg
            .call_method1(intern!(py, "_mark_cxx_frame_handler3"), (addr,))?;
        Ok(addr)
    }

    /// `_process_block_arch_specific`
    fn block_arch_specific(
        &mut self,
        ctx: &Ctx<'_>,
        addr: u64,
        id: u64,
        func: u64,
        job_gp: Option<u64>,
        summary: &mut LiftSummary,
    ) -> PyResult<()> {
        let size = summary.size as u64;
        let py = ctx.cfg.py();
        if self.conf.arch == ArchKind::X86
            && addr == func
            && self.node_bytes(py, id, addr, size)?.as_deref()
                == Some(b"\x8b\x1c\x24\xc3".as_slice())
        {
            // __x86.get_pc_thunk.bx: mov ebx, dword ptr [esp]; ret
            let ebx = pyo3::types::PyString::new(py, "ebx");
            self.store
                .bind(py)
                .borrow_mut()
                .info_set(func, "get_pc".to_owned(), ebx.as_any())?;
        }
        match self.conf.arch {
            ArchKind::Amd64 | ArchKind::X86 => {
                let delta = addr as i128 - func as i128;
                if !(delta == 0 || (0 < delta && delta <= 0x20)) {
                    return Ok(());
                }
                if self
                    .store
                    .bind(py)
                    .borrow()
                    .info_contains(func, "bp_as_gpr")?
                {
                    return Ok(());
                }
                // capstone finds `mov ebp/rbp, esp/rsp` or `lea ebp/rbp, [esp/rsp ...]` only where these opcode/ModRM
                // pairs occur; without one, the answer is True without disassembling
                let candidate = {
                    let snap = &self.snapshot.bind(py).get().inner;
                    match snap.load_bytes(addr, size as usize) {
                        Some(bytes) => bytes.windows(2).any(|w| {
                            matches!(
                                (w[0], w[1]),
                                (0x89, 0xE5)
                                    | (0x8B, 0xEC)
                                    | (0x8D, 0x2C)
                                    | (0x8D, 0x6C)
                                    | (0x8D, 0xAC)
                            )
                        }),
                        None => true,
                    }
                };
                let bp_as_gpr = if candidate {
                    self.count("callback:bp_as_gpr");
                    self.flush(ctx)?;
                    ctx.cfg
                        .call_method1(intern!(py, "_bp_as_gpr_by_capstone"), (addr, size))?
                        .is_truthy()?
                } else {
                    true
                };
                let v = PyBool::new(py, bp_as_gpr).to_owned();
                self.store.bind(py).borrow_mut().info_set(
                    func,
                    "bp_as_gpr".to_owned(),
                    v.as_any(),
                )?;
                Ok(())
            }
            ArchKind::Mips => {
                let delta = addr as i128 - func as i128;
                if !(0..15 * 4).contains(&delta)
                    || self.store.bind(py).borrow().info_contains(func, "gp")?
                {
                    return Ok(());
                }
                if let Some(found) = self.mips_gp_from_scan(py, func, summary) {
                    // the rest of the MIPS branch of _process_block_arch_specific
                    self.count("mips_gp:rust");
                    let cfg = &ctx.cfg;
                    let gp = match found {
                        Some(v) => {
                            if cfg.getattr(intern!(py, "_gp_value"))?.is_none() {
                                cfg.setattr(intern!(py, "_gp_value"), v)?;
                            }
                            Some(v)
                        }
                        None => match job_gp {
                            Some(v) => Some(v),
                            None => cfg.getattr(intern!(py, "_gp_value"))?.extract()?,
                        },
                    };
                    if let Some(v) = gp {
                        let v = v.into_pyobject(py)?;
                        self.store.bind(py).borrow_mut().info_set(
                            func,
                            "gp".to_owned(),
                            v.as_any(),
                        )?;
                    }
                    return Ok(());
                }
                // symbolic stepping in Python
                self.count("callback:mips_gp");
                self.flush(ctx)?;
                let irsb = Py::new(py, summary.clone())?;
                let cfg_node = self.resolver.bind(py).call1((id,))?;
                let kwargs = PyDict::new(py);
                kwargs.set_item(intern!(py, "caller_gp"), job_gp)?;
                ctx.cfg.call_method(
                    intern!(py, "_process_block_arch_specific"),
                    (addr, cfg_node, irsb, func),
                    Some(&kwargs),
                )?;
                Ok(())
            }
            ArchKind::Arm => {
                // the heuristics that need statements or capstone run in Python, for the whole block
                let store = self.store.bind(py).borrow();
                let thumb = addr % 2 == 1;
                let read_lr = self.conf.arm_ret_heuristics
                    && addr != func
                    && store.info_contains(func, "lr_saved_on_stack")?
                    && store.info_bool(func, "lr_saved_on_stack")? != Some(false)
                    && summary.jumpkind == IJK_BORING
                    && matches!(summary.next, NextExpr::Tmp(_));
                let ifunc = self.conf.arm_pattern_match_ifuncs
                    && thumb
                    && size == 26
                    && summary.instructions == 8
                    && jk_from_vex(summary.jumpkind) == JK_RET;
                let constant_r4 = !thumb && addr == func && size > 0;
                drop(store);
                if !(read_lr || ifunc || constant_r4) {
                    return Ok(());
                }
                self.count("callback:arm_arch_specific");
                self.flush(ctx)?;
                let irsb = Py::new(py, summary.clone())?;
                let cfg_node = self.resolver.bind(py).call1((id,))?;
                ctx.cfg.call_method1(
                    intern!(py, "_process_block_arch_specific"),
                    (addr, cfg_node, irsb.clone_ref(py), func),
                )?;
                // _arm_track_read_lr_from_stack may turn the exit into a return
                summary.jumpkind = irsb.borrow(py).jumpkind;
                Ok(())
            }
            ArchKind::Other => Ok(()),
        }
    }

    // ------------------------------------------------------------------------------------------------------------
    // Data references
    // ------------------------------------------------------------------------------------------------------------

    fn process_data_refs(&mut self, ctx: &Ctx<'_>, s: &LiftSummary) -> PyResult<()> {
        let py = ctx.cfg.py();
        let max_addr: i128 = if self.conf.bits == 32 {
            0xFFFF_FFFF
        } else {
            0xFFFF_FFFF_FFFF_FFFF
        };
        let assumption = match &ctx.arm {
            Some(arm) => arm
                .assumptions
                .call_method1(intern!(py, "get"), (s.addr & !1,))?,
            None => py.None().into_bound(py),
        };
        for r in &s.data_refs {
            if r.data_addr as i128 + r.data_size as i128 > max_addr {
                continue;
            }
            let ts = data_ref_type_str(r.data_type);
            let (dt, is_store) = if ts == "integer(store)" {
                (SORT_INTEGER, true)
            } else {
                (ts, false)
            };
            self.add_data_reference(
                ctx,
                s.addr,
                r.stmt_idx as i64,
                r.ins_addr,
                r.data_addr,
                Some(r.data_size as i64),
                dt,
            )?;
            let occupied = ctx.seg_list.borrow().is_occupied(r.data_addr);
            if !occupied && r.data_size != 0 {
                let exec = is_store && {
                    let sweep = self.sweep.bind(py).borrow();
                    addr_in_regions(&sweep.inner.exec_regions, r.data_addr)
                };
                if !exec {
                    if r.data_size < 0 {
                        return Err(PyTypeError::new_err("negative data reference size"));
                    }
                    Self::seg_occupy(ctx, r.data_addr, r.data_size as u64, SORT_UNKNOWN);
                    if !assumption.is_none() {
                        assumption.call_method1(
                            intern!(py, "add_data_seg"),
                            (r.data_addr, r.data_size),
                        )?;
                    }
                }
            }
            if self.conf.arch == ArchKind::Arm && r.data_size as i64 == self.conf.arch_bytes {
                self.arm_inlined_data(ctx, s.addr, r)?;
            }
        }
        Ok(())
    }

    /// `_process_irsb_data_ref_inlined_data`: ARM literal-pool pointers.
    fn arm_inlined_data(
        &mut self,
        ctx: &Ctx<'_>,
        irsb_addr: u64,
        r: &crate::vexlift::DataRef,
    ) -> PyResult<()> {
        let py = ctx.cfg.py();
        let snap = self.snapshot.bind(py).get().inner.clone();
        let readable_section = |a: u64| -> Option<&crate::cfg_scan::RegionInfo> {
            let (oi, si) = snap.find_section_containing(a)?;
            Some(&snap.objects[oi].sections[si])
        };
        let Some(sec) = readable_section(r.data_addr) else {
            return Ok(());
        };
        if !sec.is_readable || sec.is_writable {
            return Ok(());
        }
        let Some(mut v) = snap.load_word(r.data_addr, r.data_size as usize) else {
            return Ok(());
        };
        // a direct pointer
        if let Some(sec2) = readable_section(v)
            && sec2.is_readable
        {
            self.add_data_reference(
                ctx,
                irsb_addr,
                r.stmt_idx as i64,
                r.ins_addr,
                v,
                None,
                SORT_UNKNOWN,
            )?;
            let align = self.conf.instruction_alignment.max(1);
            if sec2.is_executable && !ctx.seg_list.borrow().is_occupied(v) && v % align == 0 {
                if !self.conf.arm_has_arm_code && v % 2 != 1 {
                    return Ok(());
                }
                let mut job = JobRec::new(v, v, JK_BORING);
                job.job_type = JobType::DatarefHints;
                let mut st = self.scan.bind(py).borrow_mut();
                st.register_job(v, &job);
                st.pending.add(job);
            }
            return Ok(());
        }
        // pc + offset
        let actual_ref_ins_addr;
        if irsb_addr & 1 == 1 {
            actual_ref_ins_addr = r.ins_addr + 2;
            v = v.wrapping_add(4 + actual_ref_ins_addr) & 0xFFFF_FFFF_FFFF_FFFE;
        } else {
            actual_ref_ins_addr = r.ins_addr + 4;
            v = v.wrapping_add(8 + actual_ref_ins_addr);
        }
        if let Some(sec3) = readable_section(v)
            && sec3.is_readable
        {
            self.add_data_reference(
                ctx,
                irsb_addr,
                r.stmt_idx as i64,
                actual_ref_ins_addr,
                v,
                None,
                SORT_UNKNOWN,
            )?;
        }
        Ok(())
    }

    /// `_post_process_successors` (ARM): THUMB IT-block filtering, then no jumps into a function of the other mode.
    fn arm_post_process_successors(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: Vec<Succ>,
    ) -> PyResult<Vec<Succ>> {
        let py = ctx.cfg.py();
        let mut succs = succs;
        if b.addr % 2 == 1 {
            // _arm_thumb_filter_jump_successors without capstone where it returns early
            let mut done = succs.len() == 1 && succs[0].stmt_idx == DEFAULT_STATEMENT;
            if !done
                && let Some(last) = b.last_ins
                && succs.iter().all(|t| t.ins_addr == Some(last))
            {
                let filtered: Vec<Succ> = succs
                    .iter()
                    .copied()
                    .filter(|t| {
                        let n = jk_name(t.jk);
                        matches!(n, "Ijk_Boring" | "Ijk_FakeRet" | "Ijk_Call" | "Ijk_Ret")
                            || n.starts_with("Ijk_Sys")
                    })
                    .collect();
                if filtered.len() == 1 {
                    succs = filtered;
                    done = true;
                }
            }
            if !done {
                self.count("callback:thumb_filter");
                self.flush(ctx)?;
                let all = PyList::empty(py);
                for (i, t) in succs.iter().enumerate() {
                    all.append((t.stmt_idx, t.ins_addr, t.target, jk_name(t.jk), i))?;
                }
                let irsb = Py::new(py, b.summary.clone())?;
                let kept: Vec<usize> = ctx
                    .cfg
                    .call_method1(intern!(py, "_rust_post_process_successors"), (irsb, all))?
                    .extract()?;
                return Ok(kept.into_iter().map(|i| succs[i]).collect());
            }
        }
        let store = self.store.bind(py).borrow();
        Ok(succs
            .into_iter()
            .filter(|t| match t.target {
                Some(a) if t.stmt_idx == DEFAULT_STATEMENT => {
                    let other = if a % 2 == 1 { a - 1 } else { a + 1 };
                    !store.contains(other)
                }
                _ => true,
            })
            .collect())
    }

    /// `_add_data_reference`, minus the Python containers (buffered for `_apply_rust_data_refs`).
    #[allow(clippy::too_many_arguments)]
    fn add_data_reference(
        &mut self,
        ctx: &Ctx<'_>,
        irsb_addr: u64,
        stmt_idx: i64,
        ins_addr: u64,
        data_addr: u64,
        data_size: Option<i64>,
        data_type: &str,
    ) -> PyResult<()> {
        let py = ctx.cfg.py();
        let snap = &self.snapshot.bind(py).get().inner;
        // loader.find_loadable_containing
        let loadable = match snap.find_object_containing(data_addr, false) {
            None => false,
            Some(oi) => {
                let obj = &snap.objects[oi];
                if obj.kind == BackendKind::Pseudo {
                    false
                } else if !obj.segments.is_empty() {
                    obj.find_segment_containing(data_addr).is_some()
                } else {
                    obj.find_section_containing(data_addr).is_some()
                }
            }
        };
        if !loadable {
            if let Some(main) = snap.objects.iter().find(|o| o.is_main) {
                for seg in &main.segments {
                    if seg.vaddr.wrapping_add(seg.memsize) == data_addr {
                        self.data_refs.push(DataRefRec::SegmentBoundary(
                            irsb_addr, stmt_idx, ins_addr, data_addr,
                        ));
                        break;
                    }
                }
            }
            return Ok(());
        }
        let mut sort: Option<String> = Some(data_type.to_owned());
        if data_type == SORT_INTEGER || data_type == SORT_UNKNOWN {
            let seg = ctx.seg_list.borrow();
            if seg.is_occupied(data_addr) {
                let existing = seg.occupied_by_sort(data_addr);
                if let Some(e) = existing
                    && e != SORT_UNKNOWN
                    && self.conf.memory_data_sorts.contains(&e)
                {
                    sort = Some(e);
                }
            }
        }
        self.data_refs.push(DataRefRec::Memory(
            irsb_addr, stmt_idx, ins_addr, data_addr, data_size, sort,
        ));
        Ok(())
    }

    // ------------------------------------------------------------------------------------------------------------
    // Jobs
    // ------------------------------------------------------------------------------------------------------------

    /// Hands one successor to `CFGFast._create_jobs`.
    fn create_jobs_py(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: &[Succ],
        i: usize,
        reason: &str,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        self.count(&format!("callback:{reason}"));
        self.flush(ctx)?;
        let t0 = Instant::now();
        let r = self.create_jobs_py_inner(ctx, b, succs, i, out);
        self.t_callback.fetch_add(
            t0.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        r
    }

    fn create_jobs_py_inner(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: &[Succ],
        i: usize,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        let py = ctx.cfg.py();
        let s = succs[i];
        let all = PyList::empty(py);
        for t in succs {
            all.append((t.stmt_idx, t.ins_addr, t.target, jk_name(t.jk)))?;
        }
        let irsb = Py::new(py, b.summary.clone())?;
        let cfg_node = self.resolver.bind(py).call1((b.id,))?;
        let jobs = ctx.cfg.call_method1(
            intern!(py, "_create_jobs"),
            PyTuple::new(
                py,
                [
                    s.target.into_pyobject(py)?.into_any(),
                    jk_name(s.jk).into_pyobject(py)?.into_any(),
                    b.func.into_pyobject(py)?.into_any(),
                    irsb.into_bound(py).into_any(),
                    b.addr.into_pyobject(py)?.into_any(),
                    cfg_node,
                    s.ins_addr.into_pyobject(py)?.into_any(),
                    s.stmt_idx.into_pyobject(py)?.into_any(),
                    all.into_any(),
                ],
            )?,
        )?;
        let scan = self.scan.bind(py);
        for j in jobs.try_iter()? {
            let j = j?;
            let rec = scan.borrow_mut().ingest(py, &j)?;
            out.push(rec);
        }
        Ok(())
    }

    /// `CFGFast._create_job_call` for one resolved target of an indirect call.
    #[allow(clippy::too_many_arguments)]
    fn create_job_call_py(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        s: &Succ,
        target: u64,
        jk: u16,
        reason: &str,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        self.count(&format!("callback:indirect_call:{reason}"));
        self.flush(ctx)?;
        let t0 = Instant::now();
        let py = ctx.cfg.py();
        let irsb = Py::new(py, b.summary.clone())?;
        let cfg_node = self.resolver.bind(py).call1((b.id,))?;
        let jobs = ctx.cfg.call_method1(
            intern!(py, "_create_job_call"),
            (
                b.addr,
                irsb,
                cfg_node,
                s.stmt_idx,
                s.ins_addr,
                b.func,
                target,
                jk_name(jk),
            ),
        );
        self.t_callback.fetch_add(
            t0.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let scan = self.scan.bind(py);
        for j in jobs?.try_iter()? {
            let rec = scan.borrow_mut().ingest(py, &j?)?;
            out.push(rec);
        }
        Ok(())
    }

    /// The indirect branch of `_create_jobs` (`_indirect_jump_encountered` and what follows) without the statement
    /// re-lift and the Python resolver loop, through the Rust resolver chain. Returns false when the successor must
    /// go to `_create_jobs` instead (nothing has happened yet then).
    fn scan_indirect(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: &[Succ],
        i: usize,
        jk: u16,
        out: &mut Vec<JobRec>,
    ) -> PyResult<bool> {
        let py = ctx.cfg.py();
        let Some(h) = &self.ijr else {
            return Ok(false);
        };
        let (chain, plt) = (
            h.chain.clone_ref(py),
            h.plt_all || h.reverse_plt.contains(&b.addr),
        );
        let known = h.indirect_jumps.bind(py).contains(b.addr)?;
        let escape = |me: &mut Self, reason: &str| -> PyResult<bool> {
            me.count(&format!("ijr:escape:{reason}"));
            Ok(false)
        };
        // InvalICache stays in Python
        if jk != JK_BORING && jk != JK_CALL {
            return escape(self, "kind");
        }
        if known {
            return escape(self, "known");
        }
        if jk == JK_BORING {
            // _resolve_plt (symbolic) or _indirect_jump_unresolved for a PLT stub
            if plt {
                return escape(self, "plt");
            }
            let plt_function = {
                let store = self.store.bind(py).borrow();
                store.contains(b.addr) && store.is_plt(b.addr)?
            };
            if plt_function {
                return escape(self, "plt_function");
            }
        }
        let Some(vex_jk) = jumpkind_from_name(jk_name(jk)) else {
            return escape(self, "jumpkind");
        };
        let r = chain.bind(py).borrow_mut().scan_timeless(
            py,
            &ctx.cfg,
            b.addr,
            b.func,
            vex_jk,
            b.size as u32,
            &b.summary.instruction_addresses,
        )?;
        let s = succs[i];
        match r {
            TimelessScan::Escape(reason) => escape(self, reason),
            TimelessScan::Resolved(targets) => {
                self.count("ijr:resolved");
                // for resolved_target in set(resolved_targets)
                let mut uniq: Vec<u64> = Vec::with_capacity(targets.len());
                for t in targets {
                    if !uniq.contains(&t) {
                        uniq.push(t);
                    }
                }
                let hashes: Vec<i64> = uniq.iter().map(|&t| py_hash_u64(t)).collect();
                for idx in cpython_set_order(&hashes) {
                    let t = uniq[idx];
                    if jk == JK_CALL {
                        self.direct_call(ctx, b, succs, i, t, jk, true, out)?;
                        continue;
                    }
                    let (to_outside, mut target_func_addr) =
                        self.branching_to_outside(ctx, b, t, jk, succs.len())?;
                    if target_func_addr == b.func {
                        // an indirect jump should be jumping to the start of a function instead of resuming the current one
                        target_func_addr = t;
                    }
                    let edge = FuncEdge::Transition {
                        src: Some(b.src()),
                        dst_addr: t,
                        src_func_addr: b.func,
                        to_outside,
                        dst_func_addr: Some(target_func_addr),
                        stmt_idx: Some(s.stmt_idx),
                        ins_addr: s.ins_addr,
                        is_exception: false,
                    };
                    let mut job = JobRec::new(t, target_func_addr, jk);
                    job.last_addr = Some(t);
                    job.src = Some(b.src());
                    job.src_stmt_idx = Some(s.stmt_idx);
                    job.src_ins_addr = s.ins_addr;
                    job.func_edges = vec![edge];
                    out.push(job);
                }
                Ok(true)
            }
            TimelessScan::Unresolved => {
                self.count("ijr:unresolved");
                self.flush(ctx)?;
                let irsb = Py::new(py, b.summary.clone())?;
                let cfg_node = self.resolver.bind(py).call1((b.id,))?;
                let jobs = ctx.cfg.call_method1(
                    intern!(py, "_ijr_unresolved_jump"),
                    (
                        b.addr,
                        irsb,
                        cfg_node,
                        s.stmt_idx,
                        s.ins_addr,
                        b.func,
                        jk_name(jk),
                    ),
                )?;
                let scan = self.scan.bind(py);
                for j in jobs.try_iter()? {
                    let rec = scan.borrow_mut().ingest(py, &j?)?;
                    out.push(rec);
                }
                Ok(true)
            }
        }
    }

    /// `_create_jobs` for successor `i`.
    fn create_jobs(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: &[Succ],
        i: usize,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        let s = succs[i];
        let mut target = s.target;
        let mut jk = s.jk;

        if jk == JK_BORING
            && let Some(t) = target
            && let Some(thunk) = ctx.known_thunks.get_item(t)?
        {
            let kind = thunk.get_item(0)?;
            let kind: String = kind.extract()?;
            match kind.as_str() {
                "ret" => {
                    jk = JK_RET;
                    target = None;
                }
                "jmp" => {}
                _ => return self.create_jobs_py(ctx, b, succs, i, "thunk", out),
            }
        }

        let jk_str = jk_name(jk);
        let is_syscall = jk_str.starts_with("Ijk_Sys");

        if jk == JK_CALL
            && !self.conf.call_pushes_ret
            && !self.conf.branch_delay_slot
            && b.ins_count > 0
            && s.ins_addr == b.last_ins
            && target == Some(b.summary.addr + b.summary.size as u64)
        {
            jk = JK_BORING;
        }

        match target {
            None => {
                if jk == JK_RET {
                    self.ret_site(ctx, b)?;
                } else if self.conf.resolve_indirect_jumps
                    && (jk == JK_BORING
                        || jk == JK_CALL
                        || jk_str == "Ijk_InvalICache"
                        || is_syscall)
                {
                    let folded = if jk == JK_BORING || jk == JK_CALL {
                        self.const_folded_next(ctx, b)?
                    } else {
                        None
                    };
                    let Some(t) = folded else {
                        if self.scan_indirect(ctx, b, succs, i, jk, out)? {
                            return Ok(());
                        }
                        return self.create_jobs_py(ctx, b, succs, i, "indirect", out);
                    };
                    if jk == JK_CALL {
                        return self.direct_call(ctx, b, succs, i, t, jk, false, out);
                    }
                    let (to_outside, mut target_func_addr) =
                        self.branching_to_outside(ctx, b, t, jk, succs.len())?;
                    if target_func_addr == b.func {
                        // an indirect jump should be jumping to the start of a function instead of resuming the current one
                        target_func_addr = t;
                    }
                    let edge = FuncEdge::Transition {
                        src: Some(b.src()),
                        dst_addr: t,
                        src_func_addr: b.func,
                        to_outside,
                        dst_func_addr: Some(target_func_addr),
                        stmt_idx: Some(s.stmt_idx),
                        ins_addr: s.ins_addr,
                        is_exception: false,
                    };
                    let mut job = JobRec::new(t, target_func_addr, jk);
                    job.last_addr = Some(t);
                    job.src = Some(b.src());
                    job.src_stmt_idx = Some(s.stmt_idx);
                    job.src_ins_addr = s.ins_addr;
                    job.func_edges = vec![edge];
                    out.push(job);
                }
            }
            Some(t) => {
                if jk == JK_BORING
                    || jk == JK_EXCEPTION
                    || jk_str == "Ijk_InvalICache"
                    || jk_str == "Ijk_Privileged"
                {
                    let (to_outside, target_func_addr) =
                        self.branching_to_outside(ctx, b, t, jk, succs.len())?;
                    let edge = FuncEdge::Transition {
                        src: Some(b.src()),
                        dst_addr: t,
                        src_func_addr: b.func,
                        to_outside,
                        dst_func_addr: Some(target_func_addr),
                        stmt_idx: Some(s.stmt_idx),
                        ins_addr: s.ins_addr,
                        is_exception: jk == JK_EXCEPTION,
                    };
                    let mut job = JobRec::new(t, target_func_addr, jk);
                    job.last_addr = Some(b.addr);
                    job.src = Some(b.src());
                    job.src_ins_addr = s.ins_addr;
                    job.src_stmt_idx = Some(s.stmt_idx);
                    job.func_edges = vec![edge];
                    out.push(job);
                } else if jk == JK_CALL || is_syscall {
                    if is_syscall {
                        return self.create_jobs_py(ctx, b, succs, i, "syscall", out);
                    }
                    return self.direct_call(ctx, b, succs, i, t, jk, false, out);
                }
            }
        }
        Ok(())
    }

    /// `_create_job_call` for a call with a known target, or Python when the callee needs it: `_create_jobs` for the
    /// successor, or (`call_py`, a resolved indirect call) `_create_job_call` for this target.
    #[allow(clippy::too_many_arguments)]
    fn direct_call(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        succs: &[Succ],
        i: usize,
        t: u64,
        jk: u16,
        call_py: bool,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        let py = ctx.cfg.py();
        let s = succs[i];
        {
            {
                {
                    if Self::is_hooked(ctx, t)? {
                        if call_py {
                            return self.create_job_call_py(
                                ctx,
                                b,
                                &s,
                                t,
                                jk,
                                "hooked_callee",
                                out,
                            );
                        }
                        return self.create_jobs_py(ctx, b, succs, i, "hooked_callee", out);
                    }
                    let (exists, is_plt, returning, gp) = {
                        let store = self.store.bind(py).borrow();
                        let exists = store.contains(t);
                        let is_plt = exists && store.is_plt(t)?;
                        let returning = if exists { store.returning(t)? } else { None };
                        let gp = if store.info_contains(b.func, "gp")? {
                            match store.info_int(b.func, "gp")? {
                                Some(v) if v >= 0 => Some(v as u64),
                                _ => None,
                            }
                            .map(Some)
                        } else {
                            Some(None)
                        };
                        (exists, is_plt, returning, gp)
                    };
                    if is_plt && self.plt_dynamic_ret_target(ctx, t)? {
                        if call_py {
                            return self.create_job_call_py(
                                ctx,
                                b,
                                &s,
                                t,
                                jk,
                                "plt_dynamic_ret",
                                out,
                            );
                        }
                        return self.create_jobs_py(ctx, b, succs, i, "plt_dynamic_ret", out);
                    }
                    let Some(gp) = gp else {
                        if call_py {
                            return self.create_job_call_py(ctx, b, &s, t, jk, "gp", out);
                        }
                        return self.create_jobs_py(ctx, b, succs, i, "gp", out);
                    };
                    self.create_job_call(ctx, b, &s, t, jk, gp, exists, returning, out)?;
                }
            }
        }
        Ok(())
    }

    /// `_resolve_const_folded_next`: the default-exit target constant-folded from a read-only region at lift time.
    fn const_folded_next(&self, ctx: &Ctx<'_>, b: &Block<'_>) -> PyResult<Option<u64>> {
        if !self.conf.fold_ro_const_loads {
            return Ok(None);
        }
        let NextExpr::Tmp(next_tmp) = b.summary.next else {
            return Ok(None);
        };
        let Some(cv) = b
            .summary
            .const_vals
            .iter()
            .find(|cv| cv.tmp as i64 == next_tmp as i64)
        else {
            return Ok(None);
        };
        let exec = {
            let sweep = self.sweep.bind(ctx.cfg.py()).borrow();
            addr_in_regions(&sweep.inner.exec_regions, cv.value)
        };
        if exec || Self::is_hooked(ctx, cv.value)? {
            Ok(Some(cv.value))
        } else {
            Ok(None)
        }
    }

    /// `_is_call_returning` of a PLT stub: does it consist of one transition to a hooked DYNAMIC_RET procedure (whose
    /// returning status Python computes)?
    fn plt_dynamic_ret_target(&self, ctx: &Ctx<'_>, plt_addr: u64) -> PyResult<bool> {
        let py = ctx.cfg.py();
        let target = {
            let store = self.store.bind(py).borrow();
            let g = store.funcs[&plt_addr].graph.bind(py).borrow();
            if g.number_of_edges() != 1 {
                return Ok(false);
            }
            let (_, dst) = g.edges()[0];
            let (kind, addr, _, _) = g.node(dst)?;
            if kind == NodeKind::Block {
                return Ok(false);
            }
            addr
        };
        match ctx.sim_procedures.get_item(target)? {
            Some(hooker) => hooker.getattr(intern!(py, "DYNAMIC_RET"))?.is_truthy(),
            None => Ok(false),
        }
    }

    /// `_create_job_call` for a direct, non-syscall call to a function that is not hooked and not a PLT stub.
    #[allow(clippy::too_many_arguments)]
    fn create_job_call(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        s: &Succ,
        target: u64,
        jk: u16,
        gp: Option<u64>,
        callee_exists: bool,
        callee_returning: Option<bool>,
        out: &mut Vec<JobRec>,
    ) -> PyResult<()> {
        {
            let py = ctx.cfg.py();
            let return_site = b.addr + b.summary.size as u64;
            let cur = b.func;
            let edge = FuncEdge::Call {
                src: Some(b.src()),
                dst_addr: target,
                ret_addr: Some(return_site),
                src_func_addr: cur,
                syscall: false,
                stmt_idx: Some(s.stmt_idx),
                ins_addr: s.ins_addr,
            };
            let mut job = JobRec::new(target, target, jk);
            job.last_addr = Some(b.addr);
            job.src = Some(b.src());
            job.src_stmt_idx = Some(s.stmt_idx);
            job.src_ins_addr = s.ins_addr;
            job.func_edges = vec![edge];
            job.gp = gp;
            out.push(job);

            let callee_might_return = !callee_exists || callee_returning != Some(false);
            if !callee_might_return {
                return Ok(());
            }
            let call_returning = if callee_exists {
                callee_returning
            } else {
                None
            };
            let scan = self.scan.bind(py);
            let mut fr_job = JobRec::new(return_site, cur, JK_FAKERET);
            fr_job.last_addr = Some(b.addr);
            fr_job.src = Some(b.src());
            fr_job.src_stmt_idx = Some(s.stmt_idx);
            fr_job.src_ins_addr = s.ins_addr;
            fr_job.returning_source = Some(target);
            match call_returning {
                Some(true) => {
                    fr_job.func_edges = vec![
                        FuncEdge::FakeRet {
                            src: Some(b.src()),
                            dst_addr: return_site,
                            src_func_addr: cur,
                            confirmed: Some(true),
                        },
                        FuncEdge::Return {
                            ret_from_addr: target,
                            ret_to_addr: return_site,
                            dst_func_addr: cur,
                        },
                    ];
                    let mut st = scan.borrow_mut();
                    st.register_job(cur, &fr_job);
                    st.pending.add(fr_job);
                    st.pending.add_returning_function(Some(target));
                }
                None => {
                    fr_job.func_edges = vec![FuncEdge::FakeRet {
                        src: Some(b.src()),
                        dst_addr: return_site,
                        src_func_addr: cur,
                        confirmed: None,
                    }];
                    let mut st = scan.borrow_mut();
                    st.function_returns
                        .add((Some(target), cur, b.addr, Some(return_site)));
                    st.register_job(cur, &fr_job);
                    st.pending.add(fr_job);
                }
                Some(false) => {}
            }
            Ok(())
        }
    }

    /// The `Ijk_Ret` branch of `_create_jobs`.
    fn ret_site(&mut self, ctx: &Ctx<'_>, b: &Block<'_>) -> PyResult<()> {
        let py = ctx.cfg.py();
        let cur = b.func;
        // self._function_exits[cur].add(addr)
        ctx.function_exits
            .get_item(cur)?
            .call_method1(intern!(py, "add"), (b.addr,))?;
        // _function_add_return_site
        let g = self.graph.bind(py).get();
        match g.first_node_at_addr(b.addr)? {
            Some(n) => {
                let spec = self.node_spec(ctx, n)?;
                RecoveryFunctions::add_return_from(self.store.bind(py), cur, spec)?;
            }
            None => {
                return Err(PyTypeError::new_err("return site without a node"));
            }
        }
        self.set_returning_true(py, cur)?;
        self.scan
            .bind(py)
            .borrow_mut()
            .pending
            .add_returning_function(Some(cur));
        ctx.block_addrs_with_return.add(b.addr)?;
        Ok(())
    }

    /// `_is_branching_to_outside` (non-ARM).
    fn branching_to_outside(
        &mut self,
        ctx: &Ctx<'_>,
        b: &Block<'_>,
        target: u64,
        jk: u16,
        n_succs: usize,
    ) -> PyResult<(bool, u64)> {
        let py = ctx.cfg.py();
        let cur = b.func;
        let snap = &self.snapshot.bind(py).get().inner;
        if self.conf.skip_unmapped_addrs && !snap.addrs_belong_to_same_section(b.addr, target) {
            return Ok((true, target));
        }
        if Self::py_set_contains(&ctx.eh_frame_boundary_addrs, target)? {
            return Ok((target != cur, target));
        }
        let is_arm = self.conf.arch == ArchKind::Arm;
        let real_target = if is_arm { target & !1 } else { target };
        let mut tfa: Option<u64> = None;
        let traced = self.scan.bind(py).borrow().traced.contains(&real_target);
        if traced {
            // model.get_any_node(target): on ARM an even target also finds the THUMB node at target + 1
            let g = self.graph.bind(py).get();
            let mut n = g.first_node_at_addr(target)?;
            if n.is_none() && is_arm && target.is_multiple_of(2) {
                n = g.first_node_at_addr(target + 1)?;
            }
            if let Some(n) = n {
                tfa = g.node_func(n)?;
            }
        }
        if tfa.is_none() && b.ins_count == 1 && b.addr == cur && jk == JK_BORING && n_succs == 1 {
            let inside = snap.symbol_at(cur).is_some_and(|s| {
                s.is_function
                    && s.rebased_addr == cur
                    && s.size > 0
                    && cur <= target
                    && (target as u128) < cur as u128 + s.size as u128
            });
            if !inside {
                tfa = Some(target);
            }
        }
        if tfa.is_none()
            && let Some(marker) = &self.conf.ibt_marker
            && jk == JK_BORING
            && n_succs == 1
            && target != b.addr + b.size
            && !traced
            && snap.load_bytes(target, marker.len()).as_deref() == Some(marker.as_slice())
        {
            tfa = Some(target);
        }
        if tfa.is_none()
            && let Some(arm) = &ctx.arm
            && jk == JK_BORING
            && n_succs == 1
            && !traced
        {
            let tail_call = if Self::py_set_contains(&arm.prologue_addrs, target)? {
                true
            } else {
                self.count("callback:block_restores_lr");
                self.flush(ctx)?;
                let irsb = Py::new(py, b.summary.clone())?;
                let cfg_node = self.resolver.bind(py).call1((b.id,))?;
                ctx.cfg
                    .call_method1(intern!(py, "_block_restores_lr"), (cfg_node, irsb))?
                    .is_truthy()?
            };
            if tail_call {
                tfa = Some(target);
            }
        }
        let tfa = tfa.unwrap_or(cur);
        Ok((tfa != cur, tfa))
    }
}

#[pymethods]
impl BlockScanner {
    /// :param cfg:         The CFGFast object (only read here; `run` takes it again).
    /// :param scan:        Its ScanState.
    /// :param resolver:    `resolver(node_id) -> CFGNode`, as the ScanState's.
    /// :param syscall:     How to test syscall addresses: ("never",), ("userland", kernel_base, align, max_number),
    ///                     ("dict", handlers) or ("callback", is_syscall_addr).
    /// :param exc_by_end:  `_exception_handling_by_endaddr` as (end, handler_addr) pairs.
    #[new]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        cfg: &Bound<'_, PyAny>,
        scan: Py<ScanState>,
        graph: Py<CfgGraph>,
        store: Py<RecoveryFunctions>,
        lifter: Py<VexLifter>,
        snapshot: Py<LoaderSnapshot>,
        sweep: Py<LinearSweep>,
        resolver: Py<PyAny>,
        syscall: &Bound<'_, PyTuple>,
        exc_by_end: Vec<(u64, Option<u64>)>,
        memory_data_sorts: Vec<String>,
        arch_registers: Py<PyAny>,
        arm_options: Option<(bool, bool, bool)>,
    ) -> PyResult<Self> {
        let arch_name: String = snapshot.bind(py).get().inner.arch.name.clone();
        let arch = match arch_name.as_str() {
            "AMD64" => ArchKind::Amd64,
            "X86" => ArchKind::X86,
            "MIPS32" | "MIPS64" => ArchKind::Mips,
            n if n.starts_with("ARM") => ArchKind::Arm,
            _ => ArchKind::Other,
        };
        let a = &snapshot.bind(py).get().inner.arch;
        let kind: String = syscall.get_item(0)?.extract()?;
        let syscall = match kind.as_str() {
            "never" => SyscallCheck::Never,
            "userland" => SyscallCheck::Userland {
                kernel_base: syscall.get_item(1)?.extract()?,
                align: syscall.get_item(2)?.extract()?,
                max_number: syscall.get_item(3)?.extract()?,
            },
            "dict" => SyscallCheck::Dict(syscall.get_item(1)?.cast_into::<PyDict>()?.unbind()),
            _ => SyscallCheck::Callback(syscall.get_item(1)?.unbind()),
        };
        let ibt: Option<Vec<u8>> = cfg.getattr("_ibt_marker")?.extract()?;
        let nop_byte = cfg.getattr("_nop_byte")?;
        let threshold = cfg.getattr("_repeating_byte_run_threshold")?;
        let mut padding: Vec<u8> = cfg
            .getattr("_padding_bytes")?
            .extract::<std::collections::HashSet<u8>>()?
            .into_iter()
            .collect();
        padding.sort_unstable();
        let conf = Config {
            arch,
            bits: a.bits as u32,
            arch_bytes: a.bytes as i64,
            instruction_alignment: a.instruction_alignment,
            branch_delay_slot: a.branch_delay_slot,
            call_pushes_ret: a.call_pushes_ret,
            skip_unmapped_addrs: cfg.getattr("_skip_unmapped_addrs")?.is_truthy()?,
            resolve_indirect_jumps: cfg.getattr("_resolve_indirect_jumps")?.is_truthy()?,
            collect_data_ref: cfg.getattr("_collect_data_ref")?.is_truthy()?,
            fold_ro_const_loads: cfg.getattr("_fold_ro_const_loads")?.is_truthy()?,
            repeating_threshold: if threshold.is_truthy()? {
                threshold.extract()?
            } else {
                0
            },
            nop_byte: if nop_byte.is_none() {
                None
            } else {
                Some(nop_byte.extract()?)
            },
            padding_bytes: padding,
            ibt_marker: ibt,
            exc_by_end: exc_by_end.into_iter().collect(),
            memory_data_sorts: memory_data_sorts.into_iter().collect(),
            syscall,
            arm_ret_heuristics: arm_options.is_some_and(|o| o.0),
            arm_pattern_match_ifuncs: arm_options.is_some_and(|o| o.1),
            arm_has_arm_code: arm_options.is_none_or(|o| o.2),
            check_funcret_max_job: cfg.getattr("_check_funcret_max_job")?.extract()?,
            mips32_gp: if arch == ArchKind::Mips && a.bits == 32 {
                let regs = arch_registers.bind(py);
                let (gp_off, _): (i32, u32) = regs.get_item("gp")?.extract()?;
                let (t9_off, _): (i32, u32) = regs.get_item("t9")?.extract()?;
                Some((gp_off, t9_off))
            } else {
                None
            },
            big_endian: a.big_endian,
        };
        let _ = conf.arch_bytes;
        Ok(BlockScanner {
            scan,
            graph,
            store,
            lifter,
            snapshot,
            sweep,
            resolver,
            arch_registers,
            conf,
            data_refs: Vec::new(),
            new_node_addrs: Vec::new(),
            cfb_blocks: None,
            stats: IndexMap::new(),
            eh_sorted: Vec::new(),
            eh_list: None,
            ijr: None,
            t_lift: Default::default(),
            t_callback: Default::default(),
            t_flush: Default::default(),
        })
    }

    /// Hand each new node to `cfg._cfb_add_rust_blocks` (at every flush) so that the CFBlanket gets the blocks the
    /// Python path would add.
    fn set_cfb(&mut self, enabled: bool) {
        self.cfb_blocks = enabled.then(Vec::new);
    }

    /// Resolve indirect jumps through `chain` without escaping to `_create_jobs` where possible. `plt_all` and
    /// `reverse_plt` say where `_resolve_plt` would run; `indirect_jumps` is `cfg.indirect_jumps`.
    fn set_ijr(
        &mut self,
        chain: Py<ResolverChain>,
        plt_all: bool,
        reverse_plt: Vec<u64>,
        indirect_jumps: Py<PyDict>,
    ) {
        self.ijr = Some(IjrHook {
            chain,
            plt_all,
            reverse_plt: reverse_plt.into_iter().collect(),
            indirect_jumps,
        });
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.scan)?;
        visit.call(&self.graph)?;
        visit.call(&self.store)?;
        visit.call(&self.lifter)?;
        visit.call(&self.snapshot)?;
        visit.call(&self.sweep)?;
        visit.call(&self.resolver)?;
        visit.call(&self.arch_registers)?;
        if let Some(l) = &self.eh_list {
            visit.call(l)?;
        }
        if let Some(h) = &self.ijr {
            visit.call(&h.chain)?;
            visit.call(&h.indirect_jumps)?;
        }
        match &self.conf.syscall {
            SyscallCheck::Dict(d) => visit.call(d)?,
            SyscallCheck::Callback(f) => visit.call(f)?,
            _ => {}
        }
        Ok(())
    }

    /// Processes jobs until the queue is empty or `budget_ns` has elapsed (False), or the front job needs Python (True;
    /// it is still queued and untouched).
    #[pyo3(signature = (cfg, budget_ns=None))]
    fn run(
        slf: &Bound<'_, Self>,
        cfg: &Bound<'_, PyAny>,
        budget_ns: Option<u64>,
    ) -> PyResult<bool> {
        let py = slf.py();
        let mut this = slf.borrow_mut();
        let ctx = this.fetch(cfg)?;
        let deadline =
            budget_ns.map(|ns| std::time::Instant::now() + std::time::Duration::from_nanos(ns));
        let r = this.run_inner(&ctx, deadline);
        let f = this.flush(&ctx);
        drop(this);
        let r = r?;
        f?;
        let _ = py;
        Ok(r)
    }

    /// Counters of Rust-handled jobs and of escapes/callbacks by reason.
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.stats {
            d.set_item(k, v)?;
        }
        d.set_item(
            "ns:lift",
            self.t_lift.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        d.set_item(
            "ns:callback",
            self.t_callback.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        d.set_item(
            "ns:flush",
            self.t_flush.load(std::sync::atomic::Ordering::Relaxed),
        )?;
        Ok(d)
    }
}

impl BlockScanner {
    /// `_pop_pending_job(returning=True)`
    fn pop_returning_pending_job(&mut self, ctx: &Ctx<'_>) -> PyResult<Option<JobRec>> {
        let py = ctx.cfg.py();
        let scan = self.scan.bind(py);
        loop {
            let mut st = scan.borrow_mut();
            if st.pending.is_empty() {
                return Ok(None);
            }
            let returning = (st.pending.len() as u64) < self.conf.check_funcret_max_job;
            let job = st.pending.pop(returning);
            drop(st);
            if let Some(j) = &job
                && j.job_type == JobType::DatarefHints
                && ctx.seg_list.borrow().is_occupied(j.addr)
            {
                continue;
            }
            return Ok(job);
        }
    }

    fn run_inner(&mut self, ctx: &Ctx<'_>, deadline: Option<std::time::Instant>) -> PyResult<bool> {
        let py = ctx.cfg.py();
        let mut processed: u64 = 0;
        let result = loop {
            if ctx.cfg.getattr(intern!(py, "_should_abort"))?.is_truthy()? {
                break false;
            }
            if let Some(d) = deadline
                && processed.is_multiple_of(BUDGET_CHECK_JOBS)
                && processed > 0
                && std::time::Instant::now() >= d
            {
                break false;
            }
            let front = self.scan.bind(py).borrow().queue.front().cloned();
            let rec = match front {
                Some(rec) => rec,
                None => {
                    // the fast path of _job_queue_empty: a pending job returning from a returning function
                    match self.pop_returning_pending_job(ctx)? {
                        Some(job) => {
                            self.count("pending:returning");
                            self.scan.bind(py).borrow_mut().push_job(job);
                            continue;
                        }
                        None => break false,
                    }
                }
            };
            let plan = self.plan(ctx, &rec)?;
            if let Plan::Escape(reason) = plan {
                self.count(&format!("escape:{reason}"));
                break true;
            }
            // _pre_job_handling
            {
                let mut s = self.scan.bind(py).borrow_mut();
                s.deregister_job(rec.func_addr, &rec);
            }
            if let Some((perf_counter, interval)) = &ctx.progress {
                // _calculate_progress_and_notify's own throttle, checked here to save the call
                let now: f64 = perf_counter.call0()?.extract()?;
                let last: f64 = ctx
                    .cfg
                    .getattr(intern!(py, "_last_progress_notify"))?
                    .extract()?;
                if now - last >= *interval {
                    self.flush(ctx)?;
                    ctx.cfg
                        .call_method0(intern!(py, "_calculate_progress_and_notify"))?;
                }
            }
            self.scan.bind(py).borrow_mut().pop_front(rec.addr);
            processed += 1;
            self.count("rust");
            if matches!(plan, Plan::Lifted { .. }) {
                self.count("lift:rust");
            }

            let entries = self.commit(ctx, &rec, plan)?;
            let mut s = self.scan.bind(py).borrow_mut();
            for e in &entries {
                s.register_job(e.func_addr, e);
            }
            for e in entries {
                s.push_job(e);
            }
        };
        if processed > 0 {
            let ctr = ctx.cfg.getattr(intern!(py, "_job_ctr"))?.extract::<u64>()?;
            ctx.cfg.setattr(intern!(py, "_job_ctr"), ctr + processed)?;
        }
        Ok(result)
    }
}

pub fn cfg_block(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BlockScanner>()?;
    let _ = jk_intern;
    let _ = JK_CALL;
    Ok(())
}
