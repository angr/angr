//! `ConstantResolver` (const_resolver.py): an indirect jump or call whose target a whole-function constant
//! propagation resolves.
//!
//! The FCP results are cached per function like `kb.propagations[("FCP", func)]`; the cache is authoritative during
//! the run and published to `kb.propagations` when the chain is released.

use std::rc::Rc;

use indexmap::IndexMap;
use pyo3::intern;
use pyo3::prelude::*;
use rustc_hash::FxHashMap;

use super::blade::{BladeParams, DEFAULT_STATEMENT, SliceGraph, SliceLoc, blade};
use super::cx::IrSpec;
use super::fcp::{CodeLoc, FcpRequest, FcpTable, LoadPolicy, Var, run_fcp, table_rows};
use super::memload::{const_word_load, is_boring_or_call};
use super::u256::U256;
use super::{Decision, Effects, JumpSite, Outcome, ResolveCx, Resolver, ShadowDiff};
use crate::vexir::{Expr, Stmt, VexIrsb, op_name};
use crate::vexlift::VEX_IRSB_MAX_SIZE;

/// One cached propagation: `PropagationModel(("FCP", func), replacements, function_block_count)`.
pub struct FcpEntry {
    pub table: Rc<FcpTable>,
    pub function_block_count: usize,
}

pub struct ConstantResolver {
    pub max_func_nodes: usize,
    /// `kb.propagations` FCP models in first-insertion order.
    pub cache: IndexMap<u64, FcpEntry>,
    /// Shadow mode: `shadow_blade(cfg, addr)` returns the Python Blade's slice nodes and edges.
    shadow_blade: Option<Py<PyAny>>,
    /// The function whose FCP ran in the last resolve, and the last slice, for shadow comparisons.
    last_fcp_func: Option<u64>,
    last_slice: Option<(u64, SliceGraph)>,
    /// Per function, the last `kb.propagations` model seen (compared, imported or published).
    models: FxHashMap<u64, Py<PyAny>>,
    /// Functions whose Rust entry is newer than `kb.propagations`.
    rust_newer: indexmap::IndexSet<u64>,
    /// `publish_fcp(cfg, func_addr, FcpTableView, function_block_count)` (Python): updates `kb.propagations`.
    publish: Py<PyAny>,
}

impl ConstantResolver {
    pub fn new(max_func_nodes: usize, shadow_blade: Option<Py<PyAny>>, publish: Py<PyAny>) -> Self {
        ConstantResolver {
            max_func_nodes,
            cache: IndexMap::new(),
            shadow_blade,
            last_fcp_func: None,
            last_slice: None,
            models: FxHashMap::default(),
            rust_newer: indexmap::IndexSet::new(),
            publish,
        }
    }

    fn publish_one(&mut self, py: Python<'_>, cfg: &Bound<'_, PyAny>, func: u64) -> PyResult<()> {
        let Some(e) = self.cache.get(&func) else {
            return Ok(());
        };
        let view = Py::new(
            py,
            FcpTableView {
                table: e.table.clone(),
            },
        )?;
        let model = self
            .publish
            .bind(py)
            .call1((cfg, func, view, e.function_block_count))?;
        self.models.insert(func, model.unbind());
        self.rust_newer.shift_remove(&func);
        Ok(())
    }

    fn py_model<'py>(
        py: Python<'py>,
        cfg: &Bound<'py, PyAny>,
        func: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        cfg.getattr(intern!(py, "kb"))?
            .getattr(intern!(py, "propagations"))?
            .call_method1(intern!(py, "get"), (("FCP", func),))
    }

    /// Bring the Rust cache entry of `func` up to date with `kb.propagations` after the Python twin ran.
    fn import_model(
        &mut self,
        py: Python<'_>,
        cfg: &Bound<'_, PyAny>,
        func: u64,
    ) -> PyResult<bool> {
        let model = Self::py_model(py, cfg, func)?;
        if model.is_none()
            || self
                .models
                .get(&func)
                .is_some_and(|m| m.bind(py).is(&model))
        {
            return Ok(true);
        }
        let count: usize = model
            .getattr(intern!(py, "function_block_count"))?
            .extract()?;
        let Some(rows) = table_from_py(&model.getattr(intern!(py, "replacements"))?)? else {
            return Ok(false);
        };
        let mut table = FcpTable::default();
        for (loc, vars) in rows {
            table.entries.insert(loc, vars.into_iter().collect());
        }
        let entry = FcpEntry {
            table: Rc::new(table),
            function_block_count: count,
        };
        match self.cache.get_mut(&func) {
            Some(e) => *e = entry,
            None => {
                self.cache.insert(func, entry);
            }
        }
        self.models.insert(func, model.unbind());
        Ok(true)
    }
}

/// An FCP table as ordered rows.
type TableRows = Vec<(CodeLoc, Vec<(Var, U256)>)>;

/// `{CodeLocation: {VEXTmp | VEXReg: int}}` as rows; None when a key or value has another type.
fn table_from_py(replacements: &Bound<'_, PyAny>) -> PyResult<Option<TableRows>> {
    let py = replacements.py();
    let mut out = Vec::new();
    for item in replacements
        .call_method0(intern!(py, "items"))?
        .try_iter()?
    {
        let (loc, vars): (Bound<'_, PyAny>, Bound<'_, PyAny>) = item?.extract()?;
        let block_addr: u64 = loc.getattr(intern!(py, "block_addr"))?.extract()?;
        let stmt_idx: i32 = loc.getattr(intern!(py, "stmt_idx"))?.extract()?;
        let ins_addr: i64 = match loc.getattr(intern!(py, "ins_addr"))?.extract() {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        let mut row = Vec::new();
        for kv in vars.call_method0(intern!(py, "items"))?.try_iter()? {
            let (k, v): (Bound<'_, PyAny>, Bound<'_, PyAny>) = kv?.extract()?;
            let name = k.get_type().name()?;
            let var = match name.to_str()? {
                "VEXTmp" => Var::Tmp(k.getattr(intern!(py, "tmp"))?.extract()?),
                "VEXReg" => Var::Reg(
                    k.getattr(intern!(py, "offset"))?.extract()?,
                    k.getattr(intern!(py, "size"))?.extract()?,
                ),
                _ => return Ok(None),
            };
            let Some(value) = py_int_u256(&v)? else {
                return Ok(None);
            };
            row.push((var, value));
        }
        out.push(((block_addr, stmt_idx, ins_addr), row));
    }
    Ok(Some(out))
}

fn py_int_u256(v: &Bound<'_, PyAny>) -> PyResult<Option<U256>> {
    if !v.is_instance_of::<pyo3::types::PyInt>() || v.is_instance_of::<pyo3::types::PyBool>() {
        return Ok(None);
    }
    if let Ok(x) = v.extract::<u64>() {
        return Ok(Some(U256::from_u64(x)));
    }
    match v.call_method1(intern!(v.py(), "to_bytes"), (32, "little")) {
        Ok(b) => Ok(U256::from_le_bytes(b.extract::<&[u8]>()?)),
        Err(_) => Ok(None),
    }
}

/// A published FCP table; `angr.analyses.cfg.indirect_jump_resolvers.rust.LazyFcpReplacements` turns it into the
/// `replacements` dict on first use.
#[pyclass(module = "angr.rustylib.ijr", unsendable, frozen)]
pub struct FcpTableView {
    table: Rc<FcpTable>,
}

#[pymethods]
impl FcpTableView {
    fn rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyList>> {
        table_rows(py, &self.table)
    }

    fn __len__(&self) -> usize {
        self.table.entries.len()
    }
}

pub const CR_BLADE: BladeParams = BladeParams {
    ignore_sp: false,
    ignore_bp: false,
    ignored_regs: Vec::new(),
    max_level: 3,
    stop_at_calls: true,
    cross_insn_opt: true,
    max_predecessors: 10,
    include_imarks: true,
    control_dependence: false,
};

/// `factory.block(addr, cross_insn_opt=True).vex`, as the checks lift.
fn cross_spec(cx: &ResolveCx, addr: u64) -> IrSpec {
    IrSpec {
        addr,
        max_size: VEX_IRSB_MAX_SIZE as i64,
        opt_level: cx.default_opt_level,
        cross_insn_opt: true,
        extra_stops: false,
    }
}

type CheckResult = Result<bool, &'static str>;

fn enqueue_preds(
    slice: &SliceGraph,
    loc: &SliceLoc,
    depth: usize,
    queue: &mut std::collections::VecDeque<(usize, u64, i64)>,
    seen: &mut rustc_hash::FxHashSet<SliceLoc>,
) -> Result<(), &'static str> {
    let preds = slice.predecessors(loc).ok_or("slice_node_missing")?;
    for &(a, i) in preds {
        if seen.insert((a, i)) {
            queue.push_back((if a != loc.0 { depth + 1 } else { depth }, a, i));
        }
    }
    Ok(())
}

/// `_check_jump_target_is_loaded_from_dynamic_addr`
fn loaded_from_dynamic_addr(
    py: Python<'_>,
    cx: &mut ResolveCx,
    slice: &SliceGraph,
    loc: SliceLoc,
) -> PyResult<CheckResult> {
    let mut queue = std::collections::VecDeque::new();
    let mut seen = rustc_hash::FxHashSet::default();
    if let Err(d) = enqueue_preds(slice, &loc, 0, &mut queue, &mut seen) {
        return Ok(Err(d));
    }
    // the first level enqueues at depth 0
    for q in queue.iter_mut() {
        q.0 = 0;
    }
    while let Some((depth, pred_addr, stmt_idx)) = queue.pop_front() {
        if depth >= 3 {
            break;
        }
        if stmt_idx != DEFAULT_STATEMENT {
            let ir = match cx.ir(py, &cross_spec(cx, pred_addr))? {
                Ok(ir) => ir,
                Err(fb) => return Ok(Err(fb.name())),
            };
            let Some(stmt) = ir.stmts.get(stmt_idx as usize) else {
                return Ok(Err("stmt_index"));
            };
            if let Stmt::IMark { .. } = stmt {
                if let Err(d) =
                    enqueue_preds(slice, &(pred_addr, stmt_idx), depth, &mut queue, &mut seen)
                {
                    return Ok(Err(d));
                }
                continue;
            }
            if let Stmt::WrTmp { data, .. } = stmt
                && let Some(Expr::Load { addr, .. }) = ir.expr(*data)
                && !matches!(ir.expr(*addr), Some(Expr::Const(_)))
            {
                return Ok(Ok(true));
            }
        }
        if let Err(d) = enqueue_preds(slice, &(pred_addr, stmt_idx), depth, &mut queue, &mut seen) {
            return Ok(Err(d));
        }
    }
    Ok(Ok(false))
}

fn get_reg(ir: &VexIrsb, tmp: u32) -> Option<i32> {
    let def = ir.tmp_def_stmt(tmp)?;
    if let Stmt::WrTmp { data, .. } = ir.stmts[def]
        && let Some(Expr::Get { offset, .. }) = ir.expr(data)
    {
        return Some(*offset);
    }
    None
}

/// `_check_jump_target_is_compared_against`
fn compared_against(
    py: Python<'_>,
    cx: &mut ResolveCx,
    slice: &SliceGraph,
    loc: SliceLoc,
) -> PyResult<CheckResult> {
    let site = match cx.ir(py, &cross_spec(cx, loc.0))? {
        Ok(ir) => ir,
        Err(fb) => return Ok(Err(fb.name())),
    };
    let Some(next_tmp) = site.next_tmp() else {
        return Ok(Ok(false));
    };
    let Some(next_reg) = get_reg(&site, next_tmp) else {
        return Ok(Ok(false));
    };
    let mut queue = std::collections::VecDeque::new();
    let mut seen = rustc_hash::FxHashSet::default();
    if let Err(d) = enqueue_preds(slice, &loc, 0, &mut queue, &mut seen) {
        return Ok(Err(d));
    }
    for q in queue.iter_mut() {
        q.0 = 0;
    }
    while let Some((depth, pred_addr, stmt_idx)) = queue.pop_front() {
        if depth > 1 {
            continue;
        }
        let pred = (pred_addr, stmt_idx);
        if stmt_idx != DEFAULT_STATEMENT {
            let ir = match cx.ir(py, &cross_spec(cx, pred_addr))? {
                Ok(ir) => ir,
                Err(fb) => return Ok(Err(fb.name())),
            };
            let Some(stmt) = ir.stmts.get(stmt_idx as usize) else {
                return Ok(Err("stmt_index"));
            };
            match stmt {
                Stmt::IMark { .. } => {
                    if let Err(d) = enqueue_preds(slice, &pred, depth, &mut queue, &mut seen) {
                        return Ok(Err(d));
                    }
                    continue;
                }
                Stmt::Put { offset, .. } if *offset == next_reg => continue,
                Stmt::WrTmp { data, .. } => {
                    if let Some(Expr::Binop { op, args }) = ir.expr(*data)
                        && op_name(*op).starts_with("Iop_Cmp")
                    {
                        for &arg in args {
                            let Some(Expr::RdTmp(arg_tmp)) = ir.expr(arg) else {
                                continue;
                            };
                            let Some(def) = ir.tmp_def_stmt(*arg_tmp) else {
                                continue;
                            };
                            if let Stmt::WrTmp { data: d, .. } = ir.stmts[def]
                                && let Some(Expr::Get { offset, .. }) = ir.expr(d)
                                && *offset == next_reg
                            {
                                return Ok(Ok(true));
                            }
                            let end = (stmt_idx as usize).min(ir.stmts.len());
                            if def + 1 < end
                                && ir.stmts[def + 1..end].iter().any(|s| {
                                    matches!(s, Stmt::Put { offset, data }
                                        if *offset == next_reg
                                            && matches!(ir.expr(*data), Some(Expr::RdTmp(t)) if t == arg_tmp))
                                })
                            {
                                return Ok(Ok(true));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if let Err(d) = enqueue_preds(slice, &pred, depth, &mut queue, &mut seen) {
            return Ok(Err(d));
        }
    }
    Ok(Ok(false))
}

impl Resolver for ConstantResolver {
    fn kind(&self) -> &'static str {
        "ConstantResolver"
    }

    fn timeless(&self) -> bool {
        false
    }

    fn filter(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        let Some(store) = cx.functions(py, cfg)? else {
            return Ok(Decision::Python("no_store"));
        };
        let st = store.bind(py).borrow();
        if !st.contains(j.func_addr) {
            return Ok(Decision::Done(false));
        }
        match st.block_count(py, j.func_addr) {
            Some(n) if n <= self.max_func_nodes => {}
            _ => return Ok(Decision::Done(false)),
        }
        Ok(Decision::Done(is_boring_or_call(j.jumpkind)))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        _fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        self.last_fcp_func = None;
        let Some(store) = cx.functions(py, cfg)? else {
            return Ok(Decision::Python("no_store"));
        };
        if !store.bind(py).borrow().contains(j.func_addr) {
            return Ok(Decision::Done(Outcome::Unresolved));
        }
        let block = match cx.ir(py, &j.block)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Decision::Python(fb.name())),
        };
        let Some(next_tmp) = block.next_tmp() else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        let Some((tmp_stmt_idx, tmp_ins_addr)) = block.find_tmp_write_stmt_and_ins(next_tmp) else {
            return Ok(Decision::Done(Outcome::Unresolved));
        };
        // a target loaded from a constant address: MemoryLoadResolver's case
        if let Stmt::WrTmp { data, .. } = block.stmts[tmp_stmt_idx]
            && let Some(Expr::Load { addr, .. }) = block.expr(data)
            && matches!(block.expr(*addr), Some(Expr::Const(_)))
            && block.result_bits(data) == cx.arch.bits
        {
            if let Some(load_addr) = const_word_load(&block, tmp_stmt_idx, cx.arch.bits)
                && let Some(value) = cx.snap.load_word(load_addr, cx.arch.bytes as usize)
                && cx.is_target_valid(py, value)?
            {
                return Ok(Decision::Done(Outcome::Resolved(vec![value])));
            }
            return Ok(Decision::Done(Outcome::Unresolved));
        }

        self.last_slice = None;
        // a full-function propagation that has no valid target for the jump answers Unresolved whatever the slice
        // checks find, so the slice is skipped (it is kept in shadow mode, which compares it)
        if self.shadow_blade.is_none()
            && let Some(e) = self.cache.get(&j.func_addr)
            && let Ok(rec) = store.bind(py).borrow().rec(j.func_addr)
            && rec.graph.bind(py).borrow().local_count() == e.function_block_count
        {
            let block_loc: CodeLoc = (block.addr, tmp_stmt_idx as i32, tmp_ins_addr as i64);
            let target = e
                .table
                .get(&block_loc, &Var::Tmp(next_tmp))
                .and_then(|v| v.to_u64());
            let valid = match target {
                Some(t) => cx.is_target_valid(py, t)?,
                None => false,
            };
            if !valid {
                cx.count("ConstantResolver:full_fcp_unresolved");
                return Ok(Decision::Done(Outcome::Unresolved));
            }
        }
        let slice = match blade(py, cx, j.addr, -1, &CR_BLADE)? {
            Ok(s) => s,
            Err(d) => return Ok(Decision::Python(d)),
        };
        if self.shadow_blade.is_some() {
            self.last_slice = Some((j.addr, slice.clone()));
        }
        let loc = (j.addr, DEFAULT_STATEMENT);
        match loaded_from_dynamic_addr(py, cx, &slice, loc)? {
            Ok(true) => return Ok(Decision::Done(Outcome::Unresolved)),
            Ok(false) => {}
            Err(d) => return Ok(Decision::Python(d)),
        }
        match compared_against(py, cx, &slice, loc)? {
            Ok(true) => return Ok(Decision::Done(Outcome::Unresolved)),
            Ok(false) => {}
            Err(d) => return Ok(Decision::Python(d)),
        }

        let block_loc: CodeLoc = (block.addr, tmp_stmt_idx as i32, tmp_ins_addr as i64);
        let var = Var::Tmp(next_tmp);
        let block_count = {
            let st = store.bind(py).borrow();
            match st.rec(j.func_addr) {
                Ok(rec) => rec.graph.bind(py).borrow().local_count(),
                Err(_) => return Ok(Decision::Python("no_function")),
            }
        };
        let mut resolved = None;
        let mut is_full = None;
        if let Some(e) = self.cache.get(&j.func_addr) {
            is_full = Some(block_count == e.function_block_count);
            resolved = e.table.get(&block_loc, &var);
        }
        if resolved.is_none() && is_full != Some(true) {
            let req = FcpRequest {
                func_addr: j.func_addr,
                blocks: None,
                cross_insn_opt: false,
                load: LoadPolicy::Propagator,
            };
            let table = match run_fcp(py, cx, &store, &req)? {
                Ok(t) => Rc::new(t),
                Err(d) => return Ok(Decision::Python(d)),
            };
            resolved = table.get(&block_loc, &var);
            let entry = FcpEntry {
                table,
                function_block_count: block_count,
            };
            match self.cache.get_mut(&j.func_addr) {
                Some(e) => *e = entry,
                None => {
                    self.cache.insert(j.func_addr, entry);
                }
            }
            self.last_fcp_func = Some(j.func_addr);
            self.rust_newer.insert(j.func_addr);
        }
        if let Some(v) = resolved
            && let Some(t) = v.to_u64()
            && cx.is_target_valid(py, t)?
        {
            return Ok(Decision::Done(Outcome::Resolved(vec![t])));
        }
        Ok(Decision::Done(Outcome::Unresolved))
    }

    fn before_twin(
        &mut self,
        py: Python<'_>,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<()> {
        if self.rust_newer.contains(&j.func_addr) {
            self.publish_one(py, cfg, j.func_addr)?;
        }
        Ok(())
    }

    fn after_twin(&mut self, py: Python<'_>, cfg: &Bound<'_, PyAny>, j: &JumpSite) -> PyResult<()> {
        self.import_model(py, cfg, j.func_addr)?;
        self.rust_newer.shift_remove(&j.func_addr);
        Ok(())
    }

    fn finish(&mut self, py: Python<'_>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        let funcs: Vec<u64> = self
            .cache
            .keys()
            .copied()
            .filter(|f| self.rust_newer.contains(f))
            .collect();
        for f in funcs {
            self.publish_one(py, cfg, f)?;
        }
        Ok(())
    }

    fn shadow_diffs(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Vec<ShadowDiff>> {
        let mut out = Vec::new();
        if let (Some((addr, slice)), Some(f)) = (self.last_slice.take(), &self.shadow_blade) {
            let r = f.bind(py).call1((cfg, addr))?;
            let (nodes, edges): (Vec<SliceLoc>, Vec<(SliceLoc, SliceLoc)>) = r.extract()?;
            cx.count("ConstantResolver:shadow_blade_compared");
            let rn: Vec<SliceLoc> = slice.nodes.keys().copied().collect();
            let re = slice.edges();
            if rn != nodes || re != edges {
                out.push((
                    "blade",
                    format!("{rn:?} {re:?}"),
                    format!("{nodes:?} {edges:?}"),
                ));
            }
        }
        let func = j.func_addr;
        let model = Self::py_model(py, cfg, func)?;
        let python_changed = !model.is_none()
            && !self
                .models
                .get(&func)
                .is_some_and(|m| m.bind(py).is(&model));
        let rust_changed = self.last_fcp_func.take() == Some(func);
        if python_changed || rust_changed {
            let py_rows = if model.is_none() {
                None
            } else {
                let count: usize = model
                    .getattr(intern!(py, "function_block_count"))?
                    .extract()?;
                table_from_py(&model.getattr(intern!(py, "replacements"))?)?.map(|r| (count, r))
            };
            let rust_rows = self.cache.get(&func).map(|e| {
                let rows: TableRows = e
                    .table
                    .entries
                    .iter()
                    .map(|(k, v)| (*k, v.iter().map(|(a, b)| (*a, *b)).collect()))
                    .collect();
                (e.function_block_count, rows)
            });
            cx.count("ConstantResolver:shadow_fcp_compared");
            if py_rows != rust_rows {
                let summary = |x: &Option<(usize, TableRows)>| match x {
                    None => "none".to_string(),
                    Some((c, rows)) => format!(
                        "count={c} locs={} vars={}",
                        rows.len(),
                        rows.iter().map(|r| r.1.len()).sum::<usize>()
                    ),
                };
                out.push(("fcp_table", summary(&rust_rows), summary(&py_rows)));
            }
            if !model.is_none() {
                self.models.insert(func, model.unbind());
            }
        }
        Ok(out)
    }
}
