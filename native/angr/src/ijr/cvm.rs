//! `ConstantValueManager._build_mapping` on the Rust FCP: the register values JumpTableResolver's and
//! SyscallResolver's symbolic execution reads back through `reg_read_callback`.
//!
//! `FcpService` is separate from the `ResolverChain`: the Python resolvers that use it run while the chain is
//! dispatching, so it cannot be reached through the chain object.

use std::rc::Rc;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use rustc_hash::FxHashSet;

use super::cx::ResolveCx;
use super::fcp::{FcpRequest, FcpTable, LoadPolicy, Var, run_fcp, table_rows};
use super::u256::U256;
use crate::cfg_scan::LoaderSnapshot;
use crate::function_graph::EdgeKind;
use crate::vexlift::VexLifter;

/// `ConstantValueManager.mapping` as a Rust table.
#[pyclass(module = "angr.rustylib.ijr", unsendable, frozen)]
pub struct CvmMapping {
    table: Rc<FcpTable>,
}

#[pymethods]
impl CvmMapping {
    /// `mapping[CodeLocation(block_addr, stmt_idx, ins_addr=ins_addr)][VEXReg(offset, size)]`, or None.
    fn reg(
        &self,
        block_addr: u64,
        stmt_idx: i32,
        ins_addr: i64,
        offset: i32,
        size: u32,
    ) -> Option<U256> {
        self.table
            .get(&(block_addr, stmt_idx, ins_addr), &Var::Reg(offset, size))
    }

    fn rows<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, pyo3::types::PyList>> {
        table_rows(py, &self.table)
    }
}

/// The blocks `_build_mapping` propagates over: three successor levels from the entry (fake returns do not count)
/// and six predecessor levels from the jump block. Err(()) where Python would raise.
fn cvm_blocks(
    py: Python<'_>,
    store: &Bound<'_, crate::recovery_functions::RecoveryFunctions>,
    func_addr: u64,
    ij_addr: u64,
) -> PyResult<Result<Option<FxHashSet<u64>>, &'static str>> {
    let st = store.borrow();
    let Ok(rec) = st.rec(func_addr) else {
        return Ok(Err("no_function"));
    };
    let g = rec.graph.bind(py).borrow();
    let Some(start) = g.get_startpoint() else {
        // the mapping stays empty
        return Ok(Ok(None));
    };
    let mut blocks: FxHashSet<u32> = FxHashSet::default();
    let mut level_list: Vec<(u32, u32)> = vec![(start, 0)];
    while !level_list.is_empty() {
        let mut next = Vec::new();
        for (node, level) in level_list {
            if !blocks.insert(node) {
                continue;
            }
            if g.node_addr(node)? == ij_addr {
                continue;
            }
            if !g.in_local_view(node) {
                return Ok(Err("not_local"));
            }
            for succ in g.local_successors(node)? {
                let fake_ret = g.edge_kind(node, succ) == Some(EdgeKind::FakeReturn);
                let new_level = if fake_ret { level } else { level + 1 };
                if new_level <= 3 {
                    next.push((succ, new_level));
                }
            }
        }
        level_list = next;
    }
    let Some(ij_block) = g.block_node_at(ij_addr) else {
        return Ok(Err("no_jump_block"));
    };
    let mut preds = vec![ij_block];
    for _ in 0..6 {
        let mut new_preds = Vec::new();
        for node in preds {
            if !blocks.insert(node) {
                continue;
            }
            if !g.in_local_view(node) {
                return Ok(Err("not_local"));
            }
            new_preds.extend(g.local_predecessors(node)?);
        }
        preds = new_preds;
        if preds.is_empty() {
            break;
        }
    }
    let mut addrs = FxHashSet::default();
    for n in blocks {
        addrs.insert(g.node_addr(n)?);
    }
    Ok(Ok(Some(addrs)))
}

/// `ConstantValueManager._build_mapping()` for the jump at `ij_addr`: the FCP table, or why it must run in Python.
pub fn cvm_table(
    py: Python<'_>,
    cx: &mut ResolveCx,
    store: &Py<crate::recovery_functions::RecoveryFunctions>,
    func_addr: u64,
    ij_addr: u64,
) -> PyResult<Result<FcpTable, &'static str>> {
    let blocks = match cvm_blocks(py, store.bind(py), func_addr, ij_addr)? {
        Ok(b) => b,
        Err(d) => return Ok(Err(d)),
    };
    let Some(blocks) = blocks else {
        return Ok(Ok(FcpTable::default()));
    };
    let req = FcpRequest {
        func_addr,
        blocks: Some(&blocks),
        cross_insn_opt: true,
        load: LoadPolicy::Propagator,
    };
    run_fcp(py, cx, store, &req)
}

#[pyclass(module = "angr.rustylib.ijr", unsendable)]
pub struct FcpService {
    cx: ResolveCx,
    mismatches: Vec<Py<PyAny>>,
    /// Shadow mode: the caller keeps the Python mapping and compares.
    #[pyo3(get)]
    shadow: bool,
}

#[pymethods]
impl FcpService {
    #[new]
    fn new(
        lifter: Py<VexLifter>,
        snapshot: &LoaderSnapshot,
        ctx: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        let shadow = match ctx.get_item("shadow")? {
            Some(v) => v.is_truthy()?,
            None => false,
        };
        Ok(FcpService {
            cx: ResolveCx::new(snapshot.inner.clone(), lifter, ctx)?,
            mismatches: Vec::new(),
            shadow,
        })
    }

    /// `ConstantValueManager(project, cfg.kb, func, ij_addr)._build_mapping()`: a `CvmMapping`, or the reason the
    /// Python implementation must run.
    fn cvm_mapping<'py>(
        &mut self,
        cfg: &Bound<'py, PyAny>,
        func_addr: u64,
        ij_addr: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        let py = cfg.py();
        let Some(store) = self.cx.functions(py, cfg)? else {
            self.cx.count("ConstantValueManager:decline:no_store");
            return Ok("no_store".into_pyobject(py)?.into_any());
        };
        let blocks = match cvm_blocks(py, store.bind(py), func_addr, ij_addr)? {
            Ok(b) => b,
            Err(d) => {
                self.cx.count(&format!("ConstantValueManager:decline:{d}"));
                return Ok(d.into_pyobject(py)?.into_any());
            }
        };
        let table = match blocks {
            None => FcpTable::default(),
            Some(blocks) => {
                let req = FcpRequest {
                    func_addr,
                    blocks: Some(&blocks),
                    cross_insn_opt: true,
                    load: LoadPolicy::Propagator,
                };
                match run_fcp(py, &mut self.cx, &store, &req)? {
                    Ok(t) => t,
                    Err(d) => {
                        self.cx.count(&format!("ConstantValueManager:decline:{d}"));
                        return Ok(d.into_pyobject(py)?.into_any());
                    }
                }
            }
        };
        self.cx.count("ConstantValueManager:rust");
        Ok(Py::new(
            py,
            CvmMapping {
                table: Rc::new(table),
            },
        )?
        .into_bound(py)
        .into_any())
    }

    /// Shadow mode: record a difference between a Rust mapping and the Python one's rows.
    fn shadow_compare(
        &mut self,
        py: Python<'_>,
        func_addr: u64,
        ij_addr: u64,
        rust: &CvmMapping,
        python: Bound<'_, PyAny>,
    ) -> PyResult<bool> {
        let rows = table_rows(py, &rust.table)?;
        let same = rows.eq(&python)?;
        if same {
            self.cx.count("ConstantValueManager:shadow_same");
        } else {
            let d = PyDict::new(py);
            d.set_item("phase", "deferred")?;
            d.set_item("kind", "ConstantValueManager")?;
            d.set_item("addr", ij_addr)?;
            d.set_item("func_addr", func_addr)?;
            d.set_item("what", "mapping")?;
            d.set_item("rust", rows.len())?;
            d.set_item("python", python.len()?)?;
            self.mismatches.push(d.into_any().unbind());
        }
        Ok(same)
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.cx.stats {
            d.set_item(k, *v)?;
        }
        Ok(d)
    }

    fn mismatches<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.mismatches.iter().map(|m| m.bind(py)))
    }
}
