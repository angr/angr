//! Drivers for CFGFast post-analysis passes.
//!
//! `OverlapScan` (`angr.rustylib.cfg_post.OverlapScan`) runs the two walks of
//! `CFGFast._remove_redundant_overlapping_blocks` over the sorted node keys of a `CfgGraph`: it picks the
//! function heads that may start with alignment nops, then yields the pairs of overlapping blocks in the order the
//! Python loop visits them. Python lifts and mutates the graph and the functions for each candidate, so every
//! filter is evaluated against the current graph when the walk reaches it, as in the Python loop.

use std::collections::HashSet;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::cfg_graph::CfgGraph;
use crate::recovery_functions::RecoveryFunctions;

type Key = (u64, i64);

#[pyclass(module = "angr.rustylib.cfg_post")]
pub struct OverlapScan {
    /// Sorted node keys; `append_keys` adds the nodes created by the first walk.
    keys: Vec<Key>,
    head_pos: usize,
    hooked: HashSet<u64>,
    plt_stubs: HashSet<u64>,
    /// Addresses at or above this one may be syscall addresses; `is_syscall_addr` decides.
    syscall_from: Option<u64>,
    is_syscall_addr: Option<Py<PyAny>>,
    /// Second walk: ARM addresses compare without the THUMB bit.
    is_arm: bool,
    pair_pos: usize,
    a_key: Option<Key>,
    pending_b: Option<Key>,
    removed: HashSet<Key>,
}

impl OverlapScan {
    /// `CFGBase._addr_hooked_or_syscall`
    fn hooked_or_syscall(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        if self.hooked.contains(&addr) {
            return Ok(true);
        }
        match (&self.syscall_from, &self.is_syscall_addr) {
            (Some(from), Some(check)) if addr >= *from => check.call1(py, (addr,))?.extract(py),
            _ => Ok(false),
        }
    }
}

#[pymethods]
impl OverlapScan {
    #[new]
    #[pyo3(signature = (graph, hooked, plt_stubs, syscall_from, is_syscall_addr, is_arm))]
    fn new(
        graph: &CfgGraph,
        hooked: HashSet<u64>,
        plt_stubs: HashSet<u64>,
        syscall_from: Option<u64>,
        is_syscall_addr: Option<Py<PyAny>>,
        is_arm: bool,
    ) -> PyResult<Self> {
        let mut keys = graph.with_store(|s| s.node_keys())?;
        keys.sort_unstable();
        Ok(OverlapScan {
            keys,
            head_pos: 0,
            hooked,
            plt_stubs,
            syscall_from,
            is_syscall_addr,
            is_arm,
            pair_pos: 0,
            a_key: None,
            pending_b: None,
            removed: HashSet::new(),
        })
    }

    /// The next function head (in key order) that is not a PLT stub, hook or syscall and has no incoming call edge:
    /// `(addr, id of model.get_any_node(addr))`. `functions` is the scan-time function store or any object
    /// supporting `in`.
    fn next_head(
        &mut self,
        py: Python<'_>,
        graph: &CfgGraph,
        functions: &Bound<'_, PyAny>,
    ) -> PyResult<Option<(u64, u64)>> {
        let store = functions.cast::<RecoveryFunctions>().ok();
        while self.head_pos < self.keys.len() {
            let addr = self.keys[self.head_pos].0;
            self.head_pos += 1;
            let is_func = match store {
                Some(s) => s.borrow().contains(addr),
                None => functions.contains(addr)?,
            };
            if !is_func || self.plt_stubs.contains(&addr) || self.hooked_or_syscall(py, addr)? {
                continue;
            }
            let found = graph.with_store(|s| {
                let Some(&id) = s.nodes_at_addr(addr)?.first() else {
                    return Ok(None);
                };
                Ok((!s.has_in_edge_with_jumpkind(id, "Ijk_Call")?).then_some(id))
            })?;
            if let Some(id) = found {
                return Ok(Some((addr, id)));
            }
        }
        Ok(None)
    }

    /// Adds the keys of the nodes created by the first walk; the second walk visits all keys in order.
    fn append_keys(&mut self, keys: Vec<Key>) {
        self.keys.extend(keys);
        self.keys.sort();
    }

    /// The next `(a_key, b_key)` whose blocks overlap; `resolve` must be called before asking for the next pair.
    fn next_overlap(&mut self, py: Python<'_>) -> PyResult<Option<(Key, Key)>> {
        if self.pending_b.is_some() {
            return Err(PyRuntimeError::new_err("resolve() the previous pair first"));
        }
        while self.pair_pos < self.keys.len() {
            let b = self.keys[self.pair_pos];
            self.pair_pos += 1;
            let Some(a) = self.a_key else {
                self.a_key = Some(self.keys[0]);
                continue;
            };
            if self.hooked_or_syscall(py, b.0)? || self.removed.contains(&b) {
                continue;
            }
            let (a_real, b_real) = if self.is_arm {
                (a.0 & 0xFFFF_FFFE, b.0 & 0xFFFF_FFFE)
            } else {
                (a.0, b.0)
            };
            if a_real <= b_real && (b_real as i128) < a_real as i128 + a.1 as i128 {
                self.pending_b = Some(b);
                return Ok(Some((a, b)));
            }
            self.a_key = Some(b);
        }
        Ok(None)
    }

    /// The outcome of the last pair: b was removed (a stays the current block), or a moves on to b.
    fn resolve(&mut self, b_removed: bool) -> PyResult<()> {
        let b = self
            .pending_b
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("no pending pair"))?;
        if b_removed {
            self.removed.insert(b);
        } else {
            self.a_key = Some(b);
        }
        Ok(())
    }
}

pub fn cfg_post(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OverlapScan>()?;
    Ok(())
}
