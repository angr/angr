//! CFGFast scan state.
//!
//! Exposed as `angr.rustylib.cfg_jobs`. The state of CFGFast's scan loop lives here: job records (`CFGJob` and the
//! function-edge descriptors a job carries), the FIFO job queue, the pending return-site jobs (`PendingJobs`),
//! per-function job accounting, the traced-address set and the `FunctionReturn` records. The per-block logic still
//! runs in Python; it sees `CFGJob` and edge objects as views over records.
//!
//! Records reference CFG nodes by `CfgGraph` id. A node that is removed from the graph while records still reference
//! it becomes an "orphan": the detached Python `CFGNode` is kept and the records point at it instead, which is what
//! holding the node object did before.
//!
//! Iteration orders that came from Python sets (`PendingJobs._updated_functions`, the `FunctionReturn` sets) are
//! reproduced with `cpython_set_order`, so the scan visits them in the same order as before.

use std::collections::VecDeque;
use std::hash::Hash;
use std::sync::{LazyLock, RwLock};

use pyo3::exceptions::{PyIndexError, PyStopIteration, PyTypeError};
use pyo3::prelude::*;
use pyo3::pyclass::CompareOp;
use pyo3::types::{PyDict, PyList, PyString, PyTuple};
use pyo3::{PyTraverseError, PyVisit, intern};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};

use crate::cfg_graph::CfgGraph;
use crate::cfg_scan::{LoaderSnapshot, Snapshot};
use crate::function_graph::{FunctionGraph, NodeKind};
use crate::recovery_functions::{NodeSpec, RecoveryFunctions};
use crate::vexlift::{IJK_INVALID, JUMPKIND_NAMES};

// ---------------------------------------------------------------------------------------------------------------
// Jumpkinds
// ---------------------------------------------------------------------------------------------------------------

/// Interned jumpkinds: the VEX `IRJumpKind` names in enum order (so `irjk - IJK_INVALID` is the id), then the
/// pseudo-jumpkinds CFGFast uses, then anything else seen at runtime.
struct JkTable {
    names: Vec<&'static str>,
    index: FxHashMap<&'static str, u16>,
}

static JK_TABLE: LazyLock<RwLock<JkTable>> = LazyLock::new(|| {
    let mut names: Vec<&'static str> = JUMPKIND_NAMES.to_vec();
    names.extend(["Ijk_FakeRet", "Ijk_Exception", "Ijk_NoHook"]);
    let index = names
        .iter()
        .enumerate()
        .map(|(i, &n)| (n, i as u16))
        .collect();
    RwLock::new(JkTable { names, index })
});

pub const JK_BORING: u16 = 1;
pub const JK_CALL: u16 = 2;
pub const JK_RET: u16 = 3;
pub const JK_FAKERET: u16 = JUMPKIND_NAMES.len() as u16;
pub const JK_EXCEPTION: u16 = JK_FAKERET + 1;

pub fn jk_intern(name: &str) -> u16 {
    if let Some(&i) = JK_TABLE.read().unwrap().index.get(name) {
        return i;
    }
    let mut t = JK_TABLE.write().unwrap();
    if let Some(&i) = t.index.get(name) {
        return i;
    }
    let s: &'static str = Box::leak(name.to_owned().into_boxed_str());
    let i = u16::try_from(t.names.len()).expect("too many distinct jumpkinds");
    t.names.push(s);
    t.index.insert(s, i);
    i
}

pub fn jk_name(jk: u16) -> &'static str {
    JK_TABLE.read().unwrap().names[jk as usize]
}

/// The jumpkind id of a VEX `IRJumpKind` value (as in `LiftSummary.jumpkind`).
pub fn jk_from_vex(irjk: u32) -> u16 {
    match irjk.checked_sub(IJK_INVALID) {
        Some(i) if (i as usize) < JUMPKIND_NAMES.len() => i as u16,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// CPython hash and set-iteration emulation
// ---------------------------------------------------------------------------------------------------------------

const PYHASH_MODULUS: u64 = (1u64 << 61) - 1;
/// `hash(None)` (a constant since Python 3.12).
pub const PY_HASH_NONE: i64 = 0xFCA8_6420;

/// `hash(v)` of a non-negative int.
pub fn py_hash_u64(v: u64) -> i64 {
    (v % PYHASH_MODULUS) as i64
}

pub fn py_hash_opt(v: Option<u64>) -> i64 {
    v.map_or(PY_HASH_NONE, py_hash_u64)
}

/// `hash(tuple)` given the hashes of its items (CPython's xxHash-based tuplehash, 64-bit).
pub fn py_hash_tuple(items: &[i64]) -> i64 {
    const P1: u64 = 11400714785074694791;
    const P2: u64 = 14029467366897019727;
    const P5: u64 = 2870177450012600261;
    let mut acc = P5;
    for &h in items {
        acc = acc.wrapping_add((h as u64).wrapping_mul(P2));
        acc = acc.rotate_left(31);
        acc = acc.wrapping_mul(P1);
    }
    acc = acc.wrapping_add((items.len() as u64) ^ (P5 ^ 3527539));
    if acc == u64::MAX {
        return 1546275796;
    }
    acc as i64
}

/// The iteration order of a CPython set built by `add`ing distinct elements with these hashes in this order and
/// never removing one (setobject.c: linear probing then perturbation, resize at 3/5 fill). Returns indices into
/// `hashes`.
pub fn cpython_set_order(hashes: &[i64]) -> Vec<usize> {
    const LINEAR_PROBES: usize = 9;
    const PERTURB_SHIFT: u32 = 5;
    const MINSIZE: usize = 8;

    fn insert_clean(table: &mut [Option<(usize, i64)>], mask: usize, idx: usize, hash: i64) {
        let mut perturb = hash as u64;
        let mut i = (hash as u64 as usize) & mask;
        loop {
            let probes = if i + LINEAR_PROBES <= mask {
                LINEAR_PROBES
            } else {
                0
            };
            for slot in &mut table[i..=i + probes] {
                if slot.is_none() {
                    *slot = Some((idx, hash));
                    return;
                }
            }
            perturb >>= PERTURB_SHIFT;
            i = (i
                .wrapping_mul(5)
                .wrapping_add(1)
                .wrapping_add(perturb as usize))
                & mask;
        }
    }

    let mut table: Vec<Option<(usize, i64)>> = vec![None; MINSIZE];
    let mut used = 0usize;
    for (idx, &hash) in hashes.iter().enumerate() {
        let mask = table.len() - 1;
        insert_clean(&mut table, mask, idx, hash);
        used += 1;
        // no dummies, so fill == used
        if used * 5 >= mask * 3 {
            let minused = if used > 50000 { used * 2 } else { used * 4 };
            let mut newsize = MINSIZE;
            while newsize <= minused {
                newsize <<= 1;
            }
            let mut newtable = vec![None; newsize];
            for &(i, h) in table.iter().flatten() {
                insert_clean(&mut newtable, newsize - 1, i, h);
            }
            table = newtable;
        }
    }
    table.into_iter().flatten().map(|(i, _)| i).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Insertion-ordered map with Python dict deletion semantics
// ---------------------------------------------------------------------------------------------------------------

/// A map that iterates in insertion order; removing a key and inserting it again moves it to the end (Python
/// `dict` semantics). Removal is O(1) amortized (tombstones, compacted when they outnumber live entries).
pub struct OrderedMap<K, V> {
    entries: Vec<Option<(K, V)>>,
    index: FxHashMap<K, usize>,
}

impl<K: Copy + Eq + Hash, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        OrderedMap {
            entries: Vec::new(),
            index: FxHashMap::default(),
        }
    }
}

impl<K: Copy + Eq + Hash, V> OrderedMap<K, V> {
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.index.contains_key(k)
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        self.index
            .get(k)
            .map(|&i| &self.entries[i].as_ref().unwrap().1)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let i = *self.index.get(k)?;
        Some(&mut self.entries[i].as_mut().unwrap().1)
    }

    /// Inserts at the end unless the key exists (then the value is left alone); returns the value.
    pub fn entry_or_insert_with(&mut self, k: K, f: impl FnOnce() -> V) -> &mut V {
        let i = match self.index.get(&k) {
            Some(&i) => i,
            None => {
                self.entries.push(Some((k, f())));
                let i = self.entries.len() - 1;
                self.index.insert(k, i);
                i
            }
        };
        &mut self.entries[i].as_mut().unwrap().1
    }

    pub fn remove(&mut self, k: &K) -> Option<V> {
        let i = self.index.remove(k)?;
        let (_, v) = self.entries[i].take().unwrap();
        while matches!(self.entries.last(), Some(None)) {
            self.entries.pop();
        }
        if self.entries.len() > 32 && self.entries.len() > 2 * self.index.len() {
            self.compact();
        }
        Some(v)
    }

    fn compact(&mut self) {
        self.entries.retain(Option::is_some);
        self.index.clear();
        for (i, e) in self.entries.iter().enumerate() {
            self.index.insert(e.as_ref().unwrap().0, i);
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.index.clear();
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&K, &V)> {
        self.entries.iter().flatten().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl DoubleEndedIterator<Item = K> + '_ {
        self.iter().map(|(k, _)| *k)
    }

    pub fn last_key(&self) -> Option<K> {
        self.keys().next_back()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.iter_mut().flatten().map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------------------------------------------

#[pyclass(
    eq,
    eq_int,
    hash,
    frozen,
    from_py_object,
    module = "angr.rustylib.cfg_jobs",
    name = "CFGJobType"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JobType {
    #[pyo3(name = "NORMAL")]
    Normal = 0,
    #[pyo3(name = "FUNCTION_PROLOGUE")]
    FunctionPrologue = 1,
    #[pyo3(name = "COMPLETE_SCANNING")]
    CompleteScanning = 2,
    #[pyo3(name = "IFUNC_HINTS")]
    IfuncHints = 3,
    #[pyo3(name = "DATAREF_HINTS")]
    DatarefHints = 4,
    #[pyo3(name = "EH_FRAME_HINTS")]
    EhFrameHints = 5,
}

#[pymethods]
impl JobType {
    #[getter]
    fn name(&self) -> &'static str {
        match self {
            JobType::Normal => "NORMAL",
            JobType::FunctionPrologue => "FUNCTION_PROLOGUE",
            JobType::CompleteScanning => "COMPLETE_SCANNING",
            JobType::IfuncHints => "IFUNC_HINTS",
            JobType::DatarefHints => "DATAREF_HINTS",
            JobType::EhFrameHints => "EH_FRAME_HINTS",
        }
    }

    #[getter]
    fn value(&self) -> u8 {
        *self as u8
    }
}

/// Where a record's CFG node lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NodeRef {
    /// A node of the scan's `CfgGraph`.
    Id(u64),
    /// A node removed from the graph; `ScanState.orphans[i]` is its detached `CFGNode`.
    Orphan(u32),
    /// Not bound yet: a Python-side object that carries the node object itself.
    Unbound,
}

/// A source CFG node: its identity (`CFGNode.__eq__` compares addr, size and SimProcedure name) and where it lives.
#[derive(Clone, Copy, Debug)]
pub struct SrcNode {
    pub addr: u64,
    pub size: i64,
    pub simproc: bool,
    pub node: NodeRef,
}

impl SrcNode {
    fn key(&self) -> (u64, i64, bool) {
        (self.addr, self.size, self.simproc)
    }
}

/// The `FunctionEdge` descriptors of cfg_fast.py, applied once the job's destination node exists.
#[derive(Clone, Debug)]
pub enum FuncEdge {
    Transition {
        src: Option<SrcNode>,
        dst_addr: u64,
        src_func_addr: u64,
        to_outside: bool,
        dst_func_addr: Option<u64>,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
        is_exception: bool,
    },
    Call {
        src: Option<SrcNode>,
        dst_addr: u64,
        ret_addr: Option<u64>,
        src_func_addr: u64,
        syscall: bool,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
    },
    FakeRet {
        src: Option<SrcNode>,
        dst_addr: u64,
        src_func_addr: u64,
        confirmed: Option<bool>,
    },
    Return {
        ret_from_addr: u64,
        ret_to_addr: u64,
        dst_func_addr: u64,
    },
}

impl FuncEdge {
    pub fn src(&self) -> Option<&SrcNode> {
        match self {
            FuncEdge::Transition { src, .. }
            | FuncEdge::Call { src, .. }
            | FuncEdge::FakeRet { src, .. } => src.as_ref(),
            FuncEdge::Return { .. } => None,
        }
    }

    fn src_mut(&mut self) -> Option<&mut SrcNode> {
        match self {
            FuncEdge::Transition { src, .. }
            | FuncEdge::Call { src, .. }
            | FuncEdge::FakeRet { src, .. } => src.as_mut(),
            FuncEdge::Return { .. } => None,
        }
    }
}

/// A `CFGJob`.
#[derive(Clone, Debug)]
pub struct JobRec {
    pub addr: u64,
    pub func_addr: u64,
    pub jumpkind: u16,
    pub ret_target: Option<u64>,
    pub last_addr: Option<u64>,
    pub src: Option<SrcNode>,
    pub src_ins_addr: Option<u64>,
    pub src_stmt_idx: Option<i64>,
    pub returning_source: Option<u64>,
    pub syscall: bool,
    pub job_type: JobType,
    pub gp: Option<u64>,
    pub func_edges: Vec<FuncEdge>,
}

impl JobRec {
    pub fn new(addr: u64, func_addr: u64, jumpkind: u16) -> Self {
        JobRec {
            addr,
            func_addr,
            jumpkind,
            ret_target: None,
            last_addr: None,
            src: None,
            src_ins_addr: None,
            src_stmt_idx: None,
            returning_source: None,
            syscall: false,
            job_type: JobType::Normal,
            gp: None,
            func_edges: Vec::new(),
        }
    }

    /// `CFGJob.__eq__`/`__hash__` compare every field but the function edges.
    pub fn key(&self) -> JobKey {
        JobKey {
            addr: self.addr,
            func_addr: self.func_addr,
            jumpkind: self.jumpkind,
            ret_target: self.ret_target,
            last_addr: self.last_addr,
            src: self.src.map(|s| s.key()),
            src_ins_addr: self.src_ins_addr,
            src_stmt_idx: self.src_stmt_idx,
            returning_source: self.returning_source,
            syscall: self.syscall,
            job_type: self.job_type,
            gp: self.gp,
        }
    }

    fn node_refs_mut(&mut self) -> impl Iterator<Item = &mut NodeRef> {
        self.src
            .as_mut()
            .into_iter()
            .chain(self.func_edges.iter_mut().filter_map(FuncEdge::src_mut))
            .map(|s| &mut s.node)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct JobKey {
    addr: u64,
    func_addr: u64,
    jumpkind: u16,
    ret_target: Option<u64>,
    last_addr: Option<u64>,
    src: Option<(u64, i64, bool)>,
    src_ins_addr: Option<u64>,
    src_stmt_idx: Option<i64>,
    returning_source: Option<u64>,
    syscall: bool,
    job_type: JobType,
    gp: Option<u64>,
}

/// An entry of a function's job set: a CFGJob (equal by value) or another object (an `IndirectJump`, equal by
/// identity).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum JobItem {
    Job(JobKey),
    Token(usize),
}

/// `(callee_func_addr, caller_func_addr, call_site_addr, return_to)`
pub type FunctionReturn = (Option<u64>, u64, u64, Option<u64>);

fn function_return_hash(fr: &FunctionReturn) -> i64 {
    py_hash_tuple(&[
        py_hash_opt(fr.0),
        py_hash_u64(fr.1),
        py_hash_u64(fr.2),
        py_hash_opt(fr.3),
    ])
}

// ---------------------------------------------------------------------------------------------------------------
// State containers
// ---------------------------------------------------------------------------------------------------------------

/// `CFGBase._jobs_to_analyze_per_function` and `_functions_without_jobs`.
#[derive(Default)]
pub struct JobAccounting {
    jobs: FxHashMap<u64, FxHashSet<JobItem>>,
    without_jobs: OrderedMap<u64, ()>,
}

impl JobAccounting {
    pub fn register(&mut self, func_addr: u64, item: JobItem) {
        let jobs = self.jobs.entry(func_addr).or_default();
        if jobs.is_empty() {
            self.without_jobs.remove(&func_addr);
        }
        jobs.insert(item);
    }

    pub fn deregister(&mut self, func_addr: u64, item: &JobItem) {
        let jobs = self.jobs.entry(func_addr).or_default();
        jobs.remove(item);
        if jobs.is_empty() {
            self.without_jobs.entry_or_insert_with(func_addr, || ());
        }
    }

    /// `_get_finished_functions`
    pub fn finished(&self) -> Vec<u64> {
        self.without_jobs.keys().collect()
    }

    /// `_cleanup_analysis_jobs`
    pub fn cleanup(&mut self, func_addrs: &[u64]) {
        for f in func_addrs {
            self.jobs.remove(f);
            self.without_jobs.remove(f);
        }
    }

    pub fn has_jobs(&self, func_addr: u64) -> bool {
        self.jobs.get(&func_addr).is_some_and(|s| !s.is_empty())
    }
}

/// `PendingJobs` of cfg_fast.py: return-site jobs bucketed by callee (`returning_source`), in insertion order.
#[derive(Default)]
pub struct PendingJobs {
    jobs: OrderedMap<Option<u64>, Vec<JobRec>>,
    returning: FxHashSet<Option<u64>>,
    /// The distinct `_updated_functions` additions since the last clear, in order.
    updated: OrderedMap<Option<u64>, ()>,
    count: usize,
}

impl PendingJobs {
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn add(&mut self, rec: JobRec) {
        self.jobs
            .entry_or_insert_with(rec.returning_source, Vec::new)
            .push(rec);
        self.count += 1;
    }

    fn pop_from(&mut self, key: Option<u64>) -> JobRec {
        let bucket = self.jobs.get_mut(&key).unwrap();
        let j = bucket.pop().unwrap();
        if bucket.is_empty() {
            self.jobs.remove(&key);
        }
        self.count -= 1;
        j
    }

    /// `PendingJobs.pop_job`
    pub fn pop(&mut self, returning: bool) -> Option<JobRec> {
        if self.count == 0 {
            return None;
        }
        if !returning {
            let key = if self.jobs.contains_key(&None) {
                None
            } else {
                self.jobs.last_key()?
            };
            return Some(self.pop_from(key));
        }
        let key = self
            .jobs
            .keys()
            .rev()
            .find(|k| self.returning.contains(k))?;
        Some(self.pop_from(key))
    }

    pub fn add_returning_function(&mut self, func_addr: Option<u64>) {
        self.returning.insert(func_addr);
        self.updated.entry_or_insert_with(func_addr, || ());
    }

    pub fn add_nonreturning_function(&mut self, func_addr: Option<u64>) {
        self.updated.entry_or_insert_with(func_addr, || ());
    }

    pub fn clear_updated_functions(&mut self) {
        self.updated.clear();
    }

    /// `_updated_functions` in the order a Python set iterates it.
    pub fn updated_functions(&self) -> Vec<Option<u64>> {
        let keys: Vec<Option<u64>> = self.updated.keys().collect();
        let hashes: Vec<i64> = keys.iter().map(|&k| py_hash_opt(k)).collect();
        cpython_set_order(&hashes)
            .into_iter()
            .map(|i| keys[i])
            .collect()
    }

    /// `PendingJobs.cleanup`: drops the jobs returning from functions now known not to return. `returning_of(addr)`
    /// gives `Some(func.returning)`, or None when the function does not exist (`warn` is then called per job).
    /// Removed jobs are handed to `removed` in the order they are deregistered.
    pub fn cleanup(
        &mut self,
        mut returning_of: impl FnMut(u64) -> PyResult<Option<Option<bool>>>,
        mut warn: impl FnMut(u64) -> PyResult<()>,
        mut removed: impl FnMut(&JobRec),
    ) -> PyResult<()> {
        let mut to_remove: Vec<(Option<u64>, Vec<usize>)> = Vec::new();
        for func_addr in self.updated_functions() {
            let Some(bucket) = self.jobs.get(&func_addr) else {
                continue;
            };
            for (i, pe) in bucket.iter().enumerate() {
                let Some(src) = pe.returning_source else {
                    continue;
                };
                match returning_of(src)? {
                    None => warn(src)?,
                    Some(Some(false)) => {
                        match to_remove.iter_mut().find(|(k, _)| *k == Some(src)) {
                            Some((_, v)) => v.push(i),
                            None => to_remove.push((Some(src), vec![i])),
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        for (key, indices) in to_remove {
            let bucket = self.jobs.get_mut(&key).unwrap();
            for &i in indices.iter().rev() {
                removed(&bucket[i]);
                bucket.remove(i);
                self.count -= 1;
            }
            if bucket.is_empty() {
                self.jobs.remove(&key);
            }
        }
        self.clear_updated_functions();
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &JobRec> {
        self.jobs.iter().flat_map(|(_, v)| v.iter())
    }

    fn records_mut(&mut self) -> impl Iterator<Item = &mut JobRec> {
        self.jobs.values_mut().flat_map(|v| v.iter_mut())
    }
}

/// `CFGFast._function_returns`: per callee, the distinct FunctionReturns in insertion order.
#[derive(Default)]
pub struct FunctionReturns {
    map: FxHashMap<Option<u64>, OrderedMap<FunctionReturn, ()>>,
}

impl FunctionReturns {
    pub fn add(&mut self, fr: FunctionReturn) {
        self.map
            .entry(fr.0)
            .or_default()
            .entry_or_insert_with(fr, || ());
    }

    pub fn contains(&self, callee: Option<u64>) -> bool {
        self.map.contains_key(&callee)
    }

    /// Removes the callee's FunctionReturns and returns them in the order the Python set iterated them.
    pub fn take(&mut self, callee: Option<u64>) -> Option<Vec<FunctionReturn>> {
        let set = self.map.remove(&callee)?;
        let frs: Vec<FunctionReturn> = set.keys().collect();
        let hashes: Vec<i64> = frs.iter().map(function_return_hash).collect();
        Some(
            cpython_set_order(&hashes)
                .into_iter()
                .map(|i| frs[i])
                .collect(),
        )
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ScanState
// ---------------------------------------------------------------------------------------------------------------

/// Python objects the scan state reaches into: the CFG graph and the scan-time function store.
struct Ctx {
    graph: Py<CfgGraph>,
    store: Py<RecoveryFunctions>,
    /// The RecoveryFunctionManager over `store`; edges take the Rust path only while it is `kb.functions`.
    manager: Py<PyAny>,
    kb: Py<PyAny>,
    sim_procedures: Py<PyDict>,
    /// `(SimMemoryError, SimEngineError)`: what `_function_add_transition_edge`/`_function_add_call_edge` swallow.
    errors: Py<PyTuple>,
}

#[pyclass(module = "angr.rustylib.cfg_jobs")]
pub struct ScanState {
    pub queue: VecDeque<JobRec>,
    /// `ForwardAnalysis._job_map` keys.
    pub queued_addrs: FxHashSet<u64>,
    pub pending: PendingJobs,
    pub accounting: JobAccounting,
    pub traced: FxHashSet<u64>,
    /// `_completed_functions`
    pub completed: FxHashSet<u64>,
    pub function_returns: FunctionReturns,
    /// Registered non-CFGJob objects, kept alive so their ids stay unique.
    tokens: FxHashMap<usize, Py<PyAny>>,
    orphans: Vec<Py<PyAny>>,
    orphan_index: FxHashMap<usize, u32>,
    /// `resolver(node_id) -> CFGNode`
    resolver: Option<Py<PyAny>>,
    ctx: Option<Ctx>,
}

impl ScanState {
    /// Binds a Python-side source node: a node of the scan graph becomes its id, anything else an orphan.
    fn bind_node(&mut self, py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<NodeRef> {
        let store = obj.getattr(intern!(py, "_store"))?;
        let in_graph = match &self.ctx {
            Some(ctx) => store.is(ctx.graph.bind(py)),
            None => !store.is_none(),
        };
        if in_graph {
            return Ok(NodeRef::Id(obj.getattr(intern!(py, "_id"))?.extract()?));
        }
        Ok(NodeRef::Orphan(self.orphan_of(obj)))
    }

    fn orphan_of(&mut self, obj: &Bound<'_, PyAny>) -> u32 {
        let ptr = obj.as_ptr() as usize;
        if let Some(&k) = self.orphan_index.get(&ptr) {
            return k;
        }
        let k = self.orphans.len() as u32;
        self.orphans.push(obj.clone().unbind());
        self.orphan_index.insert(ptr, k);
        k
    }

    fn bind_src(
        &mut self,
        py: Python<'_>,
        src: Option<SrcNode>,
        obj: Option<&Py<PyAny>>,
    ) -> PyResult<Option<SrcNode>> {
        let Some(mut s) = src else { return Ok(None) };
        if s.node == NodeRef::Unbound {
            let obj =
                obj.ok_or_else(|| PyTypeError::new_err("unbound source node without an object"))?;
            s.node = self.bind_node(py, obj.bind(py))?;
        }
        Ok(Some(s))
    }

    /// The bound source node of a `CFGNode` object, as a `CFGJob(src_node=node)` has it once queued.
    pub(crate) fn src_node(
        &mut self,
        py: Python<'_>,
        node: &Bound<'_, PyAny>,
    ) -> PyResult<SrcNode> {
        let mut s = src_of(py, node)?;
        s.node = self.bind_node(py, node)?;
        Ok(s)
    }

    /// `_deregister_analysis_job(func_addr, obj)` for an object that is not a CFGJob (an `IndirectJump`).
    pub(crate) fn deregister_object(
        &mut self,
        func_addr: u64,
        obj: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let item = self.item_of(obj)?;
        self.accounting.deregister(func_addr, &item);
        Ok(())
    }

    /// The record of a Python CFGJob, with its nodes bound.
    pub(crate) fn ingest(&mut self, py: Python<'_>, job: &Bound<'_, PyAny>) -> PyResult<JobRec> {
        let job = job.cast::<PyCFGJob>()?.borrow();
        let mut rec = job.rec.clone();
        rec.src = self.bind_src(py, rec.src, job.src_obj.as_ref())?;
        rec.func_edges = match &job.edges {
            None => Vec::new(),
            Some(JobEdges::Rec(v)) => v.iter().map(|(e, _)| e.clone()).collect(),
            Some(JobEdges::Py(v)) => {
                let mut out = Vec::with_capacity(v.len());
                for e in v {
                    let (mut edge, obj) = edge_of(e.bind(py))?;
                    if let Some(s) = edge.src_mut()
                        && s.node == NodeRef::Unbound
                    {
                        let obj = obj.ok_or_else(|| {
                            PyTypeError::new_err("unbound source node without an object")
                        })?;
                        s.node = self.bind_node(py, obj.bind(py))?;
                    }
                    out.push(edge);
                }
                out
            }
        };
        Ok(rec)
    }

    fn item_of(&mut self, job: &Bound<'_, PyAny>) -> PyResult<JobItem> {
        if let Ok(j) = job.cast::<PyCFGJob>() {
            return Ok(JobItem::Job(j.borrow().rec.key()));
        }
        let token = job.as_ptr() as usize;
        self.tokens
            .entry(token)
            .or_insert_with(|| job.clone().unbind());
        Ok(JobItem::Token(token))
    }

    pub(crate) fn resolve(&self, py: Python<'_>, node: NodeRef) -> PyResult<Py<PyAny>> {
        match node {
            NodeRef::Orphan(k) => Ok(self.orphans[k as usize].clone_ref(py)),
            NodeRef::Id(id) => match &self.resolver {
                Some(r) => Ok(r.call1(py, (id,))?),
                None => Err(PyTypeError::new_err("the scan state has no node resolver")),
            },
            NodeRef::Unbound => Err(PyTypeError::new_err("cannot resolve an unbound node")),
        }
    }

    fn refs(&self, py: Python<'_>) -> Refs {
        Refs {
            resolver: self.resolver.as_ref().map(|r| r.clone_ref(py)),
            ctx: self.ctx.as_ref().map(|c| CtxRefs {
                graph: c.graph.clone_ref(py),
                store: c.store.clone_ref(py),
                manager: c.manager.clone_ref(py),
                kb: c.kb.clone_ref(py),
                sim_procedures: c.sim_procedures.clone_ref(py),
                errors: c.errors.clone_ref(py),
            }),
        }
    }

    /// A Python view of a record. Its nodes are resolved now, so a node removed while the job is processed stays
    /// the object it was (as when jobs held CFGNode objects).
    pub fn emit(slf: &Bound<'_, Self>, mut rec: JobRec) -> PyResult<Py<PyCFGJob>> {
        let py = slf.py();
        let this = slf.borrow();
        let src_obj = match rec.src {
            Some(s) => Some(this.resolve(py, s.node)?),
            None => None,
        };
        let job_node = rec.src.map(|s| s.node);
        let mut edges = Vec::with_capacity(rec.func_edges.len());
        for e in std::mem::take(&mut rec.func_edges) {
            let obj = match e.src() {
                None => None,
                Some(s) if Some(s.node) == job_node => src_obj.as_ref().map(|o| o.clone_ref(py)),
                Some(s) => Some(this.resolve(py, s.node)?),
            };
            edges.push((e, obj));
        }
        drop(this);
        Py::new(
            py,
            PyCFGJob {
                rec,
                src_obj,
                edges: if edges.is_empty() {
                    None
                } else {
                    Some(JobEdges::Rec(edges))
                },
            },
        )
    }

    /// Pushes a job record onto the queue (`ForwardAnalysis._insert_job`).
    pub fn push_job(&mut self, rec: JobRec) {
        self.queued_addrs.insert(rec.addr);
        self.queue.push_back(rec);
    }

    /// Pops the front job; `key_addr` is the address of the job the caller peeked (`_job_map` is popped by it).
    pub fn pop_front(&mut self, key_addr: u64) -> Option<JobRec> {
        self.queued_addrs.remove(&key_addr);
        self.queue.pop_front()
    }

    pub fn register_job(&mut self, func_addr: u64, rec: &JobRec) {
        self.accounting.register(func_addr, JobItem::Job(rec.key()));
    }

    pub fn deregister_job(&mut self, func_addr: u64, rec: &JobRec) {
        self.accounting
            .deregister(func_addr, &JobItem::Job(rec.key()));
    }

    /// `ForwardAnalysis._remove_job` with a predicate over records.
    pub fn remove_jobs(&mut self, mut pred: impl FnMut(&JobRec) -> bool) -> usize {
        let before = self.queue.len();
        let mut removed_addrs = Vec::new();
        self.queue.retain(|j| {
            if pred(j) {
                removed_addrs.push(j.addr);
                false
            } else {
                true
            }
        });
        for a in removed_addrs {
            self.queued_addrs.remove(&a);
        }
        before - self.queue.len()
    }

    /// Re-points every record that references node `id` at the node object, which is about to be removed.
    pub fn orphan_node(&mut self, id: u64, node: &Bound<'_, PyAny>) {
        let target = NodeRef::Id(id);
        let referenced = self
            .queue
            .iter_mut()
            .chain(self.pending.records_mut())
            .any(|j| j.node_refs_mut().any(|r| *r == target));
        if !referenced {
            return;
        }
        let k = NodeRef::Orphan(self.orphan_of(node));
        for j in self.queue.iter_mut().chain(self.pending.records_mut()) {
            for r in j.node_refs_mut() {
                if *r == target {
                    *r = k;
                }
            }
        }
    }
}

/// Cloned references out of a ScanState, so no borrow is held while Python runs.
struct Refs {
    resolver: Option<Py<PyAny>>,
    ctx: Option<CtxRefs>,
}

struct CtxRefs {
    graph: Py<CfgGraph>,
    store: Py<RecoveryFunctions>,
    manager: Py<PyAny>,
    kb: Py<PyAny>,
    sim_procedures: Py<PyDict>,
    errors: Py<PyTuple>,
}

impl CtxRefs {
    fn functions_are_ours(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self
            .kb
            .bind(py)
            .getattr(intern!(py, "functions"))?
            .is(self.manager.bind(py)))
    }
}

#[pymethods]
impl ScanState {
    #[new]
    #[pyo3(signature = (resolver=None))]
    fn py_new(resolver: Option<Py<PyAny>>) -> Self {
        ScanState {
            queue: VecDeque::new(),
            queued_addrs: FxHashSet::default(),
            pending: PendingJobs::default(),
            accounting: JobAccounting::default(),
            traced: FxHashSet::default(),
            completed: FxHashSet::default(),
            function_returns: FunctionReturns::default(),
            tokens: FxHashMap::default(),
            orphans: Vec::new(),
            orphan_index: FxHashMap::default(),
            resolver,
            ctx: None,
        }
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for t in self.tokens.values() {
            visit.call(t)?;
        }
        for o in &self.orphans {
            visit.call(o)?;
        }
        if let Some(r) = &self.resolver {
            visit.call(r)?;
        }
        if let Some(c) = &self.ctx {
            visit.call(&c.graph)?;
            visit.call(&c.store)?;
            visit.call(&c.manager)?;
            visit.call(&c.kb)?;
            visit.call(&c.sim_procedures)?;
            visit.call(&c.errors)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.tokens.clear();
        self.orphans.clear();
        self.orphan_index.clear();
        self.resolver = None;
        self.ctx = None;
    }

    /// Lets edges be applied in Rust: `graph` is the scan's CfgGraph, `manager` the RecoveryFunctionManager over
    /// `store`, `sim_procedures` the project's hook dict.
    fn bind(
        &mut self,
        graph: Py<CfgGraph>,
        store: Py<RecoveryFunctions>,
        manager: Py<PyAny>,
        kb: Py<PyAny>,
        sim_procedures: Py<PyDict>,
        errors: Py<PyTuple>,
    ) {
        self.ctx = Some(Ctx {
            graph,
            store,
            manager,
            kb,
            sim_procedures,
            errors,
        });
    }

    // --- job queue ------------------------------------------------------------------------------------------

    /// `_insert_job`
    fn push(slf: &Bound<'_, Self>, job: &Bound<'_, PyAny>) -> PyResult<()> {
        let py = slf.py();
        let mut this = slf.borrow_mut();
        let rec = this.ingest(py, job)?;
        this.push_job(rec);
        Ok(())
    }

    fn queue_len(&self) -> usize {
        self.queue.len()
    }

    /// The front job, still queued.
    fn peek(slf: &Bound<'_, Self>) -> PyResult<Option<Py<PyCFGJob>>> {
        let rec = slf.borrow().queue.front().cloned();
        rec.map(|r| Self::emit(slf, r)).transpose()
    }

    /// `_peek_job`
    fn peek_at(slf: &Bound<'_, Self>, pos: usize) -> PyResult<Py<PyCFGJob>> {
        let rec = slf.borrow().queue.get(pos).cloned();
        match rec {
            Some(r) => Self::emit(slf, r),
            None => Err(PyIndexError::new_err(pos)),
        }
    }

    /// Drops the front job; `key_addr` is the address of the job peeked before `_pre_job_handling`.
    #[pyo3(name = "pop_front")]
    fn py_pop_front(&mut self, key_addr: u64) -> PyResult<()> {
        match self.pop_front(key_addr) {
            Some(_) => Ok(()),
            None => Err(PyIndexError::new_err("pop from an empty deque")),
        }
    }

    fn has_job_addr(&self, addr: u64) -> bool {
        self.queued_addrs.contains(&addr)
    }

    fn queued_jobs(slf: &Bound<'_, Self>) -> PyResult<Vec<Py<PyCFGJob>>> {
        let recs: Vec<JobRec> = slf.borrow().queue.iter().cloned().collect();
        recs.into_iter().map(|r| Self::emit(slf, r)).collect()
    }

    /// `_remove_jobs_by_source_node_addr`
    fn remove_jobs_by_src_addr(&mut self, addr: u64) -> usize {
        self.remove_jobs(|j| j.src.is_some_and(|s| s.addr == addr))
    }

    /// Removes the queued jobs whose `mask` entry is true (`_remove_job` with a Python predicate).
    fn remove_jobs_by_mask(&mut self, mask: Vec<bool>) -> usize {
        let mut it = mask.into_iter();
        self.remove_jobs(|_| it.next().unwrap_or(false))
    }

    /// Call before removing node `id` from the graph: queued and pending records keep `node` instead.
    #[pyo3(name = "orphan_node")]
    fn py_orphan_node(&mut self, id: u64, node: &Bound<'_, PyAny>) {
        self.orphan_node(id, node);
    }

    // --- per-function job accounting -------------------------------------------------------------------------

    #[pyo3(name = "register_job")]
    fn py_register_job(&mut self, func_addr: u64, job: &Bound<'_, PyAny>) -> PyResult<()> {
        let item = self.item_of(job)?;
        self.accounting.register(func_addr, item);
        Ok(())
    }

    #[pyo3(name = "deregister_job")]
    fn py_deregister_job(&mut self, func_addr: u64, job: &Bound<'_, PyAny>) -> PyResult<()> {
        let item = self.item_of(job)?;
        self.accounting.deregister(func_addr, &item);
        Ok(())
    }

    fn finished_functions(&self) -> Vec<u64> {
        self.accounting.finished()
    }

    fn cleanup_analysis_jobs(&mut self, func_addrs: Vec<u64>) {
        self.accounting.cleanup(&func_addrs);
    }

    fn function_has_jobs(&self, func_addr: u64) -> bool {
        self.accounting.has_jobs(func_addr)
    }

    /// `_make_completed_functions` without the `_function_completed` calls: marks the finished functions completed,
    /// cleans up their jobs, and returns the newly completed ones whose `_function_completed` can have an effect, in
    /// finished order. `filter`: 0 none, 1 AMD64, 2 X86. None (nothing done) while kb.functions is not the store's.
    fn take_completed(
        &mut self,
        py: Python<'_>,
        snapshot: &Bound<'_, LoaderSnapshot>,
        filter: u8,
    ) -> PyResult<Option<Vec<u64>>> {
        let ScanState {
            accounting,
            completed,
            ctx,
            ..
        } = self;
        let Some(ctx) = ctx.as_ref() else {
            return Ok(None);
        };
        if !ctx
            .kb
            .bind(py)
            .getattr(intern!(py, "functions"))?
            .is(ctx.manager.bind(py))
        {
            return Ok(None);
        }
        let finished = accounting.finished();
        let store = ctx.store.bind(py).borrow();
        let snap: &Snapshot = &snapshot.get().inner;
        let mut out = Vec::new();
        for &f in &finished {
            if completed.insert(f) && completed_candidate(py, &store, snap, f, filter) {
                out.push(f);
            }
        }
        accounting.cleanup(&finished);
        Ok(Some(out))
    }

    // --- FunctionReturns -------------------------------------------------------------------------------------

    fn add_function_return(
        &mut self,
        callee_func_addr: Option<u64>,
        caller_func_addr: u64,
        call_site_addr: u64,
        return_to: Option<u64>,
    ) {
        self.function_returns.add((
            callee_func_addr,
            caller_func_addr,
            call_site_addr,
            return_to,
        ));
    }

    fn has_function_returns(&self, callee_func_addr: Option<u64>) -> bool {
        self.function_returns.contains(callee_func_addr)
    }

    /// Removes and returns the callee's `(callee, caller, call_site, return_to)` tuples, or None.
    fn take_function_returns(
        &mut self,
        callee_func_addr: Option<u64>,
    ) -> Option<Vec<FunctionReturn>> {
        self.function_returns.take(callee_func_addr)
    }

    // --- views -----------------------------------------------------------------------------------------------

    #[getter]
    fn pending(slf: &Bound<'_, Self>) -> PendingJobsView {
        PendingJobsView {
            scan: slf.clone().unbind(),
        }
    }

    #[getter]
    fn traced(slf: &Bound<'_, Self>) -> TracedAddresses {
        TracedAddresses {
            scan: slf.clone().unbind(),
        }
    }

    #[getter]
    fn completed(slf: &Bound<'_, Self>) -> CompletedFunctions {
        CompletedFunctions {
            scan: slf.clone().unbind(),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<ScanState: {} queued, {} pending, {} traced>",
            self.queue.len(),
            self.pending.len(),
            self.traced.len()
        )
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Applying function edges
// ---------------------------------------------------------------------------------------------------------------

enum Src<'py> {
    Id(u64),
    Obj(Bound<'py, PyAny>),
}

impl Refs {
    /// Edges take the Rust path only while `kb.functions` is the scan's RecoveryFunctionManager (make_functions
    /// replaces it); otherwise the context is dropped and the `_function_add_*` helpers run.
    fn for_apply(mut self, py: Python<'_>) -> PyResult<Self> {
        if let Some(ctx) = &self.ctx
            && !ctx.functions_are_ours(py)?
        {
            self.ctx = None;
        }
        Ok(self)
    }

    fn resolve<'py>(&self, py: Python<'py>, id: u64) -> PyResult<Bound<'py, PyAny>> {
        match &self.resolver {
            Some(r) => Ok(r.bind(py).call1((id,))?),
            None => Err(PyTypeError::new_err("the scan state has no node resolver")),
        }
    }

    fn src_obj<'py>(&self, py: Python<'py>, src: Option<Src<'py>>) -> PyResult<Bound<'py, PyAny>> {
        match src {
            None => Ok(py.None().into_bound(py)),
            Some(Src::Obj(o)) => Ok(o),
            Some(Src::Id(id)) => self.resolve(py, id),
        }
    }
}

fn first_node_at(ctx: &CtxRefs, py: Python<'_>, addr: u64) -> PyResult<Option<u64>> {
    ctx.graph.bind(py).get().first_node_at_addr(addr)
}

fn py_spec(v: Bound<'_, PyAny>) -> PyResult<NodeSpec> {
    v.extract()
}

/// `CFGFast._snippet_spec(cfg_node=...)` for a node of the scan graph.
fn spec_of_id(
    ctx: &CtxRefs,
    refs: &Refs,
    py: Python<'_>,
    cfg: &Bound<'_, PyAny>,
    id: u64,
) -> PyResult<NodeSpec> {
    let g = ctx.graph.bind(py).get();
    let (addr, size, simprocedure_name) = g.node_view(id)?;
    if let Some(hooker) = ctx.sim_procedures.bind(py).get_item(addr)? {
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
    kwargs.set_item(intern!(py, "cfg_node"), refs.resolve(py, id)?)?;
    py_spec(cfg.call_method(intern!(py, "_snippet_spec"), (), Some(&kwargs))?)
}

/// `CFGFast._snippet_spec(addr=..., base_state=self._base_state)`
fn spec_of_addr(py: Python<'_>, cfg: &Bound<'_, PyAny>, addr: u64) -> PyResult<NodeSpec> {
    let kwargs = PyDict::new(py);
    kwargs.set_item(intern!(py, "addr"), addr)?;
    kwargs.set_item(
        intern!(py, "base_state"),
        cfg.getattr(intern!(py, "_base_state"))?,
    )?;
    py_spec(cfg.call_method(intern!(py, "_snippet_spec"), (), Some(&kwargs))?)
}

fn swallow(py: Python<'_>, ctx: &CtxRefs, r: PyResult<()>) -> PyResult<()> {
    match r {
        Err(e) if e.is_instance(py, ctx.errors.bind(py).as_any()) => Ok(()),
        r => r,
    }
}

fn apply_edge<'py>(
    py: Python<'py>,
    refs: &Refs,
    cfg: &Bound<'py, PyAny>,
    e: &FuncEdge,
    src: Option<Src<'py>>,
) -> PyResult<()> {
    let fast_ctx = refs.ctx.as_ref();
    let fast = fast_ctx.is_some()
        && (matches!(src, Some(Src::Id(_))) || matches!(e, FuncEdge::Return { .. }));
    if !fast {
        return apply_edge_py(py, refs, cfg, e, src);
    }
    let ctx = fast_ctx.unwrap();
    let store = ctx.store.bind(py);
    let src_id = match src {
        Some(Src::Id(id)) => Some(id),
        _ => None,
    };
    match *e {
        FuncEdge::Transition {
            dst_addr,
            src_func_addr,
            to_outside,
            dst_func_addr,
            stmt_idx,
            ins_addr,
            is_exception,
            ..
        } => {
            let g = ctx.graph.bind(py).get();
            let dst_node = first_node_at(ctx, py, dst_addr)?;
            let mut to_outside = to_outside;
            if !to_outside
                && let Some(n) = dst_node
                && g.node_func(n)? != Some(src_func_addr)
            {
                to_outside = true;
            }
            // _function_add_transition_edge
            let r = (|| {
                let target = match dst_node {
                    None => spec_of_addr(py, cfg, dst_addr)?,
                    Some(n) => spec_of_id(ctx, refs, py, cfg, n)?,
                };
                let from = spec_of_id(ctx, refs, py, cfg, src_id.unwrap())?;
                if to_outside {
                    RecoveryFunctions::add_outside_transition_to(
                        store,
                        src_func_addr,
                        from,
                        Some(target),
                        dst_func_addr,
                        ins_addr,
                        stmt_idx,
                        is_exception,
                    )
                } else {
                    RecoveryFunctions::add_transition_to(
                        store,
                        src_func_addr,
                        from,
                        target,
                        ins_addr,
                        stmt_idx,
                        is_exception,
                    )
                }
            })();
            swallow(py, ctx, r)
        }
        FuncEdge::Call {
            dst_addr,
            src_func_addr,
            syscall,
            stmt_idx,
            ins_addr,
            ..
        } => {
            // _function_add_call_edge
            let r = (|| {
                let from = spec_of_id(ctx, refs, py, cfg, src_id.unwrap())?;
                RecoveryFunctions::add_call_to(
                    store,
                    src_func_addr,
                    from,
                    Some(dst_addr),
                    None,
                    syscall,
                    stmt_idx,
                    ins_addr,
                    false,
                )
            })();
            swallow(py, ctx, r)
        }
        FuncEdge::FakeRet {
            dst_addr,
            src_func_addr,
            confirmed,
            ..
        } => {
            // _function_add_fakeret_edge: next(nodes_by_addr(addr)) without a default
            let Some(n) = first_node_at(ctx, py, dst_addr)? else {
                return Err(PyStopIteration::new_err(()));
            };
            let target = spec_of_id(ctx, refs, py, cfg, n)?;
            let from = spec_of_id(ctx, refs, py, cfg, src_id.unwrap())?;
            RecoveryFunctions::add_fakeret_to(
                store,
                src_func_addr,
                from,
                target,
                confirmed,
                None,
                false,
                None,
            )
        }
        FuncEdge::Return {
            ret_from_addr,
            ret_to_addr,
            dst_func_addr,
        } => {
            // _function_add_return_edge
            let (target, to_outside) = match first_node_at(ctx, py, ret_to_addr)? {
                None => (spec_of_addr(py, cfg, ret_to_addr)?, false),
                Some(n) => {
                    let func = ctx.graph.bind(py).get().node_func(n)?;
                    (
                        spec_of_id(ctx, refs, py, cfg, n)?,
                        func != Some(dst_func_addr),
                    )
                }
            };
            RecoveryFunctions::add_return_from_call(
                store,
                dst_func_addr,
                ret_from_addr,
                target,
                to_outside,
            )
        }
    }
}

/// The edge `apply` methods of cfg_fast.py, through the CFGFast `_function_add_*` helpers.
fn apply_edge_py<'py>(
    py: Python<'py>,
    refs: &Refs,
    cfg: &Bound<'py, PyAny>,
    e: &FuncEdge,
    src: Option<Src<'py>>,
) -> PyResult<()> {
    match *e {
        FuncEdge::Transition {
            dst_addr,
            src_func_addr,
            to_outside,
            dst_func_addr,
            stmt_idx,
            ins_addr,
            is_exception,
            ..
        } => {
            let mut to_outside = to_outside;
            if !to_outside {
                let kwargs = PyDict::new(py);
                kwargs.set_item(intern!(py, "force_fastpath"), true)?;
                let dst_node = cfg.getattr(intern!(py, "model"))?.call_method(
                    intern!(py, "get_any_node"),
                    (dst_addr,),
                    Some(&kwargs),
                )?;
                if !dst_node.is_none()
                    && dst_node
                        .getattr(intern!(py, "function_address"))?
                        .ne(src_func_addr)?
                {
                    to_outside = true;
                }
            }
            let kwargs = PyDict::new(py);
            kwargs.set_item(intern!(py, "to_outside"), to_outside)?;
            kwargs.set_item(intern!(py, "dst_func_addr"), dst_func_addr)?;
            kwargs.set_item(intern!(py, "stmt_idx"), stmt_idx)?;
            kwargs.set_item(intern!(py, "ins_addr"), ins_addr)?;
            kwargs.set_item(intern!(py, "is_exception"), is_exception)?;
            let src = refs.src_obj(py, src)?;
            cfg.call_method(
                intern!(py, "_function_add_transition_edge"),
                (dst_addr, src, src_func_addr),
                Some(&kwargs),
            )?;
        }
        FuncEdge::Call {
            dst_addr,
            src_func_addr,
            syscall,
            stmt_idx,
            ins_addr,
            ..
        } => {
            let kwargs = PyDict::new(py);
            kwargs.set_item(intern!(py, "syscall"), syscall)?;
            kwargs.set_item(intern!(py, "stmt_idx"), stmt_idx)?;
            kwargs.set_item(intern!(py, "ins_addr"), ins_addr)?;
            let src = refs.src_obj(py, src)?;
            cfg.call_method(
                intern!(py, "_function_add_call_edge"),
                (dst_addr, src, src_func_addr),
                Some(&kwargs),
            )?;
        }
        FuncEdge::FakeRet {
            dst_addr,
            src_func_addr,
            confirmed,
            ..
        } => {
            let kwargs = PyDict::new(py);
            kwargs.set_item(intern!(py, "confirmed"), confirmed)?;
            let src = refs.src_obj(py, src)?;
            cfg.call_method(
                intern!(py, "_function_add_fakeret_edge"),
                (dst_addr, src, src_func_addr),
                Some(&kwargs),
            )?;
        }
        FuncEdge::Return {
            ret_from_addr,
            ret_to_addr,
            dst_func_addr,
        } => {
            cfg.call_method1(
                intern!(py, "_function_add_return_edge"),
                (ret_from_addr, ret_to_addr, dst_func_addr),
            )?;
        }
    }
    Ok(())
}

/// The scan state of a CFGFast object, if it has one.
fn scan_of<'py>(
    py: Python<'py>,
    cfg: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, ScanState>>> {
    let scan = cfg.getattr(intern!(py, "_scan"))?;
    if scan.is_none() {
        return Ok(None);
    }
    Ok(Some(scan.cast_into::<ScanState>()?))
}

impl ScanState {
    /// Applies function edges of a stored record (nodes bound) in order.
    pub fn apply_edges(
        slf: &Bound<'_, Self>,
        cfg: &Bound<'_, PyAny>,
        edges: &[FuncEdge],
    ) -> PyResult<()> {
        let py = slf.py();
        let refs = slf.borrow().refs(py).for_apply(py)?;
        for e in edges {
            let src = match e.src() {
                None => None,
                Some(s) => Some(match s.node {
                    NodeRef::Id(id) => Src::Id(id),
                    NodeRef::Orphan(k) => {
                        Src::Obj(slf.borrow().orphans[k as usize].bind(py).clone())
                    }
                    NodeRef::Unbound => {
                        return Err(PyTypeError::new_err("unbound source node in a stored edge"));
                    }
                }),
            };
            apply_edge(py, &refs, cfg, e, src)?;
        }
        Ok(())
    }
}

fn refs_of(py: Python<'_>, cfg: &Bound<'_, PyAny>) -> PyResult<Refs> {
    match scan_of(py, cfg)? {
        Some(scan) => scan.borrow().refs(py).for_apply(py),
        None => Ok(Refs {
            resolver: None,
            ctx: None,
        }),
    }
}

/// The source of an edge held by a Python object: a node attached to the scan graph goes by id (the Rust path).
fn src_for<'py>(
    py: Python<'py>,
    refs: &Refs,
    e: &FuncEdge,
    obj: Option<Bound<'py, PyAny>>,
) -> PyResult<Option<Src<'py>>> {
    Ok(match (e.src(), obj) {
        (None, _) => None,
        (Some(_), Some(o)) => {
            let in_graph = match &refs.ctx {
                Some(ctx) => o.getattr(intern!(py, "_store"))?.is(ctx.graph.bind(py)),
                None => false,
            };
            if in_graph {
                Some(Src::Id(o.getattr(intern!(py, "_id"))?.extract()?))
            } else {
                Some(Src::Obj(o))
            }
        }
        (Some(s), None) => match s.node {
            NodeRef::Id(id) => Some(Src::Id(id)),
            _ => return Err(PyTypeError::new_err("edge source node is missing")),
        },
    })
}

/// Applies a Python-side edge object.
fn apply_edge_obj(py: Python<'_>, edge: &Bound<'_, PyAny>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
    let (e, obj) = edge_of(edge)?;
    let refs = refs_of(py, cfg)?;
    let src = src_for(py, &refs, &e, obj.map(|o| o.into_bound(py)))?;
    apply_edge(py, &refs, cfg, &e, src)
}

// ---------------------------------------------------------------------------------------------------------------
// Python job and edge objects
// ---------------------------------------------------------------------------------------------------------------

enum JobEdges {
    /// Edge objects passed in from Python.
    Py(Vec<Py<PyAny>>),
    /// Edges of a stored job with their source node objects, resolved when the job came out.
    Rec(Vec<(FuncEdge, Option<Py<PyAny>>)>),
}

/// `(addr, size, simprocedure_name is not None)` of a CFGNode; the node is bound to the graph when stored.
fn src_of(py: Python<'_>, node: &Bound<'_, PyAny>) -> PyResult<SrcNode> {
    Ok(SrcNode {
        addr: node.getattr(intern!(py, "_addr"))?.extract()?,
        size: node.getattr(intern!(py, "_size"))?.extract()?,
        simproc: !node.getattr(intern!(py, "simprocedure_name"))?.is_none(),
        node: NodeRef::Unbound,
    })
}

fn opt_src(
    py: Python<'_>,
    node: Option<&Bound<'_, PyAny>>,
) -> PyResult<(Option<SrcNode>, Option<Py<PyAny>>)> {
    match node {
        Some(n) if !n.is_none() => Ok((Some(src_of(py, n)?), Some(n.clone().unbind()))),
        _ => Ok((None, None)),
    }
}

/// A CFG job: where to scan next, in which function, and the function edges to add once the block exists.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "CFGJob")]
pub struct PyCFGJob {
    pub rec: JobRec,
    src_obj: Option<Py<PyAny>>,
    edges: Option<JobEdges>,
}

impl PyCFGJob {
    pub fn record(&self) -> &JobRec {
        &self.rec
    }
}

#[pymethods]
impl PyCFGJob {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (addr, func_addr, jumpkind, ret_target=None, last_addr=None, src_node=None, src_ins_addr=None, src_stmt_idx=None, returning_source=None, syscall=false, func_edges=None, job_type=JobType::Normal, gp=None))]
    fn py_new(
        py: Python<'_>,
        addr: u64,
        func_addr: u64,
        jumpkind: &str,
        ret_target: Option<u64>,
        last_addr: Option<u64>,
        src_node: Option<&Bound<'_, PyAny>>,
        src_ins_addr: Option<u64>,
        src_stmt_idx: Option<i64>,
        returning_source: Option<u64>,
        syscall: bool,
        func_edges: Option<Vec<Py<PyAny>>>,
        job_type: JobType,
        gp: Option<u64>,
    ) -> PyResult<Self> {
        let (src, src_obj) = opt_src(py, src_node)?;
        Ok(PyCFGJob {
            rec: JobRec {
                addr,
                func_addr,
                jumpkind: jk_intern(jumpkind),
                ret_target,
                last_addr,
                src,
                src_ins_addr,
                src_stmt_idx,
                returning_source,
                syscall,
                job_type,
                gp,
                func_edges: Vec::new(),
            },
            src_obj,
            edges: func_edges.map(JobEdges::Py),
        })
    }

    #[getter]
    fn addr(&self) -> u64 {
        self.rec.addr
    }

    #[getter]
    fn func_addr(&self) -> u64 {
        self.rec.func_addr
    }

    #[getter]
    fn jumpkind<'py>(&self, py: Python<'py>) -> Bound<'py, PyString> {
        PyString::new(py, jk_name(self.rec.jumpkind))
    }

    #[getter]
    fn ret_target(&self) -> Option<u64> {
        self.rec.ret_target
    }

    #[getter]
    fn last_addr(&self) -> Option<u64> {
        self.rec.last_addr
    }

    #[getter]
    fn src_node(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.src_obj.as_ref().map(|o| o.clone_ref(py))
    }

    #[getter]
    fn src_ins_addr(&self) -> Option<u64> {
        self.rec.src_ins_addr
    }

    #[getter]
    fn src_stmt_idx(&self) -> Option<i64> {
        self.rec.src_stmt_idx
    }

    #[getter]
    fn returning_source(&self) -> Option<u64> {
        self.rec.returning_source
    }

    #[getter]
    fn syscall(&self) -> bool {
        self.rec.syscall
    }

    #[getter]
    fn job_type(&self) -> JobType {
        self.rec.job_type
    }

    #[getter]
    fn gp(&self) -> Option<u64> {
        self.rec.gp
    }

    /// The function edges as edge objects, or None.
    #[getter(_func_edges)]
    fn func_edges(&self, py: Python<'_>) -> PyResult<Option<Py<PyList>>> {
        match &self.edges {
            None => Ok(None),
            Some(JobEdges::Py(v)) => Ok(Some(PyList::new(py, v)?.unbind())),
            Some(JobEdges::Rec(v)) => {
                let mut out = Vec::with_capacity(v.len());
                for (e, obj) in v {
                    out.push(edge_object(
                        py,
                        e.clone(),
                        obj.as_ref().map(|o| o.clone_ref(py)),
                    )?);
                }
                Ok(Some(PyList::new(py, out)?.unbind()))
            }
        }
    }

    #[setter(_func_edges)]
    fn set_func_edges(&mut self, edges: Option<Vec<Py<PyAny>>>) {
        self.edges = edges.map(JobEdges::Py);
    }

    fn add_function_edge(&mut self, py: Python<'_>, edge: Py<PyAny>) -> PyResult<()> {
        let mut v = match self.edges.take() {
            None => Vec::new(),
            Some(JobEdges::Py(v)) => v,
            Some(JobEdges::Rec(_)) => {
                self.edges = self
                    .func_edges(py)?
                    .map(|l| JobEdges::Py(l.bind(py).extract().unwrap()));
                match self.edges.take() {
                    Some(JobEdges::Py(v)) => v,
                    _ => Vec::new(),
                }
            }
        };
        v.push(edge);
        self.edges = Some(JobEdges::Py(v));
        Ok(())
    }

    #[pyo3(signature = (cfg, clear=false))]
    fn apply_function_edges(
        slf: &Bound<'_, Self>,
        cfg: &Bound<'_, PyAny>,
        clear: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        enum Work {
            Rec(Vec<(FuncEdge, Option<Py<PyAny>>)>),
            Py(Vec<Py<PyAny>>),
        }
        let work = {
            let this = slf.borrow();
            match &this.edges {
                None => return Ok(()),
                Some(JobEdges::Rec(v)) if v.is_empty() => return Ok(()),
                Some(JobEdges::Py(v)) if v.is_empty() => return Ok(()),
                Some(JobEdges::Rec(v)) => Work::Rec(
                    v.iter()
                        .map(|(e, o)| (e.clone(), o.as_ref().map(|o| o.clone_ref(py))))
                        .collect(),
                ),
                Some(JobEdges::Py(v)) => Work::Py(v.iter().map(|e| e.clone_ref(py)).collect()),
            }
        };
        match work {
            Work::Rec(edges) => {
                let refs = refs_of(py, cfg)?;
                for (e, obj) in edges {
                    let src = src_for(py, &refs, &e, obj.map(|o| o.into_bound(py)))?;
                    apply_edge(py, &refs, cfg, &e, src)?;
                }
            }
            Work::Py(edges) => {
                for e in edges {
                    apply_edge_obj(py, e.bind(py), cfg)?;
                }
            }
        }
        if clear {
            slf.borrow_mut().edges = None;
        }
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "<CFGJob{} {:#08x} @ func {:#08x}>",
            if self.rec.syscall { " syscall" } else { "" },
            self.rec.addr,
            self.rec.func_addr
        )
    }

    fn __richcmp__(&self, other: &Bound<'_, PyAny>, op: CompareOp) -> PyResult<Py<PyAny>> {
        let py = other.py();
        let Ok(other) = other.cast::<PyCFGJob>() else {
            return Ok(py.NotImplemented());
        };
        let eq = self.rec.key() == other.borrow().rec.key();
        match op {
            CompareOp::Eq => Ok(eq.into_pyobject(py)?.to_owned().into_any().unbind()),
            CompareOp::Ne => Ok((!eq).into_pyobject(py)?.to_owned().into_any().unbind()),
            _ => Ok(py.NotImplemented()),
        }
    }

    fn __hash__(&self) -> isize {
        let mut h = FxHasher::default();
        self.rec.key().hash(&mut h);
        std::hash::Hasher::finish(&h) as isize
    }
}

/// Builds the Python object of an edge record.
fn edge_object(py: Python<'_>, e: FuncEdge, src_obj: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
    let inner = EdgeInner { e, src_obj };
    Ok(match inner.e {
        FuncEdge::Transition { .. } => Py::new(py, PyTransitionEdge(inner))?.into_any(),
        FuncEdge::Call { .. } => Py::new(py, PyCallEdge(inner))?.into_any(),
        FuncEdge::FakeRet { .. } => Py::new(py, PyFakeRetEdge(inner))?.into_any(),
        FuncEdge::Return { .. } => Py::new(py, PyReturnEdge(inner))?.into_any(),
    })
}

/// The record and source object of a Python edge object.
fn edge_of(obj: &Bound<'_, PyAny>) -> PyResult<(FuncEdge, Option<Py<PyAny>>)> {
    let py = obj.py();
    let inner = |i: &EdgeInner| (i.e.clone(), i.src_obj.as_ref().map(|o| o.clone_ref(py)));
    if let Ok(e) = obj.cast::<PyTransitionEdge>() {
        return Ok(inner(&e.borrow().0));
    }
    if let Ok(e) = obj.cast::<PyCallEdge>() {
        return Ok(inner(&e.borrow().0));
    }
    if let Ok(e) = obj.cast::<PyFakeRetEdge>() {
        return Ok(inner(&e.borrow().0));
    }
    if let Ok(e) = obj.cast::<PyReturnEdge>() {
        return Ok(inner(&e.borrow().0));
    }
    Err(PyTypeError::new_err(format!(
        "{} is not a function edge",
        obj.get_type().name()?
    )))
}

pub struct EdgeInner {
    e: FuncEdge,
    src_obj: Option<Py<PyAny>>,
}

macro_rules! edge_field {
    ($self:ident, $variant:ident, $field:ident) => {
        match &$self.0.e {
            FuncEdge::$variant { $field, .. } => *$field,
            _ => unreachable!(),
        }
    };
}

/// A transition edge in a function's transition graph.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "FunctionTransitionEdge")]
pub struct PyTransitionEdge(EdgeInner);

#[pymethods]
impl PyTransitionEdge {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (src_node, dst_addr, src_func_addr, to_outside=false, dst_func_addr=None, stmt_idx=None, ins_addr=None, is_exception=false))]
    fn py_new(
        py: Python<'_>,
        src_node: Option<&Bound<'_, PyAny>>,
        dst_addr: u64,
        src_func_addr: u64,
        to_outside: bool,
        dst_func_addr: Option<u64>,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
        is_exception: bool,
    ) -> PyResult<Self> {
        let (src, src_obj) = opt_src(py, src_node)?;
        Ok(PyTransitionEdge(EdgeInner {
            e: FuncEdge::Transition {
                src,
                dst_addr,
                src_func_addr,
                to_outside,
                dst_func_addr,
                stmt_idx,
                ins_addr,
                is_exception,
            },
            src_obj,
        }))
    }

    #[getter]
    fn src_node(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.0.src_obj.as_ref().map(|o| o.clone_ref(py))
    }
    #[getter]
    fn dst_addr(&self) -> u64 {
        edge_field!(self, Transition, dst_addr)
    }
    #[getter]
    fn src_func_addr(&self) -> u64 {
        edge_field!(self, Transition, src_func_addr)
    }
    #[getter]
    fn to_outside(&self) -> bool {
        edge_field!(self, Transition, to_outside)
    }
    #[getter]
    fn dst_func_addr(&self) -> Option<u64> {
        edge_field!(self, Transition, dst_func_addr)
    }
    #[getter]
    fn stmt_idx(&self) -> Option<i64> {
        edge_field!(self, Transition, stmt_idx)
    }
    #[getter]
    fn ins_addr(&self) -> Option<u64> {
        edge_field!(self, Transition, ins_addr)
    }
    #[getter]
    fn is_exception(&self) -> bool {
        edge_field!(self, Transition, is_exception)
    }

    fn apply(slf: &Bound<'_, Self>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        apply_edge_obj(slf.py(), slf.as_any(), cfg)
    }
}

/// A call edge in a function's transition graph.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "FunctionCallEdge")]
pub struct PyCallEdge(EdgeInner);

#[pymethods]
impl PyCallEdge {
    #[new]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (src_node, dst_addr, ret_addr, src_func_addr, syscall=false, stmt_idx=None, ins_addr=None))]
    fn py_new(
        py: Python<'_>,
        src_node: Option<&Bound<'_, PyAny>>,
        dst_addr: u64,
        ret_addr: Option<u64>,
        src_func_addr: u64,
        syscall: bool,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
    ) -> PyResult<Self> {
        let (src, src_obj) = opt_src(py, src_node)?;
        Ok(PyCallEdge(EdgeInner {
            e: FuncEdge::Call {
                src,
                dst_addr,
                ret_addr,
                src_func_addr,
                syscall,
                stmt_idx,
                ins_addr,
            },
            src_obj,
        }))
    }

    #[getter]
    fn src_node(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.0.src_obj.as_ref().map(|o| o.clone_ref(py))
    }
    #[getter]
    fn dst_addr(&self) -> u64 {
        edge_field!(self, Call, dst_addr)
    }
    #[getter]
    fn ret_addr(&self) -> Option<u64> {
        edge_field!(self, Call, ret_addr)
    }
    #[getter]
    fn src_func_addr(&self) -> u64 {
        edge_field!(self, Call, src_func_addr)
    }
    #[getter]
    fn syscall(&self) -> bool {
        edge_field!(self, Call, syscall)
    }
    #[getter]
    fn stmt_idx(&self) -> Option<i64> {
        edge_field!(self, Call, stmt_idx)
    }
    #[getter]
    fn ins_addr(&self) -> Option<u64> {
        edge_field!(self, Call, ins_addr)
    }

    fn apply(slf: &Bound<'_, Self>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        apply_edge_obj(slf.py(), slf.as_any(), cfg)
    }
}

/// A FakeReturn (fall-through) edge in a function's transition graph.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "FunctionFakeRetEdge")]
pub struct PyFakeRetEdge(EdgeInner);

#[pymethods]
impl PyFakeRetEdge {
    #[new]
    #[pyo3(signature = (src_node, dst_addr, src_func_addr, confirmed=None))]
    fn py_new(
        py: Python<'_>,
        src_node: Option<&Bound<'_, PyAny>>,
        dst_addr: u64,
        src_func_addr: u64,
        confirmed: Option<bool>,
    ) -> PyResult<Self> {
        let (src, src_obj) = opt_src(py, src_node)?;
        Ok(PyFakeRetEdge(EdgeInner {
            e: FuncEdge::FakeRet {
                src,
                dst_addr,
                src_func_addr,
                confirmed,
            },
            src_obj,
        }))
    }

    #[getter]
    fn src_node(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        self.0.src_obj.as_ref().map(|o| o.clone_ref(py))
    }
    #[getter]
    fn dst_addr(&self) -> u64 {
        edge_field!(self, FakeRet, dst_addr)
    }
    #[getter]
    fn src_func_addr(&self) -> u64 {
        edge_field!(self, FakeRet, src_func_addr)
    }
    #[getter]
    fn confirmed(&self) -> Option<bool> {
        edge_field!(self, FakeRet, confirmed)
    }

    fn apply(slf: &Bound<'_, Self>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        apply_edge_obj(slf.py(), slf.as_any(), cfg)
    }
}

/// A return edge (from a call or syscall) in a function's transition graph.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "FunctionReturnEdge")]
pub struct PyReturnEdge(EdgeInner);

#[pymethods]
impl PyReturnEdge {
    #[new]
    fn py_new(ret_from_addr: u64, ret_to_addr: u64, dst_func_addr: u64) -> Self {
        PyReturnEdge(EdgeInner {
            e: FuncEdge::Return {
                ret_from_addr,
                ret_to_addr,
                dst_func_addr,
            },
            src_obj: None,
        })
    }

    #[getter]
    fn ret_from_addr(&self) -> u64 {
        edge_field!(self, Return, ret_from_addr)
    }
    #[getter]
    fn ret_to_addr(&self) -> u64 {
        edge_field!(self, Return, ret_to_addr)
    }
    #[getter]
    fn dst_func_addr(&self) -> u64 {
        edge_field!(self, Return, dst_func_addr)
    }

    fn apply(slf: &Bound<'_, Self>, cfg: &Bound<'_, PyAny>) -> PyResult<()> {
        apply_edge_obj(slf.py(), slf.as_any(), cfg)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// PendingJobs and traced-address views
// ---------------------------------------------------------------------------------------------------------------

/// The `PendingJobs` interface over a ScanState.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "PendingJobs")]
pub struct PendingJobsView {
    scan: Py<ScanState>,
}

#[pymethods]
impl PendingJobsView {
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.scan)
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.scan.borrow(py).pending.len()
    }

    fn __bool__(&self, py: Python<'_>) -> bool {
        !self.scan.borrow(py).pending.is_empty()
    }

    fn add_job(&self, py: Python<'_>, job: &Bound<'_, PyAny>) -> PyResult<()> {
        let mut scan = self.scan.borrow_mut(py);
        let rec = scan.ingest(py, job)?;
        scan.pending.add(rec);
        Ok(())
    }

    #[pyo3(signature = (returning=true))]
    fn pop_job(&self, py: Python<'_>, returning: bool) -> PyResult<Option<Py<PyCFGJob>>> {
        let rec = self.scan.borrow_mut(py).pending.pop(returning);
        rec.map(|r| ScanState::emit(self.scan.bind(py), r))
            .transpose()
    }

    fn all_jobs(&self, py: Python<'_>) -> PyResult<Vec<Py<PyCFGJob>>> {
        let recs: Vec<JobRec> = self.scan.borrow(py).pending.iter().cloned().collect();
        recs.into_iter()
            .map(|r| ScanState::emit(self.scan.bind(py), r))
            .collect()
    }

    fn add_returning_function(&self, py: Python<'_>, func_addr: Option<u64>) {
        self.scan
            .borrow_mut(py)
            .pending
            .add_returning_function(func_addr);
    }

    fn add_nonreturning_function(&self, py: Python<'_>, func_addr: Option<u64>) {
        self.scan
            .borrow_mut(py)
            .pending
            .add_nonreturning_function(func_addr);
    }

    fn clear_updated_functions(&self, py: Python<'_>) {
        self.scan.borrow_mut(py).pending.clear_updated_functions();
    }

    /// `_updated_functions` in Python set order.
    fn updated_functions(&self, py: Python<'_>) -> Vec<Option<u64>> {
        self.scan.borrow(py).pending.updated_functions()
    }

    /// Drops the pending jobs of callees now known not to return and deregisters them.
    fn cleanup(&self, py: Python<'_>) -> PyResult<()> {
        let refs = self.scan.borrow(py).refs(py);
        let ctx = refs
            .ctx
            .as_ref()
            .ok_or_else(|| PyTypeError::new_err("the scan state is not bound"))?;
        let functions = ctx.kb.bind(py).getattr(intern!(py, "functions"))?;
        let ours = functions.is(ctx.manager.bind(py));
        let store = ctx.store.bind(py);
        let returning_of = |addr: u64| -> PyResult<Option<Option<bool>>> {
            if ours {
                return Ok(store.borrow().funcs.get(&addr).map(|r| r.returning));
            }
            let f = functions.call_method1(intern!(py, "function"), (addr,))?;
            if f.is_none() {
                return Ok(None);
            }
            let r = f.getattr(intern!(py, "returning"))?;
            Ok(Some(if r.is_none() {
                None
            } else {
                Some(r.is_truthy()?)
            }))
        };
        let warn = |addr: u64| -> PyResult<()> {
            let logger = py
                .import(intern!(py, "logging"))?
                .call_method1(intern!(py, "getLogger"), ("angr.analyses.cfg.cfg_fast",))?;
            logger.call_method1(
                intern!(py, "warning"),
                (
                    "An expected function at %s is not found. Please report it to Fish.",
                    addr,
                ),
            )?;
            Ok(())
        };
        let mut scan = self.scan.borrow_mut(py);
        let ScanState {
            pending,
            accounting,
            ..
        } = &mut *scan;
        pending.cleanup(returning_of, warn, |job| {
            accounting.deregister(job.func_addr, &JobItem::Job(job.key()));
        })
    }
}

/// `CFGFast._traced_addresses` over a ScanState.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "TracedAddresses")]
pub struct TracedAddresses {
    scan: Py<ScanState>,
}

#[pymethods]
impl TracedAddresses {
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.scan)
    }

    fn __contains__(&self, py: Python<'_>, addr: &Bound<'_, PyAny>) -> bool {
        match addr.extract::<u64>() {
            Ok(a) => self.scan.borrow(py).traced.contains(&a),
            Err(_) => false,
        }
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.scan.borrow(py).traced.len()
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let mut v: Vec<u64> = self.scan.borrow(py).traced.iter().copied().collect();
        v.sort_unstable();
        Ok(PyList::new(py, v)?.call_method0("__iter__")?.unbind())
    }

    fn add(&self, py: Python<'_>, addr: u64) {
        self.scan.borrow_mut(py).traced.insert(addr);
    }

    fn update(&self, py: Python<'_>, addrs: Vec<u64>) {
        self.scan.borrow_mut(py).traced.extend(addrs);
    }

    fn discard(&self, py: Python<'_>, addr: u64) {
        self.scan.borrow_mut(py).traced.remove(&addr);
    }
}

/// `CFGBase._completed_functions` over a ScanState.
#[pyclass(module = "angr.rustylib.cfg_jobs", name = "CompletedFunctions")]
pub struct CompletedFunctions {
    scan: Py<ScanState>,
}

#[pymethods]
impl CompletedFunctions {
    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        visit.call(&self.scan)
    }

    fn __contains__(&self, py: Python<'_>, addr: &Bound<'_, PyAny>) -> bool {
        match addr.extract::<u64>() {
            Ok(a) => self.scan.borrow(py).completed.contains(&a),
            Err(_) => false,
        }
    }

    fn __len__(&self, py: Python<'_>) -> usize {
        self.scan.borrow(py).completed.len()
    }

    fn __iter__(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let mut v: Vec<u64> = self.scan.borrow(py).completed.iter().copied().collect();
        v.sort_unstable();
        Ok(PyList::new(py, v)?.call_method0("__iter__")?.unbind())
    }

    fn add(&self, py: Python<'_>, addr: u64) {
        self.scan.borrow_mut(py).completed.insert(addr);
    }

    fn discard(&self, py: Python<'_>, addr: u64) {
        self.scan.borrow_mut(py).completed.remove(&addr);
    }
}

const EH_PROLOG3_PREFIX: &[u8; 23] =
    b"\x50\x64\xff\x35\x00\x00\x00\x00\x8d\x44\x24\x0c\x2b\x64\x24\x0c\x53\x56\x57\x89\x28\x8b\xe8";
const SEH_PROLOG4_BODY: &[u8; 24] =
    b"\x64\xff\x35\x00\x00\x00\x00\x8b\x44\x24\x10\x89\x6c\x24\x10\x8d\x6c\x24\x10\x2b\xe0\x53\x56\x57";

/// What `func.get_block(func.addr).bytes` reads, or None when Python has to run it (the size is unknown, so
/// get_block lifts and records it, or the bytes are unmapped).
fn head_block_bytes(g: &FunctionGraph, snap: &Snapshot, addr: u64) -> Option<Vec<u8>> {
    if !g.is_local(addr) {
        return None;
    }
    let size = g.block_size(addr)?;
    snap.load_bytes(addr, size as usize)
}

/// Whether CFGFast._function_completed(addr) can change anything; it mirrors each byte test of the Python code.
fn completed_candidate(
    py: Python<'_>,
    store: &RecoveryFunctions,
    snap: &Snapshot,
    addr: u64,
    filter: u8,
) -> bool {
    let Ok(rec) = store.rec(addr) else {
        return false;
    };
    let g = rec.graph.bind(py).borrow();
    match filter {
        1 => match g.local_count() {
            3 | 4 => true,
            // _guard_xfg_dispatch_icall: `jmp rax` or `jmp [rip+disp]` (always FF 25 in 64-bit mode)
            1 | 2 if !rec.is_simprocedure => match head_block_bytes(&g, snap, addr) {
                None => true,
                Some(b) => b == b"\xff\xe0" || b.windows(2).any(|w| w == b"\xff\x25"),
            },
            _ => false,
        },
        2 => {
            if g.local_count() == 4 {
                return true;
            }
            match head_block_bytes(&g, snap, addr) {
                None => true,
                Some(b) => {
                    (b.len() >= 34 && b[..23] == EH_PROLOG3_PREFIX[..])
                        || (b.len() >= 40 && b[0] == 0x68 && b[5..29] == SEH_PROLOG4_BODY[..])
                }
            }
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------------------------------------------

/// Test hook: the iteration order of a Python set built from distinct elements with these hashes.
#[pyfunction]
fn set_iteration_order(hashes: Vec<i64>) -> Vec<usize> {
    cpython_set_order(&hashes)
}

/// Test hook: `hash((callee, caller, call_site, return_to))`.
#[pyfunction]
fn function_return_hash_of(fr: FunctionReturn) -> i64 {
    function_return_hash(&fr)
}

pub fn cfg_jobs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<JobType>()?;
    m.add_class::<PyCFGJob>()?;
    m.add_class::<PyTransitionEdge>()?;
    m.add_class::<PyCallEdge>()?;
    m.add_class::<PyFakeRetEdge>()?;
    m.add_class::<PyReturnEdge>()?;
    m.add_class::<ScanState>()?;
    m.add_class::<PendingJobsView>()?;
    m.add_class::<TracedAddresses>()?;
    m.add_class::<CompletedFunctions>()?;
    m.add_function(wrap_pyfunction!(set_iteration_order, m)?)?;
    m.add_function(wrap_pyfunction!(function_return_hash_of, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_map_has_dict_semantics() {
        let mut m: OrderedMap<u64, ()> = OrderedMap::default();
        for k in 0..100 {
            m.entry_or_insert_with(k, || ());
        }
        for k in (0..100).step_by(2) {
            m.remove(&k);
        }
        m.entry_or_insert_with(4, || ());
        m.entry_or_insert_with(5, || ());
        let keys: Vec<u64> = m.keys().collect();
        assert_eq!(keys.len(), 51);
        assert_eq!(keys[0], 1);
        assert_eq!(*keys.last().unwrap(), 4);
        assert_eq!(m.last_key(), Some(4));
    }

    #[test]
    fn small_int_set_order() {
        // a set of small ints iterates in slot order: by value modulo the table size
        assert_eq!(cpython_set_order(&[5, 1, 3]), vec![1, 2, 0]);
        // list(set) after adding 5, 13, 21, 2**40, 7, 1 on CPython 3.14
        let hashes: Vec<i64> = [5u64, 13, 21, 1 << 40, 7, 1]
            .iter()
            .map(|&v| py_hash_u64(v))
            .collect();
        assert_eq!(cpython_set_order(&hashes), vec![3, 5, 0, 4, 1, 2]);
        assert_eq!(py_hash_u64(u64::MAX), 7);
        assert_eq!(py_hash_u64((1 << 61) - 1), 0);
    }

    #[test]
    fn tuple_hash_matches_cpython() {
        // hash((1, None, 3, 4)) on CPython 3.14
        let h = py_hash_tuple(&[py_hash_u64(1), PY_HASH_NONE, py_hash_u64(3), py_hash_u64(4)]);
        assert_eq!(h, -5408450541753567386);
    }

    #[test]
    fn jumpkinds_follow_the_vex_enum() {
        assert_eq!(jk_intern("Ijk_Boring"), JK_BORING);
        assert_eq!(jk_intern("Ijk_Call"), JK_CALL);
        assert_eq!(jk_intern("Ijk_Ret"), JK_RET);
        assert_eq!(jk_intern("Ijk_FakeRet"), JK_FAKERET);
        assert_eq!(jk_intern("Ijk_Exception"), JK_EXCEPTION);
        assert_eq!(jk_from_vex(IJK_INVALID + 2), JK_CALL);
        let x = jk_intern("Ijk_Something");
        assert_eq!(jk_name(x), "Ijk_Something");
    }
}
