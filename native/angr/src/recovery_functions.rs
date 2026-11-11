//! Scan-time function store for CFGFast.
//!
//! Exposed as `angr.rustylib.recovery_functions.RecoveryFunctions`. It holds the per-function records of the
//! functions that CFGFast's scan creates (flags, returning status, info keys, the shared `FunctionGraph`), the
//! non-returning sets, and the callgraph. Everything `make_functions` later reads from the scan-time
//! `kb.functions` is here; the Python `RecoveryFunction` objects are views over these records.
//!
//! Every mutating call replicates one of the `Function` mutators (`register`, `transit_to`, `call_to`, ...) on
//! the graph and records a log entry so the Python view can update its networkx mirrors incrementally.

use std::collections::{BTreeMap, BTreeSet};

use indexmap::IndexMap;
use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyString};

use crate::function_graph::{
    EdgeKind, EndpointKind, FunctionGraph, NodeKind, PRESENT_CONFIRMED, PRESENT_INS_ADDR,
    PRESENT_OUTSIDE, PRESENT_STMT_IDX, PRESENT_TYPE, SiteKind,
};
use crate::ordered_map::OrderedMap;

/// Log entry ops; the view replays them onto its networkx mirrors.
pub const LOG_REGISTER: u8 = 0;
pub const LOG_GRAPH_NODE: u8 = 1;
pub const LOG_ADD_EDGE: u8 = 2;
pub const LOG_SET_CONFIRMED: u8 = 3;
pub const LOG_REMOVE_EDGE: u8 = 4;

/// Bits of the second operand of a LOG_REGISTER entry.
pub const REG_NEW_LOCAL: u32 = 1;
pub const REG_IN_GRAPH: u32 = 2;

/// Callgraph edge types, in the order `FunctionManager` names them.
pub const CG_CALL: u8 = 0;
pub const CG_FAKERET: u8 = 1;
pub const CG_TRANSITION: u8 = 2;
pub const CG_EXCEPTION: u8 = 3;

/// `(kind, addr, size, thumb)`: the identity of a CodeNode without the object.
pub type NodeSpec = (NodeKind, u64, u32, bool);

/// A JSON-able `Function.info` value; the typed variants are what the scan reads from Rust.
#[derive(Clone)]
pub enum InfoValue {
    Bool(bool),
    Int(i64),
    Str(String),
    Other(Py<PyAny>),
}

impl InfoValue {
    fn from_py(obj: &Bound<'_, PyAny>) -> Self {
        if let Ok(b) = obj.cast::<PyBool>() {
            return InfoValue::Bool(b.is_true());
        }
        if let Ok(i) = obj.cast::<PyInt>()
            && let Ok(v) = i.extract::<i64>()
        {
            return InfoValue::Int(v);
        }
        if let Ok(s) = obj.cast::<PyString>()
            && let Ok(v) = s.to_str()
        {
            return InfoValue::Str(v.to_owned());
        }
        InfoValue::Other(obj.clone().unbind())
    }

    pub(crate) fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        Ok(match self {
            InfoValue::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
            InfoValue::Int(i) => i.into_pyobject(py)?.into_any(),
            InfoValue::Str(s) => PyString::new(py, s).into_any(),
            InfoValue::Other(o) => o.bind(py).clone(),
        })
    }
}

pub struct FuncRecord {
    pub name: String,
    pub is_default_name: bool,
    pub previous_names: Vec<String>,
    pub binary_name: Option<String>,
    pub is_syscall: bool,
    pub is_simprocedure: bool,
    pub is_plt: bool,
    pub is_alignment: bool,
    pub returning: Option<bool>,
    pub info: IndexMap<String, InfoValue>,
    pub graph: Py<FunctionGraph>,
    /// Bumped on every graph mutation made through the store.
    pub generation: u64,
    /// Mutations since the view last drained them; only kept while `log_enabled`.
    pub log: Vec<(u8, u32, u32)>,
    pub log_enabled: bool,
}

impl FuncRecord {
    fn new(graph: Py<FunctionGraph>) -> Self {
        FuncRecord {
            name: String::new(),
            is_default_name: false,
            previous_names: Vec::new(),
            binary_name: None,
            is_syscall: false,
            is_simprocedure: false,
            is_plt: false,
            is_alignment: false,
            returning: None,
            info: IndexMap::new(),
            graph,
            generation: 0,
            log: Vec::new(),
            log_enabled: false,
        }
    }

    fn log(&mut self, op: u8, a: u32, b: u32) {
        self.generation += 1;
        if self.log_enabled {
            self.log.push((op, a, b));
        }
    }
}

/// A networkx MultiDiGraph of function addresses with a `type` on every edge; insertion orders are kept.
#[derive(Default)]
pub struct CallGraph {
    pub(crate) succ: OrderedMap<u64, OrderedMap<u64, Vec<u8>>>,
    pub(crate) pred: OrderedMap<u64, OrderedMap<u64, ()>>,
}

impl CallGraph {
    pub fn add_node(&mut self, n: u64) {
        self.succ.get_or_insert_default(n);
        self.pred.get_or_insert_default(n);
    }

    pub fn contains(&self, n: u64) -> bool {
        self.succ.contains_key(&n)
    }

    /// Adds the edge unless an edge of the same type exists (what `FunctionManager._add_*` check first).
    pub fn add_edge(&mut self, u: u64, v: u64, ty: u8) -> bool {
        self.add_node(u);
        self.add_node(v);
        let types = self.succ.get_mut(&u).unwrap().get_or_insert_default(v);
        if types.contains(&ty) {
            return false;
        }
        types.push(ty);
        self.pred.get_mut(&v).unwrap().get_or_insert_default(u);
        true
    }

    pub fn remove_node(&mut self, n: u64) -> bool {
        let Some(succs) = self.succ.shift_remove(&n) else {
            return false;
        };
        for v in succs.keys() {
            if let Some(p) = self.pred.get_mut(v) {
                p.shift_remove(&n);
            }
        }
        if let Some(preds) = self.pred.shift_remove(&n) {
            for u in preds.keys() {
                if let Some(s) = self.succ.get_mut(u) {
                    s.shift_remove(&n);
                }
            }
        }
        true
    }

    pub fn number_of_edges(&self) -> usize {
        self.succ
            .values()
            .map(|m| m.values().map(Vec::len).sum::<usize>())
            .sum()
    }
}

#[pyclass(module = "angr.rustylib.recovery_functions")]
pub struct RecoveryFunctions {
    pub funcs: BTreeMap<u64, FuncRecord>,
    pub nonreturning: BTreeSet<u64>,
    pub unknown_returning: BTreeSet<u64>,
    pub callgraph: CallGraph,
    /// `factory(addr, syscall)` creates a missing function (and its record) on the Python side.
    pub factory: Option<Py<PyAny>>,
}

fn missing(addr: u64) -> PyErr {
    PyKeyError::new_err(addr)
}

fn delta_of(spec: NodeSpec) -> i32 {
    if spec.0 == NodeKind::Block && spec.3 {
        -1
    } else {
        0
    }
}

/// Graph mutators replicating the `Function` methods; each logs onto the record.
pub(crate) struct FuncOps<'a> {
    pub(crate) rec: &'a mut FuncRecord,
    pub(crate) g: PyRefMut<'a, FunctionGraph>,
}

impl FuncOps<'_> {
    /// `Function.register`
    pub(crate) fn register(&mut self, is_local: bool, spec: NodeSpec) -> u32 {
        let (kind, addr, size, thumb) = spec;
        let (idx, _created, new_local, changed) =
            self.g
                .register_node(is_local, kind, addr, size, thumb, delta_of(spec));
        if !changed {
            return idx;
        }
        let mut bits = 0;
        if new_local {
            bits |= REG_NEW_LOCAL;
        }
        if self.g.contains_node(idx) {
            bits |= REG_IN_GRAPH;
        }
        self.rec.log(LOG_REGISTER, idx, bits);
        idx
    }

    /// `Function._graph_node`
    pub(crate) fn graph_node(&mut self, spec: NodeSpec) -> u32 {
        let (kind, addr, size, thumb) = spec;
        let (idx, created) = self.g.add_node(kind, addr, size, thumb, delta_of(spec));
        self.rec.log(LOG_GRAPH_NODE, idx, created as u32);
        idx
    }

    /// `Function._add_edge`
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_edge(
        &mut self,
        src: u32,
        dst: u32,
        kind: EdgeKind,
        present: u8,
        outside: bool,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        confirmed: bool,
    ) {
        self.g
            .add_edge(
                src, dst, kind, present, outside, ins_addr, stmt_idx, confirmed,
            )
            .expect("node ids come from this graph");
        self.rec.log(LOG_ADD_EDGE, src, dst);
    }

    pub(crate) fn set_edge_confirmed(&mut self, src: u32, dst: u32, confirmed: bool) {
        self.g
            .set_edge_confirmed(src, dst, confirmed)
            .expect("edge exists");
        self.rec.log(LOG_SET_CONFIRMED, src, dst);
    }

    /// `Function.transit_to`
    pub(crate) fn transit_to(
        &mut self,
        from: NodeSpec,
        to: Option<NodeSpec>,
        outside: bool,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        is_exception: bool,
    ) {
        let src = self.register(true, from);
        let dst = to.map(|t| self.register(!outside, t));
        if outside {
            let _ = self.g.add_site(src, SiteKind::Jumpout);
        }
        let kind = if is_exception {
            EdgeKind::Exception
        } else {
            EdgeKind::Transition
        };
        if let Some(dst) = dst {
            self.add_edge(
                src,
                dst,
                kind,
                PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR | PRESENT_STMT_IDX,
                outside,
                ins_addr,
                stmt_idx,
                false,
            );
        }
        if outside {
            let ep = if is_exception {
                EndpointKind::Exception
            } else {
                EndpointKind::Transition
            };
            let _ = self.g.add_endpoint(src, ep);
        }
    }

    /// `Function.call_to`
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn call_to(
        &mut self,
        from: NodeSpec,
        to_func: NodeSpec,
        ret: Option<NodeSpec>,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
        return_to_outside: bool,
        syscall: bool,
    ) {
        let src = self.register(true, from);
        let dst = self.graph_node(to_func);
        let kind = if syscall {
            EdgeKind::Syscall
        } else {
            EdgeKind::Call
        };
        self.add_edge(
            src,
            dst,
            kind,
            PRESENT_TYPE | PRESENT_STMT_IDX | PRESENT_INS_ADDR,
            false,
            ins_addr,
            stmt_idx,
            false,
        );
        if let Some(ret) = ret
            && !syscall
        {
            self.register(!return_to_outside, ret);
            self.fakeret_to(from, ret, None, return_to_outside);
        }
    }

    /// `Function.fakeret_to`
    pub(crate) fn fakeret_to(
        &mut self,
        from: NodeSpec,
        to: NodeSpec,
        confirmed: Option<bool>,
        to_outside: bool,
    ) {
        let src = self.register(true, from);
        let dst = if confirmed == Some(true) {
            self.register(!to_outside, to)
        } else {
            self.graph_node(to)
        };
        match confirmed {
            None => self.add_edge(
                src,
                dst,
                EdgeKind::FakeReturn,
                PRESENT_TYPE | PRESENT_OUTSIDE,
                to_outside,
                None,
                None,
                false,
            ),
            Some(c) => self.add_edge(
                src,
                dst,
                EdgeKind::FakeReturn,
                PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_CONFIRMED,
                to_outside,
                None,
                None,
                c,
            ),
        }
    }

    /// `Function.remove_edge`; returns False when the edge does not exist.
    pub(crate) fn remove_edge(&mut self, from: NodeSpec, to: NodeSpec) -> bool {
        let (Some(s), Some(d)) = (
            self.g.find_node(from.0, from.1, from.2, from.3),
            self.g.find_node(to.0, to.1, to.2, to.3),
        ) else {
            return false;
        };
        if !self.g.remove_edge(s, d) {
            return false;
        }
        self.rec.log(LOG_REMOVE_EDGE, s, d);
        true
    }

    /// `Function.return_from_call` with confirm_fakeret=True
    pub(crate) fn return_from_call(&mut self, from_func: NodeSpec, to: NodeSpec, to_outside: bool) {
        let src = self.graph_node(from_func);
        let dst = self.graph_node(to);
        self.add_edge(
            src,
            dst,
            EdgeKind::Return,
            PRESENT_TYPE | PRESENT_OUTSIDE,
            to_outside,
            None,
            None,
            false,
        );
        let preds = self.g.predecessors(dst).expect("node exists");
        for pred in preds {
            if self.g.edge_kind(pred, dst) == Some(EdgeKind::FakeReturn) {
                self.set_edge_confirmed(pred, dst, true);
            }
        }
    }

    /// `Function.add_return_site`
    pub(crate) fn add_return_site(&mut self, node: NodeSpec) {
        let idx = self.register(true, node);
        let _ = self.g.add_site(idx, SiteKind::Ret);
        let _ = self.g.add_endpoint(idx, EndpointKind::Return);
    }

    /// `Function.add_jumpout_site`
    pub(crate) fn add_jumpout_site(&mut self, node: NodeSpec) {
        let idx = self.register(true, node);
        let _ = self.g.add_site(idx, SiteKind::Jumpout);
        let _ = self.g.add_endpoint(idx, EndpointKind::Transition);
    }

    /// `Function.add_retout_site`
    pub(crate) fn add_retout_site(&mut self, node: NodeSpec) {
        let idx = self.register(true, node);
        let _ = self.g.add_site(idx, SiteKind::Retout);
        let _ = self.g.add_endpoint(idx, EndpointKind::Return);
    }
}

impl RecoveryFunctions {
    pub(crate) fn rec(&self, addr: u64) -> PyResult<&FuncRecord> {
        self.funcs.get(&addr).ok_or_else(|| missing(addr))
    }

    pub(crate) fn rec_mut(&mut self, addr: u64) -> PyResult<&mut FuncRecord> {
        self.funcs.get_mut(&addr).ok_or_else(|| missing(addr))
    }

    pub(crate) fn ops<'a>(&'a mut self, py: Python<'a>, addr: u64) -> PyResult<FuncOps<'a>> {
        let rec = self.funcs.get_mut(&addr).ok_or_else(|| missing(addr))?;
        let g = rec.graph.bind(py).try_borrow_mut()?;
        Ok(FuncOps { rec, g })
    }

    fn update_returning_sets(&mut self, addr: u64, v: Option<bool>) {
        match v {
            Some(false) => {
                self.nonreturning.insert(addr);
                self.unknown_returning.remove(&addr);
            }
            Some(true) => {
                self.nonreturning.remove(&addr);
                self.unknown_returning.remove(&addr);
            }
            None => {
                self.unknown_returning.insert(addr);
                self.nonreturning.remove(&addr);
            }
        }
    }

    /// Creates the record of a new function (returning unknown, callgraph node added).
    pub fn create_record(&mut self, py: Python<'_>, addr: u64) -> PyResult<Py<FunctionGraph>> {
        if self.funcs.contains_key(&addr) {
            return Err(PyValueError::new_err(format!(
                "function {addr:#x} already exists"
            )));
        }
        let graph = FunctionGraph::untracked(py, FunctionGraph::new(addr))?;
        self.funcs.insert(addr, FuncRecord::new(graph.clone()));
        self.unknown_returning.insert(addr);
        self.callgraph.add_node(addr);
        Ok(graph)
    }

    /// Creates a missing function through the factory; no borrow is held while it runs.
    pub fn ensure_function(slf: &Bound<'_, Self>, addr: u64, syscall: bool) -> PyResult<()> {
        let factory = {
            let this = slf.borrow();
            if this.funcs.contains_key(&addr) {
                return Ok(());
            }
            match &this.factory {
                Some(f) => f.clone_ref(slf.py()),
                None => return Err(missing(addr)),
            }
        };
        factory.call1(slf.py(), (addr, syscall))?;
        if slf.borrow().funcs.contains_key(&addr) {
            Ok(())
        } else {
            Err(PyValueError::new_err(format!(
                "the factory did not create function {addr:#x}"
            )))
        }
    }

    fn cg_edges_of(&self, u: u64, out: &mut Vec<(u64, u64, u8)>) {
        if let Some(m) = self.callgraph.succ.get(&u) {
            for (v, types) in m {
                for &t in types {
                    out.push((u, *v, t));
                }
            }
        }
    }
}

#[pymethods]
impl RecoveryFunctions {
    #[new]
    pub fn new() -> Self {
        RecoveryFunctions {
            funcs: BTreeMap::new(),
            nonreturning: BTreeSet::new(),
            unknown_returning: BTreeSet::new(),
            callgraph: CallGraph::default(),
            factory: None,
        }
    }

    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        if let Some(f) = &self.factory {
            visit.call(f)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.factory = None;
    }

    /// Sets the callable that the recovery API uses to create missing functions: `factory(addr, syscall)`.
    pub fn set_factory(&mut self, factory: Py<PyAny>) {
        self.factory = Some(factory);
    }

    // --- records -------------------------------------------------------------------------------

    /// Creates a record with default flags and a fresh graph; returns the graph.
    pub fn create(&mut self, py: Python<'_>, addr: u64) -> PyResult<Py<FunctionGraph>> {
        self.create_record(py, addr)
    }

    /// Imports an existing function (its graph is shared, not copied).
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (addr, graph, name, is_default_name, previous_names, binary_name, is_syscall, is_simprocedure, is_plt, is_alignment, returning, info))]
    pub fn import_record(
        &mut self,
        addr: u64,
        graph: Py<FunctionGraph>,
        name: String,
        is_default_name: bool,
        previous_names: Vec<String>,
        binary_name: Option<String>,
        is_syscall: bool,
        is_simprocedure: bool,
        is_plt: bool,
        is_alignment: bool,
        returning: Option<bool>,
        info: &Bound<'_, PyDict>,
    ) -> PyResult<()> {
        if self.funcs.contains_key(&addr) {
            return Err(PyValueError::new_err(format!(
                "function {addr:#x} already exists"
            )));
        }
        let mut rec = FuncRecord::new(graph);
        rec.name = name;
        rec.is_default_name = is_default_name;
        rec.previous_names = previous_names;
        rec.binary_name = binary_name;
        rec.is_syscall = is_syscall;
        rec.is_simprocedure = is_simprocedure;
        rec.is_plt = is_plt;
        rec.is_alignment = is_alignment;
        rec.returning = returning;
        for (k, v) in info.iter() {
            rec.info
                .insert(k.extract::<String>()?, InfoValue::from_py(&v));
        }
        self.funcs.insert(addr, rec);
        self.update_returning_sets(addr, returning);
        self.callgraph.add_node(addr);
        Ok(())
    }

    pub fn remove(&mut self, addr: u64) -> bool {
        if self.funcs.remove(&addr).is_none() {
            return false;
        }
        self.nonreturning.remove(&addr);
        self.unknown_returning.remove(&addr);
        self.callgraph.remove_node(addr);
        true
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.funcs.contains_key(&addr)
    }

    pub fn __len__(&self) -> usize {
        self.funcs.len()
    }

    /// All function addresses in ascending order.
    pub fn addrs(&self) -> Vec<u64> {
        self.funcs.keys().copied().collect()
    }

    /// `SortedDict.irange`
    #[pyo3(signature = (minimum=None, maximum=None, inclusive=(true, true), reverse=false))]
    pub fn addrs_in_range(
        &self,
        minimum: Option<u64>,
        maximum: Option<u64>,
        inclusive: (bool, bool),
        reverse: bool,
    ) -> Vec<u64> {
        use std::ops::Bound;
        let lo = match (minimum, inclusive.0) {
            (None, _) => Bound::Unbounded,
            (Some(m), true) => Bound::Included(m),
            (Some(m), false) => Bound::Excluded(m),
        };
        let hi = match (maximum, inclusive.1) {
            (None, _) => Bound::Unbounded,
            (Some(m), true) => Bound::Included(m),
            (Some(m), false) => Bound::Excluded(m),
        };
        if matches!((lo, hi), (Bound::Included(a) | Bound::Excluded(a), Bound::Included(b) | Bound::Excluded(b)) if a > b)
        {
            return Vec::new();
        }
        let it = self.funcs.range((lo, hi)).map(|(&a, _)| a);
        if reverse {
            it.rev().collect()
        } else {
            it.collect()
        }
    }

    pub fn ceiling_addr(&self, addr: u64) -> Option<u64> {
        self.funcs.range(addr..).next().map(|(&a, _)| a)
    }

    pub fn floor_addr(&self, addr: u64) -> Option<u64> {
        self.funcs.range(..=addr).next_back().map(|(&a, _)| a)
    }

    pub fn graph(&self, addr: u64) -> PyResult<Py<FunctionGraph>> {
        Ok(self.rec(addr)?.graph.clone())
    }

    /// Replaces the graph of a function (`Function.clear_transition_graph`).
    pub fn reset_graph(&mut self, py: Python<'_>, addr: u64) -> PyResult<Py<FunctionGraph>> {
        let graph = FunctionGraph::untracked(py, FunctionGraph::new(addr))?;
        let rec = self.rec_mut(addr)?;
        rec.graph = graph.clone();
        rec.generation += 1;
        rec.log.clear();
        rec.log_enabled = false;
        Ok(graph)
    }

    pub fn generation(&self, addr: u64) -> PyResult<u64> {
        Ok(self.rec(addr)?.generation)
    }

    /// Start recording mutations for the view's mirrors.
    pub fn enable_log(&mut self, addr: u64) -> PyResult<()> {
        self.rec_mut(addr)?.log_enabled = true;
        Ok(())
    }

    pub fn disable_log(&mut self, addr: u64) -> PyResult<()> {
        let rec = self.rec_mut(addr)?;
        rec.log_enabled = false;
        rec.log.clear();
        Ok(())
    }

    /// Returns and clears the recorded mutations: `(op, a, b)` tuples.
    pub fn take_log(&mut self, addr: u64) -> PyResult<Vec<(u8, u32, u32)>> {
        Ok(std::mem::take(&mut self.rec_mut(addr)?.log))
    }

    // --- fields --------------------------------------------------------------------------------

    pub fn name(&self, addr: u64) -> PyResult<&str> {
        Ok(&self.rec(addr)?.name)
    }

    pub fn set_name(&mut self, addr: u64, name: String) -> PyResult<()> {
        self.rec_mut(addr)?.name = name;
        Ok(())
    }

    pub fn is_default_name(&self, addr: u64) -> PyResult<bool> {
        Ok(self.rec(addr)?.is_default_name)
    }

    pub fn set_is_default_name(&mut self, addr: u64, v: bool) -> PyResult<()> {
        self.rec_mut(addr)?.is_default_name = v;
        Ok(())
    }

    pub fn previous_names(&self, addr: u64) -> PyResult<Vec<String>> {
        Ok(self.rec(addr)?.previous_names.clone())
    }

    pub fn set_previous_names(&mut self, addr: u64, names: Vec<String>) -> PyResult<()> {
        self.rec_mut(addr)?.previous_names = names;
        Ok(())
    }

    pub fn add_previous_name(&mut self, addr: u64, name: String) -> PyResult<()> {
        let rec = self.rec_mut(addr)?;
        if !rec.previous_names.contains(&name) {
            rec.previous_names.push(name);
        }
        Ok(())
    }

    pub fn binary_name(&self, addr: u64) -> PyResult<Option<&str>> {
        Ok(self.rec(addr)?.binary_name.as_deref())
    }

    pub fn set_binary_name(&mut self, addr: u64, v: Option<String>) -> PyResult<()> {
        self.rec_mut(addr)?.binary_name = v;
        Ok(())
    }

    pub fn is_syscall(&self, addr: u64) -> PyResult<bool> {
        Ok(self.rec(addr)?.is_syscall)
    }

    pub fn set_is_syscall(&mut self, addr: u64, v: bool) -> PyResult<()> {
        self.rec_mut(addr)?.is_syscall = v;
        Ok(())
    }

    pub fn is_simprocedure(&self, addr: u64) -> PyResult<bool> {
        Ok(self.rec(addr)?.is_simprocedure)
    }

    pub fn set_is_simprocedure(&mut self, addr: u64, v: bool) -> PyResult<()> {
        self.rec_mut(addr)?.is_simprocedure = v;
        Ok(())
    }

    pub fn is_plt(&self, addr: u64) -> PyResult<bool> {
        Ok(self.rec(addr)?.is_plt)
    }

    pub fn set_is_plt(&mut self, addr: u64, v: bool) -> PyResult<()> {
        self.rec_mut(addr)?.is_plt = v;
        Ok(())
    }

    pub fn is_alignment(&self, addr: u64) -> PyResult<bool> {
        Ok(self.rec(addr)?.is_alignment)
    }

    pub fn set_is_alignment(&mut self, addr: u64, v: bool) -> PyResult<()> {
        self.rec_mut(addr)?.is_alignment = v;
        Ok(())
    }

    pub fn returning(&self, addr: u64) -> PyResult<Option<bool>> {
        Ok(self.rec(addr)?.returning)
    }

    pub fn set_returning(&mut self, addr: u64, v: Option<bool>) -> PyResult<()> {
        self.rec_mut(addr)?.returning = v;
        self.update_returning_sets(addr, v);
        Ok(())
    }

    // --- info ----------------------------------------------------------------------------------

    pub fn info_get(&self, py: Python<'_>, addr: u64, key: &str) -> PyResult<Option<Py<PyAny>>> {
        self.rec(addr)?
            .info
            .get(key)
            .map(|v| v.to_py(py).map(Bound::unbind))
            .transpose()
    }

    pub fn info_set(&mut self, addr: u64, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        self.rec_mut(addr)?
            .info
            .insert(key, InfoValue::from_py(value));
        Ok(())
    }

    pub fn info_del(&mut self, addr: u64, key: &str) -> PyResult<bool> {
        Ok(self.rec_mut(addr)?.info.shift_remove(key).is_some())
    }

    pub fn info_contains(&self, addr: u64, key: &str) -> PyResult<bool> {
        Ok(self.rec(addr)?.info.contains_key(key))
    }

    pub fn info_len(&self, addr: u64) -> PyResult<usize> {
        Ok(self.rec(addr)?.info.len())
    }

    pub fn info_keys(&self, addr: u64) -> PyResult<Vec<String>> {
        Ok(self.rec(addr)?.info.keys().cloned().collect())
    }

    /// The info of a function as a new dict, in insertion order.
    pub fn info_dict<'py>(&self, py: Python<'py>, addr: u64) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.rec(addr)?.info {
            d.set_item(k, v.to_py(py)?)?;
        }
        Ok(d)
    }

    pub fn info_replace(&mut self, addr: u64, info: &Bound<'_, PyDict>) -> PyResult<()> {
        let mut map = IndexMap::with_capacity(info.len());
        for (k, v) in info.iter() {
            map.insert(k.extract::<String>()?, InfoValue::from_py(&v));
        }
        self.rec_mut(addr)?.info = map;
        Ok(())
    }

    /// `info["gp"]`-style integer lookups from Rust.
    pub fn info_int(&self, addr: u64, key: &str) -> PyResult<Option<i64>> {
        Ok(match self.rec(addr)?.info.get(key) {
            Some(InfoValue::Int(v)) => Some(*v),
            Some(InfoValue::Bool(b)) => Some(*b as i64),
            _ => None,
        })
    }

    pub fn info_bool(&self, addr: u64, key: &str) -> PyResult<Option<bool>> {
        Ok(match self.rec(addr)?.info.get(key) {
            Some(InfoValue::Bool(b)) => Some(*b),
            Some(InfoValue::Int(v)) => Some(*v != 0),
            _ => None,
        })
    }

    // --- returning sets and block counts ----------------------------------------------------------

    pub fn nonreturning_addrs(&self) -> Vec<u64> {
        self.nonreturning.iter().copied().collect()
    }

    pub fn unknown_returning_addrs(&self) -> Vec<u64> {
        self.unknown_returning.iter().copied().collect()
    }

    pub fn is_nonreturning(&self, addr: u64) -> bool {
        self.nonreturning.contains(&addr)
    }

    pub fn is_returning_unknown(&self, addr: u64) -> bool {
        self.unknown_returning.contains(&addr)
    }

    /// The number of local blocks of a function, or None if it does not exist.
    pub fn block_count(&self, py: Python<'_>, addr: u64) -> Option<usize> {
        self.funcs
            .get(&addr)
            .map(|r| r.graph.bind(py).borrow().local_count())
    }

    pub fn addrs_with_block_count(&self, py: Python<'_>, count: usize) -> Vec<u64> {
        self.funcs
            .iter()
            .filter(|(_, r)| r.graph.bind(py).borrow().local_count() == count)
            .map(|(&a, _)| a)
            .collect()
    }

    // --- callgraph -----------------------------------------------------------------------------

    pub fn cg_add_node(&mut self, n: u64) {
        self.callgraph.add_node(n);
    }

    pub fn cg_add_edge(&mut self, u: u64, v: u64, ty: u8) -> PyResult<bool> {
        if ty > CG_EXCEPTION {
            return Err(PyValueError::new_err(format!(
                "unknown callgraph edge type {ty}"
            )));
        }
        Ok(self.callgraph.add_edge(u, v, ty))
    }

    pub fn cg_remove_node(&mut self, n: u64) -> bool {
        self.callgraph.remove_node(n)
    }

    pub fn cg_contains(&self, n: u64) -> bool {
        self.callgraph.contains(n)
    }

    pub fn cg_nodes(&self) -> Vec<u64> {
        self.callgraph.succ.keys().copied().collect()
    }

    pub fn cg_number_of_nodes(&self) -> usize {
        self.callgraph.succ.len()
    }

    pub fn cg_number_of_edges(&self) -> usize {
        self.callgraph.number_of_edges()
    }

    pub fn cg_predecessors(&self, n: u64) -> PyResult<Vec<u64>> {
        Ok(self
            .callgraph
            .pred
            .get(&n)
            .ok_or_else(|| missing(n))?
            .keys()
            .copied()
            .collect())
    }

    pub fn cg_successors(&self, n: u64) -> PyResult<Vec<u64>> {
        Ok(self
            .callgraph
            .succ
            .get(&n)
            .ok_or_else(|| missing(n))?
            .keys()
            .copied()
            .collect())
    }

    pub fn cg_in_degree(&self, n: u64) -> PyResult<usize> {
        let preds = self.callgraph.pred.get(&n).ok_or_else(|| missing(n))?;
        Ok(preds.keys().map(|u| self.callgraph.succ[u][&n].len()).sum())
    }

    pub fn cg_out_degree(&self, n: u64) -> PyResult<usize> {
        let succs = self.callgraph.succ.get(&n).ok_or_else(|| missing(n))?;
        Ok(succs.values().map(Vec::len).sum())
    }

    pub fn cg_has_edge(&self, u: u64, v: u64) -> bool {
        self.callgraph
            .succ
            .get(&u)
            .is_some_and(|m| m.contains_key(&v))
    }

    /// `(u, v, type)` of every out-edge of `n`, or of every edge when `n` is None.
    #[pyo3(signature = (n=None))]
    pub fn cg_out_edges(&self, n: Option<u64>) -> PyResult<Vec<(u64, u64, u8)>> {
        let mut out = Vec::new();
        match n {
            Some(u) => {
                if !self.callgraph.contains(u) {
                    return Err(missing(u));
                }
                self.cg_edges_of(u, &mut out);
            }
            None => {
                for &u in self.callgraph.succ.keys() {
                    self.cg_edges_of(u, &mut out);
                }
            }
        }
        Ok(out)
    }

    pub fn cg_in_edges(&self, n: u64) -> PyResult<Vec<(u64, u64, u8)>> {
        let preds = self.callgraph.pred.get(&n).ok_or_else(|| missing(n))?;
        let mut out = Vec::new();
        for &u in preds.keys() {
            for &t in &self.callgraph.succ[&u][&n] {
                out.push((u, n, t));
            }
        }
        Ok(out)
    }

    /// The edge types of (u, v) in insertion order.
    pub fn cg_edge_types(&self, u: u64, v: u64) -> Vec<u8> {
        self.callgraph
            .succ
            .get(&u)
            .and_then(|m| m.get(&v))
            .cloned()
            .unwrap_or_default()
    }

    pub fn cg_clear(&mut self) {
        self.callgraph = CallGraph::default();
        for &addr in self.funcs.keys() {
            self.callgraph.add_node(addr);
        }
    }

    // --- recovery API: the int-only `FunctionManager._add_*` ------------------------------------

    /// `FunctionManager._add_node`. Like every `add_*` method, it creates missing functions through the factory.
    #[pyo3(signature = (function_addr, node, syscall=None))]
    pub fn add_node(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        node: NodeSpec,
        syscall: Option<bool>,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        if let Some(s) = syscall {
            this.rec_mut(function_addr)?.is_syscall = s;
        }
        this.ops(py, function_addr)?.register(true, node);
        Ok(())
    }

    /// `FunctionManager._add_call_to`; the callee is created before the caller.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (function_addr, from_node, to_addr, retn_node=None, syscall=false, stmt_idx=None, ins_addr=None, return_to_outside=false))]
    pub fn add_call_to(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
        to_addr: Option<u64>,
        retn_node: Option<NodeSpec>,
        syscall: bool,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
        return_to_outside: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        if let Some(to_addr) = to_addr {
            Self::ensure_function(slf, to_addr, syscall)?;
        }
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        {
            let mut ops = this.ops(py, function_addr)?;
            ops.g
                .add_call_site(from_node.1, to_addr, retn_node.map(|n| n.1));
            if let Some(to_addr) = to_addr {
                ops.call_to(
                    from_node,
                    (NodeKind::Func, to_addr, 0, false),
                    retn_node,
                    stmt_idx,
                    ins_addr,
                    return_to_outside,
                    syscall,
                );
            }
            if return_to_outside {
                ops.add_retout_site(from_node);
            }
        }
        if let Some(to_addr) = to_addr {
            this.callgraph.add_edge(function_addr, to_addr, CG_CALL);
        }
        Ok(())
    }

    /// `FunctionManager._add_fakeret_to`
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (function_addr, from_node, to_node, confirmed=None, syscall=None, to_outside=false, to_function_addr=None))]
    pub fn add_fakeret_to(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
        to_node: NodeSpec,
        confirmed: Option<bool>,
        syscall: Option<bool>,
        to_outside: bool,
        to_function_addr: Option<u64>,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        if let Some(s) = syscall {
            this.rec_mut(function_addr)?.is_syscall = s;
        }
        this.ops(py, function_addr)?
            .fakeret_to(from_node, to_node, confirmed, to_outside);
        if to_outside && let Some(to_function_addr) = to_function_addr {
            this.callgraph
                .add_edge(function_addr, to_function_addr, CG_FAKERET);
        }
        Ok(())
    }

    /// `FunctionManager._remove_fakeret`; returns False when the edge does not exist.
    pub fn remove_fakeret(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
        to_node: NodeSpec,
    ) -> PyResult<bool> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        Ok(this.ops(py, function_addr)?.remove_edge(from_node, to_node))
    }

    /// `FunctionManager._add_return_from`
    pub fn add_return_from(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        this.ops(py, function_addr)?.add_return_site(from_node);
        Ok(())
    }

    /// `FunctionManager._add_transition_to`
    #[pyo3(signature = (function_addr, from_node, to_node, ins_addr=None, stmt_idx=None, is_exception=false))]
    pub fn add_transition_to(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
        to_node: NodeSpec,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        is_exception: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        this.ops(py, function_addr)?.transit_to(
            from_node,
            Some(to_node),
            false,
            ins_addr,
            stmt_idx,
            is_exception,
        );
        Ok(())
    }

    /// `FunctionManager._add_outside_transition_to`. `to_node=None` is the "snippet could not be lifted"
    /// fallback that only records a jump-out site.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (function_addr, from_node, to_node, to_function_addr=None, ins_addr=None, stmt_idx=None, is_exception=false))]
    pub fn add_outside_transition_to(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        from_node: NodeSpec,
        to_node: Option<NodeSpec>,
        to_function_addr: Option<u64>,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        is_exception: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        {
            let mut ops = this.ops(py, function_addr)?;
            let Some(to_node) = to_node else {
                ops.add_jumpout_site(from_node);
                return Ok(());
            };
            ops.transit_to(
                from_node,
                Some(to_node),
                true,
                ins_addr,
                stmt_idx,
                is_exception,
            );
        }
        if let Some(to_function_addr) = to_function_addr {
            let ty = if is_exception {
                CG_EXCEPTION
            } else {
                CG_TRANSITION
            };
            this.callgraph.add_edge(function_addr, to_function_addr, ty);
        }
        Ok(())
    }

    /// `FunctionManager._add_return_from_call`
    #[pyo3(signature = (function_addr, src_function_addr, to_node, to_outside=false))]
    pub fn add_return_from_call(
        slf: &Bound<'_, Self>,
        function_addr: u64,
        src_function_addr: u64,
        to_node: NodeSpec,
        to_outside: bool,
    ) -> PyResult<()> {
        let py = slf.py();
        Self::ensure_function(slf, function_addr, false)?;
        let mut this = slf.borrow_mut();
        this.ops(py, function_addr)?.return_from_call(
            (NodeKind::Func, src_function_addr, 0, false),
            to_node,
            to_outside,
        );
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "<RecoveryFunctions: {} functions, {} non-returning, {} callgraph edges>",
            self.funcs.len(),
            self.nonreturning.len(),
            self.callgraph.number_of_edges()
        )
    }
}

impl Default for RecoveryFunctions {
    fn default() -> Self {
        Self::new()
    }
}

pub fn recovery_functions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RecoveryFunctions>()?;
    m.add("LOG_REGISTER", LOG_REGISTER)?;
    m.add("LOG_GRAPH_NODE", LOG_GRAPH_NODE)?;
    m.add("LOG_ADD_EDGE", LOG_ADD_EDGE)?;
    m.add("LOG_SET_CONFIRMED", LOG_SET_CONFIRMED)?;
    m.add("LOG_REMOVE_EDGE", LOG_REMOVE_EDGE)?;
    m.add("REG_NEW_LOCAL", REG_NEW_LOCAL)?;
    m.add("REG_IN_GRAPH", REG_IN_GRAPH)?;
    m.add("CG_CALL", CG_CALL)?;
    m.add("CG_FAKERET", CG_FAKERET)?;
    m.add("CG_TRANSITION", CG_TRANSITION)?;
    m.add("CG_EXCEPTION", CG_EXCEPTION)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callgraph_keeps_insertion_order_and_dedupes_types() {
        let mut cg = CallGraph::default();
        assert!(cg.add_edge(1, 2, CG_CALL));
        assert!(!cg.add_edge(1, 2, CG_CALL));
        assert!(cg.add_edge(1, 2, CG_FAKERET));
        assert!(cg.add_edge(3, 2, CG_CALL));
        assert_eq!(cg.pred[&2].keys().copied().collect::<Vec<_>>(), vec![1, 3]);
        assert_eq!(cg.number_of_edges(), 3);
        assert!(cg.remove_node(1));
        assert_eq!(cg.pred[&2].keys().copied().collect::<Vec<_>>(), vec![3]);
        assert!(!cg.contains(1));
    }
}
