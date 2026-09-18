//! Packed storage for the transition graph of a `Function`.
//!
//! Exposed as `angr.rustylib.function_graph.FunctionGraph`. Node ids are indices into the node table and are
//! stable for the lifetime of the graph: `remove_node` only clears graph membership (and edges), so the id
//! maps (`local_at`, `addr_to_block`, ...) keep pointing at the same records, exactly like the old Python dicts
//! kept pointing at node objects that had left the networkx graph.

use indexmap::IndexMap;
use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyType};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

const FORMAT_VERSION: u8 = 1;

/// Which attribute keys the networkx edge-data dict carried. Reproducing the key set exactly keeps
/// `"outside" in data` style checks in callers behaving as before.
pub const PRESENT_TYPE: u8 = 1;
pub const PRESENT_OUTSIDE: u8 = 2;
pub const PRESENT_INS_ADDR: u8 = 4;
pub const PRESENT_STMT_IDX: u8 = 8;
pub const PRESENT_CONFIRMED: u8 = 16;

const SITE_RET: u8 = 1;
const SITE_JUMPOUT: u8 = 2;
const SITE_CALLOUT: u8 = 4;
const SITE_RETOUT: u8 = 8;
const EP_CALL: u8 = 16;
const EP_RETURN: u8 = 32;
const EP_TRANSITION: u8 = 64;
const EP_EXCEPTION: u8 = 128;

#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.function_graph",
    name = "NodeKind",
    skip_from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeKind {
    #[pyo3(name = "BLOCK")]
    Block = 0,
    #[pyo3(name = "FUNC")]
    Func = 1,
    #[pyo3(name = "HOOK")]
    Hook = 2,
    #[pyo3(name = "SYSCALL")]
    Syscall = 3,
}

#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.function_graph",
    name = "EdgeKind",
    skip_from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeKind {
    #[pyo3(name = "TRANSITION")]
    Transition = 0,
    #[pyo3(name = "CALL")]
    Call = 1,
    #[pyo3(name = "FAKE_RETURN")]
    FakeReturn = 2,
    #[pyo3(name = "RETURN")]
    Return = 3,
    #[pyo3(name = "EXCEPTION")]
    Exception = 4,
    #[pyo3(name = "SYSCALL")]
    Syscall = 5,
}

impl EdgeKind {
    fn as_str(self) -> &'static str {
        match self {
            EdgeKind::Transition => "transition",
            EdgeKind::Call => "call",
            EdgeKind::FakeReturn => "fake_return",
            EdgeKind::Return => "return",
            EdgeKind::Exception => "exception",
            EdgeKind::Syscall => "syscall",
        }
    }
}

#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.function_graph",
    name = "SiteKind",
    skip_from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SiteKind {
    #[pyo3(name = "RET")]
    Ret = 0,
    #[pyo3(name = "JUMPOUT")]
    Jumpout = 1,
    #[pyo3(name = "CALLOUT")]
    Callout = 2,
    #[pyo3(name = "RETOUT")]
    Retout = 3,
}

#[pyclass(
    eq,
    eq_int,
    module = "angr.rustylib.function_graph",
    name = "EndpointKind",
    skip_from_py_object
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EndpointKind {
    #[pyo3(name = "CALL")]
    Call = 0,
    #[pyo3(name = "RETURN")]
    Return = 1,
    #[pyo3(name = "TRANSITION")]
    Transition = 2,
    #[pyo3(name = "EXCEPTION")]
    Exception = 3,
}

macro_rules! enum_hash {
    ($ty:ident) => {
        #[pymethods]
        impl $ty {
            fn __hash__(&self) -> u64 {
                *self as u64
            }

            fn __int__(&self) -> u64 {
                *self as u64
            }
        }
    };
}

enum_hash!(NodeKind);
enum_hash!(EdgeKind);
enum_hash!(SiteKind);
enum_hash!(EndpointKind);

macro_rules! enum_from_py {
    ($ty:ident, $($v:literal => $variant:ident),+) => {
        impl<'py> FromPyObject<'_, 'py> for $ty {
            type Error = PyErr;

            fn extract(obj: pyo3::Borrowed<'_, 'py, PyAny>) -> Result<Self, Self::Error> {
                if let Ok(cell) = obj.cast::<$ty>() {
                    return Ok(*cell.borrow());
                }
                if let Ok(v) = obj.extract::<i64>() {
                    return match v {
                        $($v => Ok($ty::$variant),)+
                        _ => Err(PyValueError::new_err(format!(
                            "Unknown {} value: {}",
                            stringify!($ty),
                            v
                        ))),
                    };
                }
                Err(PyTypeError::new_err(format!(
                    "expected a {} or int",
                    stringify!($ty)
                )))
            }
        }
    };
}

enum_from_py!(NodeKind, 0 => Block, 1 => Func, 2 => Hook, 3 => Syscall);
enum_from_py!(EdgeKind, 0 => Transition, 1 => Call, 2 => FakeReturn, 3 => Return, 4 => Exception, 5 => Syscall);
enum_from_py!(SiteKind, 0 => Ret, 1 => Jumpout, 2 => Callout, 3 => Retout);
enum_from_py!(EndpointKind, 0 => Call, 1 => Return, 2 => Transition, 3 => Exception);

impl SiteKind {
    fn bit(self) -> u8 {
        match self {
            SiteKind::Ret => SITE_RET,
            SiteKind::Jumpout => SITE_JUMPOUT,
            SiteKind::Callout => SITE_CALLOUT,
            SiteKind::Retout => SITE_RETOUT,
        }
    }
}

impl EndpointKind {
    fn bit(self) -> u8 {
        match self {
            EndpointKind::Call => EP_CALL,
            EndpointKind::Return => EP_RETURN,
            EndpointKind::Transition => EP_TRANSITION,
            EndpointKind::Exception => EP_EXCEPTION,
        }
    }
}

type NodeKey = (NodeKind, u64, u32, bool);

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Node {
    addr: u64,
    size: u32,
    kind: NodeKind,
    thumb: bool,
    in_graph: bool,
    flags: u8,
}

impl Node {
    fn key(&self) -> NodeKey {
        (self.kind, self.addr, self.size, self.thumb)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Edge {
    kind: EdgeKind,
    present: u8,
    outside: bool,
    ins_addr: Option<u64>,
    stmt_idx: Option<i64>,
    confirmed: bool,
}

impl Edge {
    /// networkx `add_edge` semantics: keys given in the call overwrite, the rest survive.
    fn merge(&mut self, other: &Edge) {
        if other.present & PRESENT_TYPE != 0 {
            self.kind = other.kind;
        }
        if other.present & PRESENT_OUTSIDE != 0 {
            self.outside = other.outside;
        }
        if other.present & PRESENT_INS_ADDR != 0 {
            self.ins_addr = other.ins_addr;
        }
        if other.present & PRESENT_STMT_IDX != 0 {
            self.stmt_idx = other.stmt_idx;
        }
        if other.present & PRESENT_CONFIRMED != 0 {
            self.confirmed = other.confirmed;
        }
        self.present |= other.present;
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        if self.present & PRESENT_TYPE != 0 {
            d.set_item(intern!(py, "type"), self.kind.as_str())?;
        }
        if self.present & PRESENT_OUTSIDE != 0 {
            d.set_item(intern!(py, "outside"), self.outside)?;
        }
        if self.present & PRESENT_INS_ADDR != 0 {
            d.set_item(intern!(py, "ins_addr"), self.ins_addr)?;
        }
        if self.present & PRESENT_STMT_IDX != 0 {
            d.set_item(intern!(py, "stmt_idx"), self.stmt_idx)?;
        }
        if self.present & PRESENT_CONFIRMED != 0 {
            d.set_item(intern!(py, "confirmed"), self.confirmed)?;
        }
        Ok(d)
    }

    /// Edges the local (intra-function) graph keeps: non-outside transitions, exceptions and fake returns.
    fn is_local(&self) -> bool {
        self.present & PRESENT_TYPE != 0
            && matches!(
                self.kind,
                EdgeKind::Transition | EdgeKind::Exception | EdgeKind::FakeReturn
            )
            && !(self.present & PRESENT_OUTSIDE != 0 && self.outside)
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    func_addr: u64,
    nodes: Vec<Node>,
    edges: Vec<(u32, u32, Edge)>,
    startpoint: Option<u32>,
    local_at: Vec<(u64, u32)>,
    addr_to_block: Vec<(u64, u32)>,
    block_sizes: Vec<(u64, u32)>,
    call_sites: Vec<(u64, Option<u64>, Option<u64>)>,
}

#[pyclass(module = "angr.rustylib.function_graph")]
#[derive(Clone)]
pub struct FunctionGraph {
    func_addr: u64,
    nodes: Vec<Node>,
    by_key: FxHashMap<NodeKey, u32>,
    edges: FxHashMap<(u32, u32), Edge>,
    out_adj: Vec<Vec<u32>>,
    in_adj: Vec<Vec<u32>>,
    startpoint: Option<u32>,
    local_at: IndexMap<u64, u32>,
    addr_to_block: FxHashMap<u64, u32>,
    block_sizes: FxHashMap<u64, u32>,
    call_sites: IndexMap<u64, (Option<u64>, Option<u64>)>,
}

impl FunctionGraph {
    fn node_ref(&self, idx: u32) -> PyResult<&Node> {
        self.nodes
            .get(idx as usize)
            .ok_or_else(|| PyKeyError::new_err(format!("no node with id {idx}")))
    }

    fn new_entry(&mut self, kind: NodeKind, addr: u64, size: u32, thumb: bool) -> u32 {
        let idx = self.nodes.len() as u32;
        self.nodes.push(Node {
            addr,
            size,
            kind,
            thumb,
            in_graph: false,
            flags: 0,
        });
        self.by_key.insert((kind, addr, size, thumb), idx);
        self.out_adj.push(Vec::new());
        self.in_adj.push(Vec::new());
        idx
    }

    fn find_or_create(&mut self, kind: NodeKind, addr: u64, size: u32, thumb: bool) -> (u32, bool) {
        match self.by_key.get(&(kind, addr, size, thumb)) {
            Some(&idx) => (idx, false),
            None => (self.new_entry(kind, addr, size, thumb), true),
        }
    }

    fn insert_edge(&mut self, src: u32, dst: u32, edge: Edge) -> bool {
        if let Some(existing) = self.edges.get_mut(&(src, dst)) {
            existing.merge(&edge);
            return false;
        }
        self.nodes[src as usize].in_graph = true;
        self.nodes[dst as usize].in_graph = true;
        self.edges.insert((src, dst), edge);
        self.out_adj[src as usize].push(dst);
        self.in_adj[dst as usize].push(src);
        true
    }

    fn delete_edge(&mut self, src: u32, dst: u32) -> bool {
        if self.edges.remove(&(src, dst)).is_none() {
            return false;
        }
        self.out_adj[src as usize].retain(|&d| d != dst);
        self.in_adj[dst as usize].retain(|&s| s != src);
        true
    }

    fn detach_node(&mut self, idx: u32) -> bool {
        let node = &mut self.nodes[idx as usize];
        if !node.in_graph {
            return false;
        }
        node.in_graph = false;
        for dst in std::mem::take(&mut self.out_adj[idx as usize]) {
            self.edges.remove(&(idx, dst));
            self.in_adj[dst as usize].retain(|&s| s != idx);
        }
        for src in std::mem::take(&mut self.in_adj[idx as usize]) {
            self.edges.remove(&(src, idx));
            self.out_adj[src as usize].retain(|&d| d != idx);
        }
        true
    }

    fn graph_nodes(&self) -> impl Iterator<Item = u32> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.in_graph)
            .map(|(i, _)| i as u32)
    }

    fn edge_pairs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.graph_nodes()
            .flat_map(move |u| self.out_adj[u as usize].iter().map(move |&v| (u, v)))
    }

    fn nodes_with_flag(&self, bit: u8) -> Vec<u32> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.flags & bit != 0)
            .map(|(i, _)| i as u32)
            .collect()
    }

    fn to_payload(&self) -> Payload {
        // keep graph members plus every record a map or flag still refers to; renumber densely
        let mut keep = vec![false; self.nodes.len()];
        for (i, n) in self.nodes.iter().enumerate() {
            keep[i] = n.in_graph || n.flags != 0;
        }
        for &idx in self
            .local_at
            .values()
            .chain(self.addr_to_block.values())
            .chain(self.startpoint.iter())
        {
            keep[idx as usize] = true;
        }
        let mut remap = vec![u32::MAX; self.nodes.len()];
        let mut nodes = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            if keep[i] {
                remap[i] = nodes.len() as u32;
                nodes.push(*n);
            }
        }
        let edges = self
            .edge_pairs()
            .map(|(u, v)| (remap[u as usize], remap[v as usize], self.edges[&(u, v)]))
            .collect();
        let mut block_sizes: Vec<(u64, u32)> =
            self.block_sizes.iter().map(|(&a, &s)| (a, s)).collect();
        block_sizes.sort_unstable();
        let mut addr_to_block: Vec<(u64, u32)> = self
            .addr_to_block
            .iter()
            .map(|(&a, &i)| (a, remap[i as usize]))
            .collect();
        addr_to_block.sort_unstable();
        Payload {
            func_addr: self.func_addr,
            nodes,
            edges,
            startpoint: self.startpoint.map(|i| remap[i as usize]),
            local_at: self
                .local_at
                .iter()
                .map(|(&a, &i)| (a, remap[i as usize]))
                .collect(),
            addr_to_block,
            block_sizes,
            call_sites: self
                .call_sites
                .iter()
                .map(|(&a, &(t, r))| (a, t, r))
                .collect(),
        }
    }

    fn from_payload(p: Payload) -> PyResult<Self> {
        let n = p.nodes.len();
        let check = |idx: u32| -> PyResult<u32> {
            if (idx as usize) < n {
                Ok(idx)
            } else {
                Err(PyValueError::new_err(
                    "corrupt FunctionGraph payload: node id out of range",
                ))
            }
        };
        let mut g = FunctionGraph {
            func_addr: p.func_addr,
            nodes: p.nodes,
            by_key: FxHashMap::default(),
            edges: FxHashMap::default(),
            out_adj: vec![Vec::new(); n],
            in_adj: vec![Vec::new(); n],
            startpoint: p.startpoint.map(check).transpose()?,
            local_at: IndexMap::with_capacity(p.local_at.len()),
            addr_to_block: FxHashMap::default(),
            block_sizes: p.block_sizes.into_iter().collect(),
            call_sites: p
                .call_sites
                .into_iter()
                .map(|(a, t, r)| (a, (t, r)))
                .collect(),
        };
        for (i, node) in g.nodes.iter().enumerate() {
            g.by_key.insert(node.key(), i as u32);
        }
        for (src, dst, edge) in p.edges {
            check(src)?;
            check(dst)?;
            g.edges.insert((src, dst), edge);
            g.out_adj[src as usize].push(dst);
            g.in_adj[dst as usize].push(src);
        }
        for (a, i) in p.local_at {
            g.local_at.insert(a, check(i)?);
        }
        for (a, i) in p.addr_to_block {
            g.addr_to_block.insert(a, check(i)?);
        }
        Ok(g)
    }

    fn decode(data: &[u8]) -> PyResult<Self> {
        match data.split_first() {
            Some((&FORMAT_VERSION, rest)) => {
                let payload: Payload = postcard::from_bytes(rest)
                    .map_err(|e| PyValueError::new_err(format!("FunctionGraph.from_bytes: {e}")))?;
                Self::from_payload(payload)
            }
            Some((v, _)) => Err(PyValueError::new_err(format!(
                "unsupported FunctionGraph format version {v}"
            ))),
            None => Err(PyValueError::new_err("empty FunctionGraph payload")),
        }
    }
}

#[pymethods]
impl FunctionGraph {
    #[new]
    pub fn new(func_addr: u64) -> Self {
        FunctionGraph {
            func_addr,
            nodes: Vec::new(),
            by_key: FxHashMap::default(),
            edges: FxHashMap::default(),
            out_adj: Vec::new(),
            in_adj: Vec::new(),
            startpoint: None,
            local_at: IndexMap::new(),
            addr_to_block: FxHashMap::default(),
            block_sizes: FxHashMap::default(),
            call_sites: IndexMap::new(),
        }
    }

    #[getter]
    fn func_addr(&self) -> u64 {
        self.func_addr
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "<FunctionGraph {:#x}: {} nodes, {} edges>",
            self.func_addr,
            self.number_of_nodes(),
            self.edges.len()
        )
    }

    // --- nodes ---------------------------------------------------------------------------------

    pub fn number_of_nodes(&self) -> usize {
        self.graph_nodes().count()
    }

    pub fn number_of_edges(&self) -> usize {
        self.edges.len()
    }

    /// Insert a node into the graph (networkx `add_node`). Returns `(id, created)`.
    pub fn add_node(&mut self, kind: NodeKind, addr: u64, size: u32, thumb: bool) -> (u32, bool) {
        let (idx, created) = self.find_or_create(kind, addr, size, thumb);
        self.nodes[idx as usize].in_graph = true;
        (idx, created)
    }

    /// Port of `Function._register_node`. Returns `(id, created, new_local, changed)`: `created` tells the
    /// caller that the id is fresh and it should keep the incoming CodeNode object as the canonical object for
    /// it; `changed` is False only on the early-return path (an equal local node was already registered).
    pub fn register_node(
        &mut self,
        is_local: bool,
        kind: NodeKind,
        addr: u64,
        size: u32,
        thumb: bool,
    ) -> (u32, bool, bool, bool) {
        let key = (kind, addr, size, thumb);
        if is_local {
            if let Some(&idx) = self.local_at.get(&addr) {
                if self.nodes[idx as usize].key() == key {
                    return (idx, false, false, false);
                }
            }
        }
        let (idx, created) = self.find_or_create(kind, addr, size, thumb);
        if !self.block_sizes.contains_key(&addr) {
            self.nodes[idx as usize].in_graph = true;
        }
        if self.block_sizes.get(&addr).copied().unwrap_or(0) == 0 {
            self.block_sizes.insert(addr, size);
        }
        if addr == self.func_addr {
            let startpoint_is_hook = self
                .startpoint
                .map(|s| self.nodes[s as usize].kind == NodeKind::Hook)
                .unwrap_or(false);
            if !startpoint_is_hook {
                self.startpoint = Some(idx);
            }
        }
        let mut new_local = false;
        if is_local && !self.local_at.contains_key(&addr) {
            self.local_at.insert(addr, idx);
            new_local = true;
        }
        if kind == NodeKind::Block && !self.addr_to_block.contains_key(&addr) {
            self.addr_to_block.insert(addr, idx);
        }
        (idx, created, new_local, true)
    }

    pub fn find_node(&self, kind: NodeKind, addr: u64, size: u32, thumb: bool) -> Option<u32> {
        self.by_key.get(&(kind, addr, size, thumb)).copied()
    }

    pub fn contains_node(&self, idx: u32) -> bool {
        self.nodes
            .get(idx as usize)
            .map(|n| n.in_graph)
            .unwrap_or(false)
    }

    /// `(kind, addr, size, thumb)` of a node id.
    pub fn node(&self, idx: u32) -> PyResult<(NodeKind, u64, u32, bool)> {
        let n = self.node_ref(idx)?;
        Ok((n.kind, n.addr, n.size, n.thumb))
    }

    pub fn node_addr(&self, idx: u32) -> PyResult<u64> {
        Ok(self.node_ref(idx)?.addr)
    }

    pub fn node_size(&self, idx: u32) -> PyResult<u32> {
        Ok(self.node_ref(idx)?.size)
    }

    pub fn node_kind(&self, idx: u32) -> PyResult<NodeKind> {
        Ok(self.node_ref(idx)?.kind)
    }

    /// Ids of all graph members, in insertion order.
    pub fn nodes(&self) -> Vec<u32> {
        self.graph_nodes().collect()
    }

    /// Remove a node and its edges from the graph. Maps and flags that refer to it are left untouched.
    pub fn remove_node(&mut self, idx: u32) -> PyResult<bool> {
        self.node_ref(idx)?;
        Ok(self.detach_node(idx))
    }

    // --- edges ---------------------------------------------------------------------------------

    /// networkx `add_edge(u, v, **data)`: `present` says which keys were given. Missing nodes are added to the
    /// graph. Returns True if the edge is new.
    #[pyo3(signature = (src, dst, kind, present, outside=false, ins_addr=None, stmt_idx=None, confirmed=false))]
    #[allow(clippy::too_many_arguments)]
    pub fn add_edge(
        &mut self,
        src: u32,
        dst: u32,
        kind: EdgeKind,
        present: u8,
        outside: bool,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        confirmed: bool,
    ) -> PyResult<bool> {
        self.node_ref(src)?;
        self.node_ref(dst)?;
        Ok(self.insert_edge(
            src,
            dst,
            Edge {
                kind,
                present,
                outside,
                ins_addr,
                stmt_idx,
                confirmed,
            },
        ))
    }

    pub fn remove_edge(&mut self, src: u32, dst: u32) -> bool {
        self.delete_edge(src, dst)
    }

    pub fn has_edge(&self, src: u32, dst: u32) -> bool {
        self.edges.contains_key(&(src, dst))
    }

    /// The edge-data dict of an edge, or None.
    pub fn edge_data<'py>(
        &self,
        py: Python<'py>,
        src: u32,
        dst: u32,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        self.edges
            .get(&(src, dst))
            .map(|e| e.to_dict(py))
            .transpose()
    }

    pub fn set_edge_confirmed(&mut self, src: u32, dst: u32, confirmed: bool) -> PyResult<()> {
        let edge = self
            .edges
            .get_mut(&(src, dst))
            .ok_or_else(|| PyKeyError::new_err(format!("no edge ({src}, {dst})")))?;
        edge.confirmed = confirmed;
        edge.present |= PRESENT_CONFIRMED;
        Ok(())
    }

    pub fn edge_kind(&self, src: u32, dst: u32) -> Option<EdgeKind> {
        self.edges
            .get(&(src, dst))
            .filter(|e| e.present & PRESENT_TYPE != 0)
            .map(|e| e.kind)
    }

    pub fn edge_is_outside(&self, src: u32, dst: u32) -> Option<bool> {
        self.edges
            .get(&(src, dst))
            .map(|e| e.present & PRESENT_OUTSIDE != 0 && e.outside)
    }

    pub fn edge_confirmed(&self, src: u32, dst: u32) -> Option<Option<bool>> {
        self.edges.get(&(src, dst)).map(|e| {
            if e.present & PRESENT_CONFIRMED != 0 {
                Some(e.confirmed)
            } else {
                None
            }
        })
    }

    /// `(src, dst)` pairs in networkx iteration order.
    pub fn edges(&self) -> Vec<(u32, u32)> {
        self.edge_pairs().collect()
    }

    /// `(src, dst, data)` triples in networkx iteration order.
    pub fn edges_with_data<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<(u32, u32, Bound<'py, PyDict>)>> {
        self.edge_pairs()
            .map(|(u, v)| Ok((u, v, self.edges[&(u, v)].to_dict(py)?)))
            .collect()
    }

    /// Edges of the local (intra-function) view, with data.
    pub fn local_edges_with_data<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<(u32, u32, Bound<'py, PyDict>)>> {
        self.edge_pairs()
            .filter(|(u, v)| self.edges[&(*u, *v)].is_local())
            .map(|(u, v)| Ok((u, v, self.edges[&(u, v)].to_dict(py)?)))
            .collect()
    }

    pub fn edges_of_kind(&self, kind: EdgeKind) -> Vec<(u32, u32)> {
        self.edge_pairs()
            .filter(|(u, v)| {
                let e = &self.edges[&(*u, *v)];
                e.present & PRESENT_TYPE != 0 && e.kind == kind
            })
            .collect()
    }

    pub fn out_edges(&self, idx: u32) -> PyResult<Vec<(u32, u32)>> {
        self.node_ref(idx)?;
        Ok(self.out_adj[idx as usize]
            .iter()
            .map(|&v| (idx, v))
            .collect())
    }

    pub fn in_edges(&self, idx: u32) -> PyResult<Vec<(u32, u32)>> {
        self.node_ref(idx)?;
        Ok(self.in_adj[idx as usize]
            .iter()
            .map(|&u| (u, idx))
            .collect())
    }

    pub fn successors(&self, idx: u32) -> PyResult<Vec<u32>> {
        self.node_ref(idx)?;
        Ok(self.out_adj[idx as usize].clone())
    }

    pub fn predecessors(&self, idx: u32) -> PyResult<Vec<u32>> {
        self.node_ref(idx)?;
        Ok(self.in_adj[idx as usize].clone())
    }

    pub fn out_degree(&self, idx: u32) -> PyResult<usize> {
        self.node_ref(idx)?;
        Ok(self.out_adj[idx as usize].len())
    }

    pub fn in_degree(&self, idx: u32) -> PyResult<usize> {
        self.node_ref(idx)?;
        Ok(self.in_adj[idx as usize].len())
    }

    /// Addresses of callees and jump-out targets: FuncNode/HookNode/SyscallNode members (other than the start
    /// node of a hooked function) plus targets of outside transition edges. This is what the call graph needs.
    pub fn outgoing_function_targets(&self) -> Vec<(u64, bool)> {
        let mut out = Vec::new();
        for idx in self.graph_nodes() {
            let n = &self.nodes[idx as usize];
            if matches!(n.kind, NodeKind::Hook | NodeKind::Syscall) && n.addr == self.func_addr {
                continue;
            }
            if matches!(n.kind, NodeKind::Func | NodeKind::Hook | NodeKind::Syscall) {
                out.push((n.addr, true));
            } else if self.in_adj[idx as usize].iter().any(|&u| {
                let e = &self.edges[&(u, idx)];
                e.present & PRESENT_TYPE != 0
                    && e.kind == EdgeKind::Transition
                    && e.present & PRESENT_OUTSIDE != 0
                    && e.outside
            }) {
                out.push((n.addr, false));
            }
        }
        out
    }

    // --- startpoint, local blocks, block sizes ----------------------------------------------------

    #[getter]
    pub fn get_startpoint(&self) -> Option<u32> {
        self.startpoint
    }

    #[setter]
    pub fn set_startpoint(&mut self, idx: Option<u32>) -> PyResult<()> {
        if let Some(i) = idx {
            self.node_ref(i)?;
        }
        self.startpoint = idx;
        Ok(())
    }

    pub fn local_at(&self, addr: u64) -> Option<u32> {
        self.local_at.get(&addr).copied()
    }

    pub fn set_local_at(&mut self, addr: u64, idx: u32) -> PyResult<()> {
        self.node_ref(idx)?;
        self.local_at.insert(addr, idx);
        Ok(())
    }

    pub fn is_local(&self, addr: u64) -> bool {
        self.local_at.contains_key(&addr)
    }

    pub fn local_addrs(&self) -> Vec<u64> {
        self.local_at.keys().copied().collect()
    }

    pub fn local_items(&self) -> Vec<(u64, u32)> {
        self.local_at.iter().map(|(&a, &i)| (a, i)).collect()
    }

    pub fn local_count(&self) -> usize {
        self.local_at.len()
    }

    /// Sum of the recorded block sizes of all local blocks (`Function.size`).
    pub fn local_size(&self) -> u64 {
        self.local_at
            .keys()
            .map(|a| self.block_sizes.get(a).copied().unwrap_or(0) as u64)
            .sum()
    }

    pub fn block_node_at(&self, addr: u64) -> Option<u32> {
        self.addr_to_block.get(&addr).copied()
    }

    pub fn set_block_node_at(&mut self, addr: u64, idx: u32) -> PyResult<()> {
        self.node_ref(idx)?;
        self.addr_to_block.insert(addr, idx);
        Ok(())
    }

    pub fn block_size(&self, addr: u64) -> Option<u32> {
        self.block_sizes.get(&addr).copied()
    }

    pub fn set_block_size(&mut self, addr: u64, size: u32) {
        self.block_sizes.insert(addr, size);
    }

    pub fn has_block_size(&self, addr: u64) -> bool {
        self.block_sizes.contains_key(&addr)
    }

    // --- sites and endpoints -------------------------------------------------------------------

    pub fn add_site(&mut self, idx: u32, kind: SiteKind) -> PyResult<()> {
        self.node_ref(idx)?;
        self.nodes[idx as usize].flags |= kind.bit();
        Ok(())
    }

    pub fn has_site(&self, idx: u32, kind: SiteKind) -> PyResult<bool> {
        Ok(self.node_ref(idx)?.flags & kind.bit() != 0)
    }

    pub fn sites(&self, kind: SiteKind) -> Vec<u32> {
        self.nodes_with_flag(kind.bit())
    }

    pub fn add_endpoint(&mut self, idx: u32, kind: EndpointKind) -> PyResult<()> {
        self.node_ref(idx)?;
        self.nodes[idx as usize].flags |= kind.bit();
        Ok(())
    }

    pub fn endpoints(&self, kind: EndpointKind) -> Vec<u32> {
        self.nodes_with_flag(kind.bit())
    }

    pub fn has_endpoint(&self, idx: u32, kind: EndpointKind) -> PyResult<bool> {
        Ok(self.node_ref(idx)?.flags & kind.bit() != 0)
    }

    pub fn has_any_endpoint(&self) -> bool {
        self.nodes
            .iter()
            .any(|n| n.flags & (EP_CALL | EP_RETURN | EP_TRANSITION | EP_EXCEPTION) != 0)
    }

    // --- call sites ----------------------------------------------------------------------------

    pub fn add_call_site(&mut self, addr: u64, target: Option<u64>, ret: Option<u64>) {
        self.call_sites.insert(addr, (target, ret));
    }

    pub fn call_site(&self, addr: u64) -> Option<(Option<u64>, Option<u64>)> {
        self.call_sites.get(&addr).copied()
    }

    pub fn call_sites(&self) -> Vec<(u64, Option<u64>, Option<u64>)> {
        self.call_sites
            .iter()
            .map(|(&a, &(t, r))| (a, t, r))
            .collect()
    }

    pub fn call_site_addrs(&self) -> Vec<u64> {
        self.call_sites.keys().copied().collect()
    }

    // --- normalization -------------------------------------------------------------------------

    /// Port of `Function.normalize`: split overlapping blocks that share an end address.
    /// `branch_ins_addr(addr, size)` lifts a block and returns the address of its branch instruction.
    pub fn normalize(&mut self, is_arm: bool, branch_ins_addr: &Bound<'_, PyAny>) -> PyResult<()> {
        let real = |a: u64| if is_arm { a & !1 } else { a };
        let mut end_addresses: IndexMap<u64, Vec<u32>> = IndexMap::new();
        for idx in self.graph_nodes() {
            let n = &self.nodes[idx as usize];
            if n.kind == NodeKind::Block {
                end_addresses
                    .entry(n.addr.wrapping_add(n.size as u64))
                    .or_default()
                    .push(idx);
            }
        }

        loop {
            let Some((&end_addr, group)) = end_addresses.iter().find(|(_, v)| v.len() > 1) else {
                break;
            };
            let mut all_nodes = group.clone();
            all_nodes.sort_by_key(|&i| self.nodes[i as usize].size);
            let smallest = all_nodes[0];
            let others: Vec<u32> = all_nodes[1..].to_vec();
            let is_outside_node = !self.nodes[smallest as usize].in_graph;

            for &n in &others {
                let n_addr = self.nodes[n as usize].addr;
                let n_thumb = self.nodes[n as usize].thumb;
                let new_size =
                    real(self.nodes[smallest as usize].addr) as i64 - real(n_addr) as i64;
                if new_size <= 0 {
                    continue;
                }
                let new_size = new_size as u32;
                let new_end = n_addr.wrapping_add(new_size as u64);

                let existing = end_addresses.get(&new_end).and_then(|v| {
                    v.iter()
                        .copied()
                        .find(|&i| self.nodes[i as usize].addr == n_addr)
                });
                let new_node = match existing {
                    Some(i) => i,
                    None => {
                        let (i, _) =
                            self.find_or_create(NodeKind::Block, n_addr, new_size, n_thumb);
                        self.block_sizes.insert(n_addr, new_size);
                        self.addr_to_block.insert(n_addr, i);
                        end_addresses.entry(new_end).or_default().push(i);
                        i
                    }
                };

                let preds: Vec<(u32, Edge)> = self.in_adj[n as usize]
                    .iter()
                    .map(|&p| (p, self.edges[&(p, n)]))
                    .collect();
                let succs: Vec<(u32, Edge)> = self.out_adj[n as usize]
                    .iter()
                    .map(|&d| (d, self.edges[&(n, d)]))
                    .collect();

                for &(d, data) in &succs {
                    if data.present & PRESENT_INS_ADDR != 0 {
                        if let Some(ins_addr) = data.ins_addr {
                            if ins_addr < self.nodes[d as usize].addr {
                                continue;
                            }
                        }
                    }
                    if !self.edges.contains_key(&(smallest, d)) {
                        let target = if d == n { new_node } else { d };
                        self.insert_edge(smallest, target, data);
                    }
                }
                self.detach_node(n);

                if let Some(&local) = self.local_at.get(&n_addr) {
                    if self.nodes[local as usize].size != new_size {
                        self.local_at.shift_remove(&n_addr);
                        self.local_at.insert(n_addr, new_node);
                    }
                }
                if let Some(&size) = self.block_sizes.get(&n_addr) {
                    if size != new_size {
                        self.block_sizes.insert(n_addr, new_size);
                    }
                }
                for &(p, data) in &preds {
                    if !others.contains(&p) {
                        self.insert_edge(p, new_node, data);
                    }
                }

                let smallest_addr = self.nodes[smallest as usize].addr;
                if let Some(&new_successor) = all_nodes
                    .iter()
                    .find(|&&i| self.nodes[i as usize].addr == smallest_addr)
                {
                    let computed: Option<u64> =
                        branch_ins_addr.call1((n_addr, new_size))?.extract()?;
                    let new_ins_addr =
                        computed.unwrap_or(n_addr.wrapping_add(new_size as u64).wrapping_sub(1));
                    self.insert_edge(
                        new_node,
                        new_successor,
                        Edge {
                            kind: EdgeKind::Transition,
                            present: PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR,
                            outside: is_outside_node,
                            ins_addr: Some(new_ins_addr),
                            stmt_idx: None,
                            confirmed: false,
                        },
                    );
                }

                let flags = std::mem::take(&mut self.nodes[n as usize].flags);
                self.nodes[smallest as usize].flags |= flags;
            }
            end_addresses.insert(end_addr, vec![smallest]);
        }

        if let Some(sp) = self.startpoint {
            let sp_node = self.nodes[sp as usize];
            if self.block_sizes.get(&sp_node.addr).copied() != Some(sp_node.size) {
                self.startpoint = self.addr_to_block.get(&sp_node.addr).copied();
            }
        }
        Ok(())
    }

    // --- serialization -------------------------------------------------------------------------

    pub fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = vec![FORMAT_VERSION];
        postcard::to_io(&self.to_payload(), &mut out)
            .map_err(|e| PyValueError::new_err(format!("FunctionGraph.to_bytes: {e}")))?;
        Ok(PyBytes::new(py, &out))
    }

    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> PyResult<Self> {
        Self::decode(data)
    }

    /// Local block addresses of a serialized graph, without keeping the graph.
    #[staticmethod]
    pub fn local_block_addrs_from_bytes(data: &[u8]) -> PyResult<Vec<u64>> {
        Ok(Self::decode(data)?.local_addrs())
    }

    fn __reduce__<'py>(
        slf: Bound<'py, Self>,
    ) -> PyResult<(Bound<'py, PyAny>, (Bound<'py, PyBytes>,))> {
        let py = slf.py();
        let bytes = slf.borrow().to_bytes(py)?;
        let from_bytes = slf.get_type().getattr("from_bytes")?;
        Ok((from_bytes, (bytes,)))
    }
}

pub fn function_graph(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<NodeKind>()?;
    m.add_class::<EdgeKind>()?;
    m.add_class::<SiteKind>()?;
    m.add_class::<EndpointKind>()?;
    m.add_class::<FunctionGraph>()?;
    m.add("PRESENT_TYPE", PRESENT_TYPE)?;
    m.add("PRESENT_OUTSIDE", PRESENT_OUTSIDE)?;
    m.add("PRESENT_INS_ADDR", PRESENT_INS_ADDR)?;
    m.add("PRESENT_STMT_IDX", PRESENT_STMT_IDX)?;
    m.add("PRESENT_CONFIRMED", PRESENT_CONFIRMED)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_nodes_edges_and_maps() {
        let mut g = FunctionGraph::new(0x1000);
        let (a, _, _, _) = g.register_node(true, NodeKind::Block, 0x1000, 8, false);
        let (b, _, _, _) = g.register_node(true, NodeKind::Block, 0x1008, 4, false);
        let (f, _) = g.add_node(NodeKind::Func, 0x2000, 0, false);
        g.add_edge(
            a,
            b,
            EdgeKind::Transition,
            PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR,
            false,
            Some(0x1004),
            None,
            false,
        )
        .unwrap();
        g.add_edge(
            b,
            f,
            EdgeKind::Call,
            PRESENT_TYPE | PRESENT_STMT_IDX,
            false,
            None,
            Some(-2),
            false,
        )
        .unwrap();
        g.add_site(b, SiteKind::Ret).unwrap();
        g.add_endpoint(b, EndpointKind::Return).unwrap();
        g.add_call_site(0x1008, Some(0x2000), None);

        let payload = g.to_payload();
        let bytes = postcard::to_stdvec(&payload).unwrap();
        let back = FunctionGraph::from_payload(postcard::from_bytes(&bytes).unwrap()).unwrap();

        assert_eq!(back.nodes(), vec![0, 1, 2]);
        assert_eq!(back.edges(), vec![(0, 1), (1, 2)]);
        assert_eq!(back.get_startpoint(), Some(0));
        assert_eq!(back.local_addrs(), vec![0x1000, 0x1008]);
        assert_eq!(back.block_size(0x1008), Some(4));
        assert_eq!(back.sites(SiteKind::Ret), vec![1]);
        assert_eq!(back.endpoints(EndpointKind::Return), vec![1]);
        assert_eq!(back.call_sites(), vec![(0x1008, Some(0x2000), None)]);
        let e = back.edges[&(1, 2)];
        assert_eq!(e.stmt_idx, Some(-2));
        assert_eq!(e.present, PRESENT_TYPE | PRESENT_STMT_IDX);
    }

    #[test]
    fn add_edge_merges_like_networkx() {
        let mut g = FunctionGraph::new(0);
        let (a, _) = g.add_node(NodeKind::Block, 0, 1, false);
        let (b, _) = g.add_node(NodeKind::Block, 1, 1, false);
        g.add_edge(
            a,
            b,
            EdgeKind::FakeReturn,
            PRESENT_TYPE | PRESENT_OUTSIDE,
            false,
            None,
            None,
            false,
        )
        .unwrap();
        g.add_edge(
            a,
            b,
            EdgeKind::Transition,
            PRESENT_TYPE | PRESENT_INS_ADDR,
            true,
            Some(7),
            None,
            false,
        )
        .unwrap();
        let e = g.edges[&(a, b)];
        assert_eq!(e.kind, EdgeKind::Transition);
        assert!(!e.outside);
        assert_eq!(e.ins_addr, Some(7));
        assert_eq!(e.present, PRESENT_TYPE | PRESENT_OUTSIDE | PRESENT_INS_ADDR);
        assert_eq!(g.number_of_edges(), 1);
    }

    #[test]
    fn remove_node_keeps_maps() {
        let mut g = FunctionGraph::new(0x10);
        let (a, _, _, _) = g.register_node(true, NodeKind::Block, 0x10, 2, false);
        let (b, _, _, _) = g.register_node(true, NodeKind::Block, 0x12, 2, false);
        g.add_edge(
            a,
            b,
            EdgeKind::Transition,
            PRESENT_TYPE,
            false,
            None,
            None,
            false,
        )
        .unwrap();
        assert!(g.remove_node(b).unwrap());
        assert_eq!(g.number_of_edges(), 0);
        assert_eq!(g.nodes(), vec![a]);
        assert_eq!(g.local_at(0x12), Some(b));
        assert_eq!(g.out_degree(a).unwrap(), 0);
    }
}
