//! Packed storage for the whole-program CFG graph (`CFGModel.graph`).
//!
//! Exposed as `angr.rustylib.cfg_graph.CfgGraph`. Nodes are `(addr, size)` keys mapped to dense ids; the
//! owning Python `SpillingCFG` maps its block keys onto them. Ids are stable for the lifetime of the graph:
//! `remove_node` detaches a node, and re-adding the same key allocates a fresh id so that node iteration order
//! matches networkx (re-added nodes come last).

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyType};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

const FORMAT_VERSION: u8 = 1;

pub const PRESENT_JUMPKIND: u8 = 1;
pub const PRESENT_INS_ADDR: u8 = 2;
pub const PRESENT_STMT_IDX: u8 = 4;

const NO_JK: u16 = u16::MAX;
const NO_INS_ADDR: u64 = u64::MAX;
const NO_STMT_IDX: i64 = i64::MIN;
const NIL: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Node {
    addr: u64,
    size: i64,
    in_graph: bool,
    /// Sticky call-destination flag (see `SpillingCFG.call_destination_keys`).
    call_dst: bool,
    /// Next live node with the same address (intrusive list headed by `by_addr`).
    next_at_addr: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Edge {
    jk: u16,
    present: u8,
    ins_addr: u64,
    stmt_idx: i64,
}

impl Edge {
    /// networkx `add_edge` semantics: passed attributes overwrite, others are kept.
    fn merge(&mut self, other: &Edge) {
        if other.present & PRESENT_JUMPKIND != 0 {
            self.jk = other.jk;
        }
        if other.present & PRESENT_INS_ADDR != 0 {
            self.ins_addr = other.ins_addr;
        }
        if other.present & PRESENT_STMT_IDX != 0 {
            self.stmt_idx = other.stmt_idx;
        }
        self.present |= other.present;
    }
}

#[derive(Serialize, Deserialize)]
struct Payload {
    nodes: Vec<Node>,
    edges: Vec<(u32, u32, Edge)>,
    jumpkinds: Vec<String>,
}

#[pyclass(module = "angr.rustylib.cfg_graph", skip_from_py_object)]
#[derive(Clone)]
pub struct CfgGraph {
    nodes: Vec<Node>,
    by_key: FxHashMap<(u64, i64), u32>,
    by_addr: FxHashMap<u64, u32>,
    edges: FxHashMap<(u32, u32), Edge>,
    out_adj: Vec<Vec<u32>>,
    in_adj: Vec<Vec<u32>>,
    n_live: usize,
    jumpkinds: Vec<String>,
    jk_index: FxHashMap<String, u16>,
    jk_is_call: Vec<bool>,
}

impl Default for CfgGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgGraph {
    fn live(&self, idx: u32) -> PyResult<&Node> {
        match self.nodes.get(idx as usize) {
            Some(n) if n.in_graph => Ok(n),
            _ => Err(PyKeyError::new_err(format!("no node with id {idx}"))),
        }
    }

    fn intern_jk(&mut self, jk: Option<&str>) -> u16 {
        let Some(jk) = jk else { return NO_JK };
        if let Some(&i) = self.jk_index.get(jk) {
            return i;
        }
        let i = self.jumpkinds.len() as u16;
        self.jumpkinds.push(jk.to_owned());
        self.jk_index.insert(jk.to_owned(), i);
        self.jk_is_call
            .push(jk == "Ijk_Call" || jk.starts_with("Ijk_Sys"));
        i
    }

    fn edge_is_call(&self, e: &Edge) -> bool {
        e.jk != NO_JK && self.jk_is_call[e.jk as usize]
    }

    fn new_node(&mut self, addr: u64, size: i64) -> u32 {
        let idx = self.nodes.len() as u32;
        self.nodes.push(Node {
            addr,
            size,
            in_graph: true,
            call_dst: false,
            next_at_addr: NIL,
        });
        self.out_adj.push(Vec::new());
        self.in_adj.push(Vec::new());
        self.by_key.insert((addr, size), idx);
        self.link_addr(idx);
        self.n_live += 1;
        idx
    }

    fn link_addr(&mut self, idx: u32) {
        let addr = self.nodes[idx as usize].addr;
        match self.by_addr.get(&addr).copied() {
            None => {
                self.by_addr.insert(addr, idx);
            }
            Some(head) => {
                let mut cur = head;
                while self.nodes[cur as usize].next_at_addr != NIL {
                    cur = self.nodes[cur as usize].next_at_addr;
                }
                self.nodes[cur as usize].next_at_addr = idx;
            }
        }
    }

    fn unlink_addr(&mut self, idx: u32) {
        let addr = self.nodes[idx as usize].addr;
        let next = self.nodes[idx as usize].next_at_addr;
        let Some(&head) = self.by_addr.get(&addr) else {
            return;
        };
        if head == idx {
            if next == NIL {
                self.by_addr.remove(&addr);
            } else {
                self.by_addr.insert(addr, next);
            }
        } else {
            let mut cur = head;
            while cur != NIL && self.nodes[cur as usize].next_at_addr != idx {
                cur = self.nodes[cur as usize].next_at_addr;
            }
            if cur != NIL {
                self.nodes[cur as usize].next_at_addr = next;
            }
        }
        self.nodes[idx as usize].next_at_addr = NIL;
    }

    fn ids_at(&self, addr: u64) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = self.by_addr.get(&addr).copied().unwrap_or(NIL);
        while cur != NIL {
            out.push(cur);
            cur = self.nodes[cur as usize].next_at_addr;
        }
        out
    }

    fn insert_edge(&mut self, src: u32, dst: u32, edge: Edge) -> bool {
        let is_call = self.edge_is_call(&edge) && edge.present & PRESENT_JUMPKIND != 0;
        if is_call {
            self.nodes[dst as usize].call_dst = true;
        }
        if let Some(existing) = self.edges.get_mut(&(src, dst)) {
            existing.merge(&edge);
            return false;
        }
        self.edges.insert((src, dst), edge);
        self.out_adj[src as usize].push(dst);
        self.in_adj[dst as usize].push(src);
        true
    }

    /// Clear `dst`'s sticky flag if no call edge other than `(skip, dst)` remains.
    fn recheck_call_dst(&mut self, dst: u32, skip: u32) {
        if !self.nodes[dst as usize].call_dst {
            return;
        }
        let other = self.in_adj[dst as usize]
            .iter()
            .any(|&p| p != skip && self.edge_is_call(&self.edges[&(p, dst)]));
        if !other {
            self.nodes[dst as usize].call_dst = false;
        }
    }

    fn delete_edge(&mut self, src: u32, dst: u32) -> bool {
        let Some(edge) = self.edges.get(&(src, dst)).copied() else {
            return false;
        };
        if self.edge_is_call(&edge) {
            self.recheck_call_dst(dst, src);
        }
        self.edges.remove(&(src, dst));
        self.out_adj[src as usize].retain(|&d| d != dst);
        self.in_adj[dst as usize].retain(|&s| s != src);
        true
    }

    fn detach_node(&mut self, idx: u32) {
        let node = self.nodes[idx as usize];
        self.nodes[idx as usize].call_dst = false;
        for dst in std::mem::take(&mut self.out_adj[idx as usize]) {
            let edge = self.edges.remove(&(idx, dst)).unwrap();
            self.in_adj[dst as usize].retain(|&s| s != idx);
            if self.edge_is_call(&edge) {
                self.recheck_call_dst(dst, idx);
            }
        }
        for src in std::mem::take(&mut self.in_adj[idx as usize]) {
            self.edges.remove(&(src, idx));
            self.out_adj[src as usize].retain(|&d| d != idx);
        }
        self.nodes[idx as usize].in_graph = false;
        self.by_key.remove(&(node.addr, node.size));
        self.unlink_addr(idx);
        self.n_live -= 1;
    }

    fn live_nodes(&self) -> impl Iterator<Item = u32> + '_ {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.in_graph)
            .map(|(i, _)| i as u32)
    }

    fn edge_pairs(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.live_nodes()
            .flat_map(move |u| self.out_adj[u as usize].iter().map(move |&v| (u, v)))
    }

    fn edge_dict<'py>(&self, py: Python<'py>, e: &Edge) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        if e.present & PRESENT_JUMPKIND != 0 {
            if e.jk == NO_JK {
                d.set_item(intern!(py, "jumpkind"), py.None())?;
            } else {
                d.set_item(
                    intern!(py, "jumpkind"),
                    self.jumpkinds[e.jk as usize].as_str(),
                )?;
            }
        }
        if e.present & PRESENT_INS_ADDR != 0 {
            d.set_item(
                intern!(py, "ins_addr"),
                (e.ins_addr != NO_INS_ADDR).then_some(e.ins_addr),
            )?;
        }
        if e.present & PRESENT_STMT_IDX != 0 {
            d.set_item(
                intern!(py, "stmt_idx"),
                (e.stmt_idx != NO_STMT_IDX).then_some(e.stmt_idx),
            )?;
        }
        Ok(d)
    }

    fn to_payload(&self) -> Payload {
        Payload {
            nodes: self.nodes.clone(),
            edges: self
                .edge_pairs()
                .map(|(u, v)| (u, v, self.edges[&(u, v)]))
                .collect(),
            jumpkinds: self.jumpkinds.clone(),
        }
    }

    fn from_payload(p: Payload) -> PyResult<Self> {
        let n = p.nodes.len();
        let check = |idx: u32| -> PyResult<u32> {
            if (idx as usize) < n && p.nodes[idx as usize].in_graph {
                Ok(idx)
            } else {
                Err(PyValueError::new_err(
                    "corrupt CfgGraph payload: edge endpoint is not a live node",
                ))
            }
        };
        let mut g = CfgGraph::new();
        for jk in &p.jumpkinds {
            g.intern_jk(Some(jk));
        }
        g.out_adj = vec![Vec::new(); n];
        g.in_adj = vec![Vec::new(); n];
        for (i, node) in p.nodes.iter().enumerate() {
            let mut node = *node;
            node.next_at_addr = NIL;
            g.nodes.push(node);
            if node.in_graph {
                g.by_key.insert((node.addr, node.size), i as u32);
                g.link_addr(i as u32);
                g.n_live += 1;
            }
        }
        for (src, dst, edge) in p.edges {
            check(src)?;
            check(dst)?;
            if edge.jk != NO_JK && edge.jk as usize >= g.jumpkinds.len() {
                return Err(PyValueError::new_err(
                    "corrupt CfgGraph payload: jumpkind index out of range",
                ));
            }
            g.edges.insert((src, dst), edge);
            g.out_adj[src as usize].push(dst);
            g.in_adj[dst as usize].push(src);
        }
        Ok(g)
    }

    fn decode(data: &[u8]) -> PyResult<Self> {
        match data.split_first() {
            Some((&FORMAT_VERSION, rest)) => {
                let payload: Payload = postcard::from_bytes(rest)
                    .map_err(|e| PyValueError::new_err(format!("CfgGraph.from_bytes: {e}")))?;
                Self::from_payload(payload)
            }
            Some((v, _)) => Err(PyValueError::new_err(format!(
                "unsupported CfgGraph blob format version {v}; only version {FORMAT_VERSION} is readable"
            ))),
            None => Err(PyValueError::new_err("empty CfgGraph payload")),
        }
    }
}

#[pymethods]
impl CfgGraph {
    #[new]
    pub fn new() -> Self {
        CfgGraph {
            nodes: Vec::new(),
            by_key: FxHashMap::default(),
            by_addr: FxHashMap::default(),
            edges: FxHashMap::default(),
            out_adj: Vec::new(),
            in_adj: Vec::new(),
            n_live: 0,
            jumpkinds: Vec::new(),
            jk_index: FxHashMap::default(),
            jk_is_call: Vec::new(),
        }
    }

    pub fn copy(&self) -> Self {
        self.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "<CfgGraph: {} nodes, {} edges>",
            self.n_live,
            self.edges.len()
        )
    }

    pub fn clear(&mut self) {
        *self = CfgGraph::new();
    }

    // --- nodes ---------------------------------------------------------------------------------

    pub fn number_of_nodes(&self) -> usize {
        self.n_live
    }

    pub fn number_of_edges(&self) -> usize {
        self.edges.len()
    }

    /// Insert `(addr, size)` (networkx `add_node`). Returns `(id, created)`.
    pub fn add_node(&mut self, addr: u64, size: i64) -> (u32, bool) {
        match self.by_key.get(&(addr, size)) {
            Some(&idx) => (idx, false),
            None => (self.new_node(addr, size), true),
        }
    }

    pub fn find_node(&self, addr: u64, size: i64) -> Option<u32> {
        self.by_key.get(&(addr, size)).copied()
    }

    pub fn contains_node(&self, idx: u32) -> bool {
        self.nodes
            .get(idx as usize)
            .map(|n| n.in_graph)
            .unwrap_or(false)
    }

    /// `(addr, size)` of a live node id.
    pub fn node_key(&self, idx: u32) -> PyResult<(u64, i64)> {
        let n = self.live(idx)?;
        Ok((n.addr, n.size))
    }

    pub fn node_addr(&self, idx: u32) -> PyResult<u64> {
        Ok(self.live(idx)?.addr)
    }

    /// Live node ids in insertion order.
    pub fn nodes(&self) -> Vec<u32> {
        self.live_nodes().collect()
    }

    /// `(addr, size)` keys of live nodes in insertion order.
    pub fn node_keys(&self) -> Vec<(u64, i64)> {
        self.nodes
            .iter()
            .filter(|n| n.in_graph)
            .map(|n| (n.addr, n.size))
            .collect()
    }

    /// Remove a node and its edges. Returns False if the id is not a live node.
    pub fn remove_node(&mut self, idx: u32) -> bool {
        if !self.contains_node(idx) {
            return false;
        }
        self.detach_node(idx);
        true
    }

    pub fn nodes_at_addr(&self, addr: u64) -> Vec<u32> {
        self.ids_at(addr)
    }

    pub fn first_node_at_addr(&self, addr: u64) -> Option<u32> {
        self.by_addr.get(&addr).copied()
    }

    pub fn has_addr(&self, addr: u64) -> bool {
        self.by_addr.contains_key(&addr)
    }

    /// Distinct addresses of live nodes.
    pub fn addrs(&self) -> Vec<u64> {
        self.by_addr.keys().copied().collect()
    }

    // --- edges ---------------------------------------------------------------------------------

    /// networkx `add_edge`: attributes whose `present` bit is set overwrite, the others are kept.
    /// Both endpoints must be live nodes. Returns True if the edge is new.
    #[pyo3(signature = (src, dst, present=0, jumpkind=None, ins_addr=None, stmt_idx=None))]
    pub fn add_edge(
        &mut self,
        src: u32,
        dst: u32,
        present: u8,
        jumpkind: Option<&str>,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
    ) -> PyResult<bool> {
        self.live(src)?;
        self.live(dst)?;
        let jk = self.intern_jk(jumpkind);
        Ok(self.insert_edge(
            src,
            dst,
            Edge {
                jk,
                present,
                ins_addr: ins_addr.unwrap_or(NO_INS_ADDR),
                stmt_idx: stmt_idx.unwrap_or(NO_STMT_IDX),
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
            .map(|e| self.edge_dict(py, e))
            .transpose()
    }

    pub fn edge_jumpkind(&self, src: u32, dst: u32) -> Option<&str> {
        let e = self.edges.get(&(src, dst))?;
        if e.jk == NO_JK {
            None
        } else {
            Some(self.jumpkinds[e.jk as usize].as_str())
        }
    }

    /// `(src, dst)` pairs: nodes in insertion order, successors in insertion order.
    pub fn edges(&self) -> Vec<(u32, u32)> {
        self.edge_pairs().collect()
    }

    pub fn edges_with_data<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<(u32, u32, Bound<'py, PyDict>)>> {
        self.edge_pairs()
            .map(|(u, v)| Ok((u, v, self.edge_dict(py, &self.edges[&(u, v)])?)))
            .collect()
    }

    pub fn out_edges(&self, idx: u32) -> PyResult<Vec<(u32, u32)>> {
        self.live(idx)?;
        Ok(self.out_adj[idx as usize]
            .iter()
            .map(|&v| (idx, v))
            .collect())
    }

    pub fn in_edges(&self, idx: u32) -> PyResult<Vec<(u32, u32)>> {
        self.live(idx)?;
        Ok(self.in_adj[idx as usize]
            .iter()
            .map(|&u| (u, idx))
            .collect())
    }

    pub fn out_edges_with_data<'py>(
        &self,
        py: Python<'py>,
        idx: u32,
    ) -> PyResult<Vec<(u32, u32, Bound<'py, PyDict>)>> {
        self.live(idx)?;
        self.out_adj[idx as usize]
            .iter()
            .map(|&v| Ok((idx, v, self.edge_dict(py, &self.edges[&(idx, v)])?)))
            .collect()
    }

    pub fn in_edges_with_data<'py>(
        &self,
        py: Python<'py>,
        idx: u32,
    ) -> PyResult<Vec<(u32, u32, Bound<'py, PyDict>)>> {
        self.live(idx)?;
        self.in_adj[idx as usize]
            .iter()
            .map(|&u| Ok((u, idx, self.edge_dict(py, &self.edges[&(u, idx)])?)))
            .collect()
    }

    pub fn successors(&self, idx: u32) -> PyResult<Vec<u32>> {
        self.live(idx)?;
        Ok(self.out_adj[idx as usize].clone())
    }

    pub fn predecessors(&self, idx: u32) -> PyResult<Vec<u32>> {
        self.live(idx)?;
        Ok(self.in_adj[idx as usize].clone())
    }

    pub fn out_degree(&self, idx: u32) -> PyResult<usize> {
        self.live(idx)?;
        Ok(self.out_adj[idx as usize].len())
    }

    pub fn in_degree(&self, idx: u32) -> PyResult<usize> {
        self.live(idx)?;
        Ok(self.in_adj[idx as usize].len())
    }

    // --- call destinations ---------------------------------------------------------------------

    pub fn is_call_destination(&self, idx: u32) -> bool {
        self.nodes
            .get(idx as usize)
            .map(|n| n.in_graph && n.call_dst)
            .unwrap_or(false)
    }

    pub fn call_destinations(&self) -> Vec<u32> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, n)| n.in_graph && n.call_dst)
            .map(|(i, _)| i as u32)
            .collect()
    }

    // --- serialization -------------------------------------------------------------------------

    pub fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut out = vec![FORMAT_VERSION];
        postcard::to_io(&self.to_payload(), &mut out)
            .map_err(|e| PyValueError::new_err(format!("CfgGraph.to_bytes: {e}")))?;
        Ok(PyBytes::new(py, &out))
    }

    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, data: &[u8]) -> PyResult<Self> {
        Self::decode(data)
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

pub fn cfg_graph(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CfgGraph>()?;
    m.add("PRESENT_JUMPKIND", PRESENT_JUMPKIND)?;
    m.add("PRESENT_INS_ADDR", PRESENT_INS_ADDR)?;
    m.add("PRESENT_STMT_IDX", PRESENT_STMT_IDX)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u8 = PRESENT_JUMPKIND | PRESENT_INS_ADDR | PRESENT_STMT_IDX;

    #[test]
    fn nodes_edges_and_addr_index() {
        let mut g = CfgGraph::new();
        let (a, _) = g.add_node(0x1000, 8);
        let (b, _) = g.add_node(0x1008, 4);
        let (b2, created) = g.add_node(0x1008, 6);
        assert!(created);
        assert_eq!(g.add_node(0x1000, 8), (a, false));
        assert_eq!(g.nodes_at_addr(0x1008), vec![b, b2]);
        assert!(
            g.add_edge(a, b, ALL, Some("Ijk_Boring"), Some(0x1004), Some(3))
                .unwrap()
        );
        assert!(
            !g.add_edge(a, b, PRESENT_JUMPKIND, Some("Ijk_Call"), None, None)
                .unwrap()
        );
        let e = g.edges[&(a, b)];
        assert_eq!(g.edge_jumpkind(a, b), Some("Ijk_Call"));
        assert_eq!(e.ins_addr, 0x1004);
        assert_eq!(e.present, ALL);
        assert_eq!(g.out_degree(a).unwrap(), 1);
        assert_eq!(g.in_degree(b).unwrap(), 1);
        assert!(g.is_call_destination(b));
        assert!(g.remove_edge(a, b));
        assert!(!g.is_call_destination(b));
        assert!(!g.remove_edge(a, b));
    }

    #[test]
    fn remove_node_detaches_and_reinsert_gets_fresh_id() {
        let mut g = CfgGraph::new();
        let (a, _) = g.add_node(0x10, 2);
        let (b, _) = g.add_node(0x12, 2);
        let (c, _) = g.add_node(0x14, 2);
        g.add_edge(a, b, ALL, Some("Ijk_Call"), None, None).unwrap();
        g.add_edge(c, b, ALL, Some("Ijk_Call"), None, None).unwrap();
        assert!(g.remove_node(a));
        assert!(g.is_call_destination(b));
        assert!(g.remove_node(c));
        assert!(!g.is_call_destination(b));
        assert_eq!(g.number_of_edges(), 0);
        assert_eq!(g.nodes(), vec![b]);
        assert!(!g.has_addr(0x10));
        let (a2, created) = g.add_node(0x10, 2);
        assert!(created);
        assert_ne!(a2, a);
        assert_eq!(g.nodes(), vec![b, a2]);
        assert_eq!(g.nodes_at_addr(0x10), vec![a2]);
    }

    #[test]
    fn sticky_call_destination_survives_jumpkind_change() {
        let mut g = CfgGraph::new();
        let (a, _) = g.add_node(1, 1);
        let (b, _) = g.add_node(2, 1);
        g.add_edge(a, b, PRESENT_JUMPKIND, Some("Ijk_Sys_syscall"), None, None)
            .unwrap();
        g.add_edge(a, b, PRESENT_JUMPKIND, Some("Ijk_Boring"), None, None)
            .unwrap();
        assert!(g.is_call_destination(b));
        // master only re-checks when the removed edge is a call at removal time
        assert!(g.remove_edge(a, b));
        assert!(g.is_call_destination(b));
        assert!(g.remove_node(b));
        assert!(!g.is_call_destination(b));
    }

    #[test]
    fn payload_round_trip_keeps_ids_and_order() {
        let mut g = CfgGraph::new();
        let (a, _) = g.add_node(0x1000, 8);
        let (b, _) = g.add_node(0x1008, 4);
        let (c, _) = g.add_node(0x100c, 4);
        g.add_edge(a, c, ALL, Some("Ijk_Boring"), Some(0x1004), None)
            .unwrap();
        g.add_edge(a, b, ALL, Some("Ijk_Call"), None, Some(-2))
            .unwrap();
        g.remove_node(b);
        let bytes = postcard::to_stdvec(&g.to_payload()).unwrap();
        let back = CfgGraph::from_payload(postcard::from_bytes(&bytes).unwrap()).unwrap();
        assert_eq!(back.nodes(), vec![a, c]);
        assert_eq!(back.edges(), vec![(a, c)]);
        assert_eq!(back.edges[&(a, c)], g.edges[&(a, c)]);
        assert_eq!(back.edge_jumpkind(a, c), Some("Ijk_Boring"));
        assert_eq!(back.find_node(0x1008, 4), None);
        assert_eq!(back.nodes_at_addr(0x1000), vec![a]);
        let (b2, _) = back.clone().add_node(0x1008, 4);
        assert_eq!(b2, 3);
    }
}
