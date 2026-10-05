//! Packed, segmented storage for the whole-program CFG graph (`CFGModel.graph`).
//!
//! Exposed as `angr.rustylib.cfg_graph.CfgGraph`. Nodes are `(addr, size)` keys; the owning Python `SpillingCFG`
//! maps its block keys onto node ids. The graph is partitioned into address-window segments (`addr >> shift`);
//! a node id packs `(segment slot, local index)` into one u64. Each segment is a self-contained petgraph
//! `StableDiGraph`: an edge whose endpoints lie in two segments is stored in both, the foreign endpoint being
//! represented by a proxy node keyed by its id, so that every query needs only the node's own segment.
//!
//! Segments can be paged: with a backend attached, resident segments are kept under a byte budget (LRU), dirty
//! segments are written back as postcard blobs on eviction and reloaded on demand. Without a backend every
//! segment stays resident and the layout costs nothing beyond the slot indirection.
//!
//! Node and edge iteration order is global insertion order (nodes) x insertion order (successors), exactly what
//! networkx produced. Ids are stable while a node lives; a removed node's local index may be reused.

use petgraph::Direction::{Incoming, Outgoing};
use petgraph::graph::NodeIndex;
use petgraph::stable_graph::StableDiGraph;
use petgraph::visit::{EdgeIndexable, EdgeRef, NodeIndexable};
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString, PyType};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, TryLockError};

const FORMAT_VERSION: u8 = 2;

pub const PRESENT_JUMPKIND: u8 = 1;
pub const PRESENT_INS_ADDR: u8 = 2;
pub const PRESENT_STMT_IDX: u8 = 4;

const NO_JK: u16 = u16::MAX;
const NO_INS_ADDR: u64 = u64::MAX;
const NO_STMT_IDX: i32 = i32::MIN;
const NIL: u32 = u32::MAX;
const NIL_ID: u64 = u64::MAX;
pub const DEFAULT_WINDOW_SHIFT: u32 = 20;

// --- records -----------------------------------------------------------------------------------

/// Presence bits as a fieldless enum so that `Option<EdgeRec>` (petgraph's slot type) gets a niche.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Present {
    P0 = 0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
}

impl Present {
    const ALL: [Present; 8] = [
        Present::P0,
        Present::P1,
        Present::P2,
        Present::P3,
        Present::P4,
        Present::P5,
        Present::P6,
        Present::P7,
    ];

    fn from_bits(bits: u8) -> Present {
        Present::ALL[(bits & 7) as usize]
    }

    fn bits(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRec {
    ins_addr: u64,
    stmt_idx: i32,
    jk: u16,
    present: Present,
}

impl EdgeRec {
    /// networkx `add_edge` semantics: passed attributes overwrite, others are kept.
    fn merge(&mut self, other: &EdgeRec) {
        let o = other.present.bits();
        if o & PRESENT_JUMPKIND != 0 {
            self.jk = other.jk;
        }
        if o & PRESENT_INS_ADDR != 0 {
            self.ins_addr = other.ins_addr;
        }
        if o & PRESENT_STMT_IDX != 0 {
            self.stmt_idx = other.stmt_idx;
        }
        self.present = Present::from_bits(self.present.bits() | o);
    }

    fn has(&self, bit: u8) -> bool {
        self.present.bits() & bit != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRec {
    Live {
        addr_lo: u32,
        size: i32,
        /// Next live node with the same address (intrusive list headed by `Segment::by_addr`).
        next_at_addr: u32,
        /// Index into `Store::order`.
        seq: u32,
        /// Sticky call-destination flag (see `SpillingCFG.call_destination_keys`).
        call_dst: bool,
    },
    /// Stand-in for a node of another segment that an edge of this segment touches.
    Proxy { slot: u32, local: u32 },
}

const _: () = assert!(std::mem::size_of::<Option<EdgeRec>>() == 16);
const _: () = assert!(std::mem::size_of::<Option<NodeRec>>() <= 20);

#[inline]
fn node_id(slot: u32, local: u32) -> u64 {
    ((slot as u64) << 32) | local as u64
}

#[inline]
fn split_id(id: u64) -> (u32, u32) {
    ((id >> 32) as u32, id as u32)
}

#[inline]
fn nx(local: u32) -> NodeIndex<u32> {
    NodeIndex::new(local as usize)
}

// --- errors ------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum StoreError {
    NotLive(u64),
    Backend(String),
    Corrupt(String),
    Range(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotLive(id) => write!(f, "no node with id {id}"),
            StoreError::Backend(s) => write!(f, "CFG segment backend: {s}"),
            StoreError::Corrupt(s) => write!(f, "corrupt CfgGraph payload: {s}"),
            StoreError::Range(s) => write!(f, "{s}"),
        }
    }
}

impl From<StoreError> for PyErr {
    fn from(e: StoreError) -> PyErr {
        match e {
            StoreError::NotLive(_) => PyKeyError::new_err(e.to_string()),
            _ => PyValueError::new_err(e.to_string()),
        }
    }
}

type SResult<T> = Result<T, StoreError>;

// --- backends ----------------------------------------------------------------------------------

/// Where evicted segment blobs go. Keys are window numbers (`addr >> shift`).
pub trait SegmentBackend: Send + Sync {
    fn get(&mut self, window: u64) -> SResult<Option<Vec<u8>>>;
    fn put(&mut self, window: u64, data: &[u8]) -> SResult<()>;
    fn delete(&mut self, window: u64) -> SResult<()>;
    fn delete_all(&mut self) -> SResult<()>;
}

#[derive(Default)]
pub struct MemoryBackend {
    blobs: FxHashMap<u64, Vec<u8>>,
}

impl MemoryBackend {
    pub fn len(&self) -> usize {
        self.blobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.blobs.is_empty()
    }
}

impl SegmentBackend for MemoryBackend {
    fn get(&mut self, window: u64) -> SResult<Option<Vec<u8>>> {
        Ok(self.blobs.get(&window).cloned())
    }

    fn put(&mut self, window: u64, data: &[u8]) -> SResult<()> {
        self.blobs.insert(window, data.to_vec());
        Ok(())
    }

    fn delete(&mut self, window: u64) -> SResult<()> {
        self.blobs.remove(&window);
        Ok(())
    }

    fn delete_all(&mut self) -> SResult<()> {
        self.blobs.clear();
        Ok(())
    }
}

/// A Python object with `get(window) -> bytes | None`, `put(window, bytes)`, `delete(window)`, `delete_all()`.
struct PyBackend {
    obj: Py<PyAny>,
}

fn py_backend_err(e: PyErr) -> StoreError {
    StoreError::Backend(e.to_string())
}

impl SegmentBackend for PyBackend {
    fn get(&mut self, window: u64) -> SResult<Option<Vec<u8>>> {
        Python::attach(|py| {
            let r = self
                .obj
                .bind(py)
                .call_method1(intern!(py, "get"), (window,))
                .map_err(py_backend_err)?;
            if r.is_none() {
                return Ok(None);
            }
            let b = r.cast::<PyBytes>().map_err(|e| py_backend_err(e.into()))?;
            Ok(Some(b.as_bytes().to_vec()))
        })
    }

    fn put(&mut self, window: u64, data: &[u8]) -> SResult<()> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1(intern!(py, "put"), (window, PyBytes::new(py, data)))
                .map_err(py_backend_err)?;
            Ok(())
        })
    }

    fn delete(&mut self, window: u64) -> SResult<()> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method1(intern!(py, "delete"), (window,))
                .map_err(py_backend_err)?;
            Ok(())
        })
    }

    fn delete_all(&mut self) -> SResult<()> {
        Python::attach(|py| {
            self.obj
                .bind(py)
                .call_method0(intern!(py, "delete_all"))
                .map_err(py_backend_err)?;
            Ok(())
        })
    }
}

// --- segments ----------------------------------------------------------------------------------

#[derive(Clone, Default)]
struct Segment {
    g: StableDiGraph<NodeRec, EdgeRec, u32>,
    /// addr_lo -> first live node at that address (chained through `NodeRec::Live::next_at_addr`).
    by_addr: FxHashMap<u32, u32>,
    /// Foreign node id -> proxy local index.
    proxy_of: FxHashMap<u64, u32>,
    dirty: bool,
    last_used: u64,
    /// Cached `estimate_bytes()`; `Store::resident_bytes` is the sum over resident segments.
    bytes: usize,
}

#[derive(Serialize, Deserialize)]
struct SegPayload {
    /// Node records in local-index order; `None` keeps a vacant slot so that ids stay stable.
    nodes: Vec<Option<NodeRec>>,
    /// `(src local, dst local, record)` in per-source insertion order.
    edges: Vec<(u32, u32, EdgeRec)>,
}

impl Segment {
    fn estimate_bytes(&self) -> usize {
        let (nc, ec) = self.g.capacity();
        nc * 28 + ec * 32 + self.by_addr.capacity() * 12 + self.proxy_of.capacity() * 16
    }

    fn live(&self, local: u32) -> Option<&NodeRec> {
        match self.g.node_weight(nx(local)) {
            Some(n @ NodeRec::Live { .. }) => Some(n),
            _ => None,
        }
    }

    fn is_live(&self, local: u32) -> bool {
        self.live(local).is_some()
    }

    fn live_fields(&self, local: u32) -> (u32, i32, u32, bool) {
        match self.g.node_weight(nx(local)) {
            Some(NodeRec::Live {
                addr_lo,
                size,
                seq,
                call_dst,
                ..
            }) => (*addr_lo, *size, *seq, *call_dst),
            _ => unreachable!("not a live node"),
        }
    }

    fn set_call_dst(&mut self, local: u32, value: bool) {
        if let Some(NodeRec::Live { call_dst, .. }) = self.g.node_weight_mut(nx(local)) {
            *call_dst = value;
        }
    }

    fn next_at_addr(&self, local: u32) -> u32 {
        match self.g.node_weight(nx(local)) {
            Some(NodeRec::Live { next_at_addr, .. }) => *next_at_addr,
            _ => NIL,
        }
    }

    fn set_next_at_addr(&mut self, local: u32, value: u32) {
        if let Some(NodeRec::Live { next_at_addr, .. }) = self.g.node_weight_mut(nx(local)) {
            *next_at_addr = value;
        }
    }

    fn find_local(&self, addr_lo: u32, size: i32) -> Option<u32> {
        let mut cur = self.by_addr.get(&addr_lo).copied().unwrap_or(NIL);
        while cur != NIL {
            let (_, s, _, _) = self.live_fields(cur);
            if s == size {
                return Some(cur);
            }
            cur = self.next_at_addr(cur);
        }
        None
    }

    fn locals_at(&self, addr_lo: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = self.by_addr.get(&addr_lo).copied().unwrap_or(NIL);
        while cur != NIL {
            out.push(cur);
            cur = self.next_at_addr(cur);
        }
        out
    }

    fn link_addr(&mut self, local: u32, addr_lo: u32) {
        match self.by_addr.get(&addr_lo).copied() {
            None => {
                self.by_addr.insert(addr_lo, local);
            }
            Some(head) => {
                let mut cur = head;
                while self.next_at_addr(cur) != NIL {
                    cur = self.next_at_addr(cur);
                }
                self.set_next_at_addr(cur, local);
            }
        }
    }

    fn unlink_addr(&mut self, local: u32, addr_lo: u32) {
        let next = self.next_at_addr(local);
        let Some(&head) = self.by_addr.get(&addr_lo) else {
            return;
        };
        if head == local {
            if next == NIL {
                self.by_addr.remove(&addr_lo);
            } else {
                self.by_addr.insert(addr_lo, next);
            }
        } else {
            let mut cur = head;
            while cur != NIL && self.next_at_addr(cur) != local {
                cur = self.next_at_addr(cur);
            }
            if cur != NIL {
                self.set_next_at_addr(cur, next);
            }
        }
        self.set_next_at_addr(local, NIL);
    }

    /// Local index standing for `foreign` (a node id of another segment), created on demand.
    fn proxy(&mut self, foreign: u64) -> u32 {
        if let Some(&p) = self.proxy_of.get(&foreign) {
            return p;
        }
        let (slot, local) = split_id(foreign);
        let p = self.g.add_node(NodeRec::Proxy { slot, local }).index() as u32;
        self.proxy_of.insert(foreign, p);
        p
    }

    /// Drop a proxy that no edge uses any more.
    fn gc_proxy(&mut self, p: u32) {
        if let Some(NodeRec::Proxy { slot, local }) = self.g.node_weight(nx(p)).copied()
            && self.g.neighbors_undirected(nx(p)).next().is_none()
        {
            self.g.remove_node(nx(p));
            self.proxy_of.remove(&node_id(slot, local));
        }
    }

    /// Resolve a neighbour local index to a node id, given this segment's slot.
    fn id_of_local(&self, slot: u32, local: u32) -> u64 {
        match self.g.node_weight(nx(local)) {
            Some(NodeRec::Proxy { slot: s, local: l }) => node_id(*s, *l),
            _ => node_id(slot, local),
        }
    }

    /// Successor locals in insertion order (petgraph lists are newest-first).
    fn out_locals(&self, local: u32) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .g
            .edges_directed(nx(local), Outgoing)
            .map(|e| e.target().index() as u32)
            .collect();
        v.reverse();
        v
    }

    fn in_locals(&self, local: u32) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .g
            .edges_directed(nx(local), Incoming)
            .map(|e| e.source().index() as u32)
            .collect();
        v.reverse();
        v
    }

    fn out_with_rec(&self, local: u32) -> Vec<(u32, EdgeRec)> {
        let mut v: Vec<(u32, EdgeRec)> = self
            .g
            .edges_directed(nx(local), Outgoing)
            .map(|e| (e.target().index() as u32, *e.weight()))
            .collect();
        v.reverse();
        v
    }

    fn in_with_rec(&self, local: u32) -> Vec<(u32, EdgeRec)> {
        let mut v: Vec<(u32, EdgeRec)> = self
            .g
            .edges_directed(nx(local), Incoming)
            .map(|e| (e.source().index() as u32, *e.weight()))
            .collect();
        v.reverse();
        v
    }

    fn rec(&self, src: u32, dst: u32) -> Option<EdgeRec> {
        self.g.find_edge(nx(src), nx(dst)).map(|e| self.g[e])
    }

    /// Insert or merge. Returns true if the edge is new.
    fn put_edge(&mut self, src: u32, dst: u32, rec: EdgeRec) -> bool {
        match self.g.find_edge(nx(src), nx(dst)) {
            Some(e) => {
                self.g[e].merge(&rec);
                false
            }
            None => {
                self.g.add_edge(nx(src), nx(dst), rec);
                true
            }
        }
    }

    fn del_edge(&mut self, src: u32, dst: u32) -> Option<EdgeRec> {
        let e = self.g.find_edge(nx(src), nx(dst))?;
        self.g.remove_edge(e)
    }

    /// Edges in an order that reproduces every node's out-list AND in-list when replayed: a topological
    /// merge of the per-node insertion orders (petgraph lists are newest-first).
    fn edges_in_replay_order(&self) -> Vec<(u32, u32, EdgeRec)> {
        let eb = self.g.edge_bound();
        let mut succ: Vec<[u32; 2]> = vec![[NIL; 2]; eb];
        let mut indeg: Vec<u8> = vec![0; eb];
        for n in self.g.node_indices() {
            for dir in [Outgoing, Incoming] {
                // newest-first: each edge must be replayed before the one listed previously
                let mut prev = NIL;
                for e in self.g.edges_directed(n, dir) {
                    let cur = e.id().index() as u32;
                    if prev != NIL {
                        succ[cur as usize][dir.index()] = prev;
                        indeg[prev as usize] += 1;
                    }
                    prev = cur;
                }
            }
        }
        let mut ready: Vec<u32> = (0..eb as u32)
            .filter(|&e| {
                self.g
                    .edge_weight(petgraph::graph::EdgeIndex::new(e as usize))
                    .is_some()
            })
            .filter(|&e| indeg[e as usize] == 0)
            .collect();
        ready.reverse();
        let mut out = Vec::with_capacity(self.g.edge_count());
        while let Some(e) = ready.pop() {
            let ei = petgraph::graph::EdgeIndex::new(e as usize);
            let (s, d) = self.g.edge_endpoints(ei).expect("live edge");
            out.push((s.index() as u32, d.index() as u32, self.g[ei]));
            for &nxt in succ[e as usize].iter().rev() {
                if nxt != NIL {
                    indeg[nxt as usize] -= 1;
                    if indeg[nxt as usize] == 0 {
                        ready.push(nxt);
                    }
                }
            }
        }
        debug_assert_eq!(out.len(), self.g.edge_count());
        out
    }

    fn to_payload(&self) -> SegPayload {
        let n = self.g.node_bound();
        let nodes = (0..n)
            .map(|i| self.g.node_weight(nx(i as u32)).copied())
            .collect();
        SegPayload {
            nodes,
            edges: self.edges_in_replay_order(),
        }
    }

    fn from_payload(p: SegPayload) -> SResult<Segment> {
        let mut seg = Segment {
            g: StableDiGraph::with_capacity(p.nodes.len(), p.edges.len()),
            ..Segment::default()
        };
        let mut vacant = Vec::new();
        // per-address chains are kept verbatim (`next_at_addr`); a head is a live node nothing points to
        let mut pointed: Vec<bool> = vec![false; p.nodes.len()];
        for (i, rec) in p.nodes.into_iter().enumerate() {
            match rec {
                Some(rec) => {
                    let idx = seg.g.add_node(rec).index() as u32;
                    match rec {
                        NodeRec::Live { next_at_addr, .. } => {
                            if next_at_addr != NIL {
                                match pointed.get_mut(next_at_addr as usize) {
                                    Some(p) => *p = true,
                                    None => {
                                        return Err(StoreError::Corrupt(
                                            "address chain out of range".into(),
                                        ));
                                    }
                                }
                            }
                        }
                        NodeRec::Proxy { slot, local } => {
                            seg.proxy_of.insert(node_id(slot, local), idx);
                        }
                    }
                }
                None => vacant.push(seg.g.add_node(NodeRec::Proxy {
                    slot: NIL,
                    local: NIL,
                })),
            }
            debug_assert_eq!(seg.g.node_bound(), i + 1);
        }
        for (i, &is_pointed) in pointed.iter().enumerate() {
            if let Some(NodeRec::Live { addr_lo, .. }) = seg.g.node_weight(nx(i as u32))
                && !is_pointed
            {
                seg.by_addr.insert(*addr_lo, i as u32);
            }
        }
        for (src, dst, rec) in p.edges {
            if seg.g.node_weight(nx(src)).is_none() || seg.g.node_weight(nx(dst)).is_none() {
                return Err(StoreError::Corrupt("edge endpoint is not a node".into()));
            }
            seg.g.add_edge(nx(src), nx(dst), rec);
        }
        for v in vacant.into_iter().rev() {
            seg.g.remove_node(v);
        }
        seg.bytes = seg.estimate_bytes();
        Ok(seg)
    }

    fn encode(&self) -> SResult<Vec<u8>> {
        postcard::to_stdvec(&self.to_payload()).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    fn decode(data: &[u8]) -> SResult<Segment> {
        let p: SegPayload =
            postcard::from_bytes(data).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Segment::from_payload(p)
    }
}

enum Slot {
    Resident(Segment),
    /// Undecoded blob not (yet) handed to a backend.
    Cold(Vec<u8>),
    /// Held by the backend.
    Evicted,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub loads: u64,
    pub evictions: u64,
    pub writebacks: u64,
}

#[derive(Serialize, Deserialize)]
struct Header {
    shift: u32,
    slot_windows: Vec<u64>,
    order: Vec<u64>,
    n_live: usize,
    n_edges: usize,
    jumpkinds: Vec<String>,
}

// --- store -------------------------------------------------------------------------------------

pub struct Store {
    shift: u32,
    windows: FxHashMap<u64, u32>,
    slot_windows: Vec<u64>,
    slots: Vec<Slot>,
    /// Node ids in insertion order; `NIL_ID` marks a removed node.
    order: Vec<u64>,
    n_live: usize,
    n_edges: usize,
    jumpkinds: Vec<String>,
    jk_index: FxHashMap<String, u16>,
    jk_is_call: Vec<bool>,
    backend: Option<Box<dyn SegmentBackend>>,
    budget: usize,
    resident_bytes: usize,
    tick: u64,
    stats: Stats,
}

impl Store {
    pub fn new(shift: u32) -> Store {
        Store {
            shift,
            windows: FxHashMap::default(),
            slot_windows: Vec::new(),
            slots: Vec::new(),
            order: Vec::new(),
            n_live: 0,
            n_edges: 0,
            jumpkinds: Vec::new(),
            jk_index: FxHashMap::default(),
            jk_is_call: Vec::new(),
            backend: None,
            budget: usize::MAX,
            resident_bytes: 0,
            tick: 0,
            stats: Stats::default(),
        }
    }

    pub fn shift(&self) -> u32 {
        self.shift
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn is_paged(&self) -> bool {
        self.backend.is_some()
    }

    pub fn budget(&self) -> usize {
        self.budget
    }

    pub fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }

    pub fn resident_segments(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| matches!(s, Slot::Resident(_)))
            .count()
    }

    pub fn segment_count(&self) -> usize {
        self.slots.len()
    }

    // --- jumpkinds -------------------------------------------------------------------------------

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

    fn rec_is_call(&self, e: &EdgeRec) -> bool {
        e.jk != NO_JK && self.jk_is_call[e.jk as usize]
    }

    pub fn jumpkind_str(&self, jk: u16) -> Option<&str> {
        (jk != NO_JK).then(|| self.jumpkinds[jk as usize].as_str())
    }

    // --- residency -------------------------------------------------------------------------------

    fn slot_for(&mut self, window: u64) -> u32 {
        if let Some(&s) = self.windows.get(&window) {
            return s;
        }
        let s = self.slots.len() as u32;
        self.windows.insert(window, s);
        self.slot_windows.push(window);
        let seg = Segment {
            last_used: self.tick,
            ..Segment::default()
        };
        self.resident_bytes += seg.bytes;
        self.slots.push(Slot::Resident(seg));
        s
    }

    fn base(&self, slot: u32) -> u64 {
        self.slot_windows[slot as usize] << self.shift
    }

    fn split_addr(&self, addr: u64) -> (u64, u32) {
        (
            addr >> self.shift,
            (addr & ((1u64 << self.shift) - 1)) as u32,
        )
    }

    fn seg(&self, slot: u32) -> &Segment {
        match &self.slots[slot as usize] {
            Slot::Resident(s) => s,
            _ => panic!("segment {slot} is not resident"),
        }
    }

    fn seg_mut(&mut self, slot: u32) -> &mut Segment {
        match &mut self.slots[slot as usize] {
            Slot::Resident(s) => {
                s.dirty = true;
                s
            }
            _ => panic!("segment {slot} is not resident"),
        }
    }

    fn load(&mut self, slot: u32) -> SResult<()> {
        let data = match &mut self.slots[slot as usize] {
            Slot::Resident(_) => return Ok(()),
            Slot::Cold(data) => std::mem::take(data),
            Slot::Evicted => {
                let window = self.slot_windows[slot as usize];
                let backend = self.backend.as_mut().ok_or_else(|| {
                    StoreError::Backend("segment evicted without a backend".into())
                })?;
                backend
                    .get(window)?
                    .ok_or_else(|| StoreError::Backend(format!("segment {window:#x} missing")))?
            }
        };
        let mut seg = Segment::decode(&data)?;
        seg.last_used = self.tick;
        self.resident_bytes += seg.bytes;
        self.stats.loads += 1;
        self.slots[slot as usize] = Slot::Resident(seg);
        Ok(())
    }

    /// Make `pins` resident (touching them) and bring the resident set under budget without evicting a pin.
    fn ensure(&mut self, pins: &[u32]) -> SResult<()> {
        self.tick += 1;
        for &p in pins {
            self.load(p)?;
            if let Slot::Resident(s) = &mut self.slots[p as usize] {
                s.last_used = self.tick;
            }
        }
        if self.resident_bytes > self.budget {
            self.evict_beyond_budget(pins)?;
        }
        Ok(())
    }

    /// Refresh the byte estimate of mutated segments, then enforce the budget.
    fn finish(&mut self, touched: &[u32]) -> SResult<()> {
        for &t in touched {
            if let Slot::Resident(s) = &mut self.slots[t as usize] {
                let new = s.estimate_bytes();
                self.resident_bytes = self.resident_bytes + new - s.bytes;
                s.bytes = new;
            }
        }
        if self.resident_bytes > self.budget {
            self.evict_beyond_budget(&[])?;
        }
        Ok(())
    }

    fn evict_beyond_budget(&mut self, pins: &[u32]) -> SResult<()> {
        if self.backend.is_none() {
            return Ok(());
        }
        while self.resident_bytes > self.budget {
            let mut victim: Option<(u32, u64)> = None;
            for (i, s) in self.slots.iter().enumerate() {
                if let Slot::Resident(seg) = s
                    && !pins.contains(&(i as u32))
                    && victim.is_none_or(|(_, t)| seg.last_used < t)
                {
                    victim = Some((i as u32, seg.last_used));
                }
            }
            match victim {
                Some((v, _)) => self.evict(v)?,
                None => break,
            }
        }
        Ok(())
    }

    fn evict(&mut self, slot: u32) -> SResult<()> {
        let Slot::Resident(seg) = &self.slots[slot as usize] else {
            return Ok(());
        };
        let window = self.slot_windows[slot as usize];
        if seg.dirty {
            let data = seg.encode()?;
            self.backend
                .as_mut()
                .expect("evict without backend")
                .put(window, &data)?;
            self.stats.writebacks += 1;
        }
        self.resident_bytes -= seg.bytes;
        self.stats.evictions += 1;
        self.slots[slot as usize] = Slot::Evicted;
        Ok(())
    }

    /// Attach a backend and a byte budget; cold blobs are handed over, the resident set is brought under budget.
    pub fn attach_backend(
        &mut self,
        backend: Box<dyn SegmentBackend>,
        budget: usize,
    ) -> SResult<()> {
        self.detach_backend()?;
        self.backend = Some(backend);
        self.budget = budget;
        for i in 0..self.slots.len() {
            if let Slot::Cold(data) = &self.slots[i] {
                let window = self.slot_windows[i];
                self.backend.as_mut().unwrap().put(window, data)?;
                self.slots[i] = Slot::Evicted;
            }
        }
        self.evict_beyond_budget(&[])
    }

    /// Make everything resident again and drop the backend (deleting its blobs).
    pub fn detach_backend(&mut self) -> SResult<()> {
        if self.backend.is_none() {
            self.budget = usize::MAX;
            return Ok(());
        }
        self.budget = usize::MAX;
        for i in 0..self.slots.len() {
            self.load(i as u32)?;
            if let Slot::Resident(s) = &mut self.slots[i] {
                s.dirty = true;
            }
        }
        let mut backend = self.backend.take().unwrap();
        backend.delete_all()?;
        Ok(())
    }

    /// Write every dirty resident segment back (they stay resident).
    pub fn flush(&mut self) -> SResult<()> {
        if self.backend.is_none() {
            return Ok(());
        }
        for i in 0..self.slots.len() {
            if let Slot::Resident(seg) = &self.slots[i]
                && seg.dirty
            {
                let data = seg.encode()?;
                let window = self.slot_windows[i];
                self.backend.as_mut().unwrap().put(window, &data)?;
                self.stats.writebacks += 1;
                if let Slot::Resident(seg) = &mut self.slots[i] {
                    seg.dirty = false;
                }
            }
        }
        Ok(())
    }

    /// Rebuild every resident segment at exact capacity (drops Vec growth slack); ids are unchanged.
    pub fn compact(&mut self) -> SResult<()> {
        for i in 0..self.slots.len() {
            if let Slot::Resident(seg) = &mut self.slots[i] {
                let mut rebuilt = Segment::from_payload(seg.to_payload())?;
                rebuilt.by_addr.shrink_to_fit();
                rebuilt.proxy_of.shrink_to_fit();
                rebuilt.bytes = rebuilt.estimate_bytes();
                rebuilt.dirty = seg.dirty;
                rebuilt.last_used = seg.last_used;
                self.resident_bytes = self.resident_bytes + rebuilt.bytes - seg.bytes;
                *seg = rebuilt;
            }
        }
        Ok(())
    }

    /// Evict every resident segment (test/measurement helper).
    pub fn evict_all(&mut self) -> SResult<()> {
        if self.backend.is_none() {
            return Err(StoreError::Backend("no backend attached".into()));
        }
        for i in 0..self.slots.len() {
            self.evict(i as u32)?;
        }
        Ok(())
    }

    fn all_resident(&self) -> bool {
        self.slots.iter().all(|s| matches!(s, Slot::Resident(_)))
    }

    // --- nodes -----------------------------------------------------------------------------------

    pub fn number_of_nodes(&self) -> usize {
        self.n_live
    }

    pub fn number_of_edges(&self) -> usize {
        self.n_edges
    }

    fn check_live(&self, id: u64) -> SResult<(u32, u32)> {
        let (slot, local) = split_id(id);
        if (slot as usize) < self.slots.len() && self.seg(slot).is_live(local) {
            Ok((slot, local))
        } else {
            Err(StoreError::NotLive(id))
        }
    }

    pub fn add_node(&mut self, addr: u64, size: i64) -> SResult<(u64, bool)> {
        let size = i32::try_from(size)
            .map_err(|_| StoreError::Range(format!("node size {size} does not fit in 32 bits")))?;
        let (window, addr_lo) = self.split_addr(addr);
        let slot = self.slot_for(window);
        self.ensure(&[slot])?;
        if let Some(local) = self.seg(slot).find_local(addr_lo, size) {
            return Ok((node_id(slot, local), false));
        }
        let seq = self.order.len() as u32;
        let seg = self.seg_mut(slot);
        let local = seg
            .g
            .add_node(NodeRec::Live {
                addr_lo,
                size,
                next_at_addr: NIL,
                seq,
                call_dst: false,
            })
            .index() as u32;
        seg.link_addr(local, addr_lo);
        let id = node_id(slot, local);
        self.order.push(id);
        self.n_live += 1;
        self.finish(&[slot])?;
        Ok((id, true))
    }

    pub fn find_node(&mut self, addr: u64, size: i64) -> SResult<Option<u64>> {
        let Ok(size) = i32::try_from(size) else {
            return Ok(None);
        };
        let (window, addr_lo) = self.split_addr(addr);
        let Some(&slot) = self.windows.get(&window) else {
            return Ok(None);
        };
        self.ensure(&[slot])?;
        Ok(self
            .seg(slot)
            .find_local(addr_lo, size)
            .map(|l| node_id(slot, l)))
    }

    pub fn contains_node(&mut self, id: u64) -> SResult<bool> {
        let (slot, local) = split_id(id);
        if (slot as usize) >= self.slots.len() {
            return Ok(false);
        }
        self.ensure(&[slot])?;
        Ok(self.seg(slot).is_live(local))
    }

    pub fn node_key(&mut self, id: u64) -> SResult<(u64, i64)> {
        let (slot, local) = split_id(id);
        if (slot as usize) >= self.slots.len() {
            return Err(StoreError::NotLive(id));
        }
        self.ensure(&[slot])?;
        let seg = self.seg(slot);
        if !seg.is_live(local) {
            return Err(StoreError::NotLive(id));
        }
        let (addr_lo, size, _, _) = seg.live_fields(local);
        Ok((self.base(slot) | addr_lo as u64, size as i64))
    }

    /// Live node ids in insertion order (no segment access).
    pub fn nodes(&self) -> Vec<u64> {
        self.order
            .iter()
            .copied()
            .filter(|&id| id != NIL_ID)
            .collect()
    }

    /// `(seq, slot, local)` of every live node, segment by segment (paging-friendly), sorted into insertion order.
    fn live_by_seq(&mut self) -> SResult<Vec<(u32, u32, u32)>> {
        let mut out = Vec::with_capacity(self.n_live);
        for slot in 0..self.slots.len() as u32 {
            self.ensure(&[slot])?;
            let seg = self.seg(slot);
            for n in seg.g.node_indices() {
                if let Some(NodeRec::Live { seq, .. }) = seg.g.node_weight(n) {
                    out.push((*seq, slot, n.index() as u32));
                }
            }
        }
        out.sort_unstable();
        Ok(out)
    }

    pub fn node_keys(&mut self) -> SResult<Vec<(u64, i64)>> {
        if self.all_resident() {
            let mut out = Vec::with_capacity(self.n_live);
            for &id in &self.order {
                if id == NIL_ID {
                    continue;
                }
                let (slot, local) = split_id(id);
                let (addr_lo, size, _, _) = self.seg(slot).live_fields(local);
                out.push((self.base(slot) | addr_lo as u64, size as i64));
            }
            return Ok(out);
        }
        let mut out = Vec::with_capacity(self.n_live);
        for (_, slot, local) in self.live_by_seq()? {
            self.ensure(&[slot])?;
            let (addr_lo, size, _, _) = self.seg(slot).live_fields(local);
            out.push((self.base(slot) | addr_lo as u64, size as i64));
        }
        Ok(out)
    }

    pub fn nodes_at_addr(&mut self, addr: u64) -> SResult<Vec<u64>> {
        let (window, addr_lo) = self.split_addr(addr);
        let Some(&slot) = self.windows.get(&window) else {
            return Ok(Vec::new());
        };
        self.ensure(&[slot])?;
        Ok(self
            .seg(slot)
            .locals_at(addr_lo)
            .into_iter()
            .map(|l| node_id(slot, l))
            .collect())
    }

    pub fn first_node_at_addr(&mut self, addr: u64) -> SResult<Option<u64>> {
        let (window, addr_lo) = self.split_addr(addr);
        let Some(&slot) = self.windows.get(&window) else {
            return Ok(None);
        };
        self.ensure(&[slot])?;
        Ok(self
            .seg(slot)
            .by_addr
            .get(&addr_lo)
            .map(|&l| node_id(slot, l)))
    }

    pub fn has_addr(&mut self, addr: u64) -> SResult<bool> {
        let (window, addr_lo) = self.split_addr(addr);
        let Some(&slot) = self.windows.get(&window) else {
            return Ok(false);
        };
        self.ensure(&[slot])?;
        Ok(self.seg(slot).by_addr.contains_key(&addr_lo))
    }

    pub fn addrs(&mut self) -> SResult<Vec<u64>> {
        let mut out = Vec::new();
        for slot in 0..self.slots.len() as u32 {
            self.ensure(&[slot])?;
            let base = self.base(slot);
            out.extend(self.seg(slot).by_addr.keys().map(|&lo| base | lo as u64));
        }
        Ok(out)
    }

    pub fn remove_node(&mut self, id: u64) -> SResult<bool> {
        let (slot, local) = split_id(id);
        if (slot as usize) >= self.slots.len() {
            return Ok(false);
        }
        self.ensure(&[slot])?;
        if !self.seg(slot).is_live(local) {
            return Ok(false);
        }
        let (addr_lo, _, seq, _) = self.seg(slot).live_fields(local);

        // phase 1: this segment. Record cross-segment endpoints to mirror afterwards.
        let outs = self.seg(slot).out_with_rec(local);
        let ins = self.seg(slot).in_with_rec(local);
        let mut foreign: Vec<(u64, bool)> = Vec::new(); // (foreign id, this node called it)
        let mut local_call_dsts: Vec<u32> = Vec::new();
        let mut removed = 0usize;
        for (dst, rec) in &outs {
            removed += 1;
            let is_call = self.rec_is_call(rec);
            match self.seg(slot).g.node_weight(nx(*dst)) {
                Some(NodeRec::Proxy { slot: s, local: l }) => {
                    foreign.push((node_id(*s, *l), is_call))
                }
                _ => {
                    if is_call && *dst != local {
                        local_call_dsts.push(*dst);
                    }
                }
            }
        }
        for (src, _) in &ins {
            if *src == local {
                continue; // self loop counted once
            }
            removed += 1;
            if let Some(NodeRec::Proxy { slot: s, local: l }) =
                self.seg(slot).g.node_weight(nx(*src))
            {
                foreign.push((node_id(*s, *l), false));
            }
        }
        {
            let seg = self.seg_mut(slot);
            seg.unlink_addr(local, addr_lo);
            seg.g.remove_node(nx(local));
            let proxies: Vec<u32> = outs
                .iter()
                .map(|(d, _)| *d)
                .chain(ins.iter().map(|(s, _)| *s))
                .collect();
            for p in proxies {
                seg.gc_proxy(p);
            }
        }
        for d in local_call_dsts {
            self.recheck_call_dst(slot, d);
        }
        self.order[seq as usize] = NIL_ID;
        self.n_live -= 1;
        self.n_edges -= removed;
        self.finish(&[slot])?;

        // phase 2: mirrors in the other segments.
        foreign.sort_unstable();
        foreign.dedup_by_key(|f| f.0);
        for (fid, called) in foreign {
            let (fslot, flocal) = split_id(fid);
            self.ensure(&[fslot])?;
            let seg = self.seg_mut(fslot);
            if let Some(p) = seg.proxy_of.remove(&id) {
                seg.g.remove_node(nx(p));
            }
            if called {
                self.recheck_call_dst(fslot, flocal);
            }
            self.finish(&[fslot])?;
        }
        Ok(true)
    }

    // --- edges -----------------------------------------------------------------------------------

    /// Clear `dst`'s sticky flag if no call edge into it remains.
    fn recheck_call_dst(&mut self, slot: u32, local: u32) {
        let seg = self.seg(slot);
        let (_, _, _, call_dst) = seg.live_fields(local);
        if !call_dst {
            return;
        }
        let other = seg
            .g
            .edges_directed(nx(local), Incoming)
            .any(|e| self.rec_is_call(e.weight()));
        if !other {
            self.seg_mut(slot).set_call_dst(local, false);
        }
    }

    pub fn add_edge(
        &mut self,
        src: u64,
        dst: u64,
        present: u8,
        jumpkind: Option<&str>,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
    ) -> SResult<bool> {
        let stmt_idx = match stmt_idx {
            None => NO_STMT_IDX,
            Some(v) => i32::try_from(v)
                .map_err(|_| StoreError::Range(format!("stmt_idx {v} does not fit in 32 bits")))?,
        };
        let (a, sl) = split_id(src);
        let (b, dl) = split_id(dst);
        if (a as usize) >= self.slots.len() {
            return Err(StoreError::NotLive(src));
        }
        if (b as usize) >= self.slots.len() {
            return Err(StoreError::NotLive(dst));
        }
        self.ensure(&[a, b])?;
        if !self.seg(a).is_live(sl) {
            return Err(StoreError::NotLive(src));
        }
        if !self.seg(b).is_live(dl) {
            return Err(StoreError::NotLive(dst));
        }
        let jk = self.intern_jk(jumpkind);
        let rec = EdgeRec {
            ins_addr: ins_addr.unwrap_or(NO_INS_ADDR),
            stmt_idx,
            jk,
            present: Present::from_bits(present),
        };
        let is_call = present & PRESENT_JUMPKIND != 0 && self.rec_is_call(&rec);
        let new = if a == b {
            self.seg_mut(a).put_edge(sl, dl, rec)
        } else {
            let seg = self.seg_mut(a);
            let p = seg.proxy(dst);
            let new = seg.put_edge(sl, p, rec);
            let seg = self.seg_mut(b);
            let p = seg.proxy(src);
            seg.put_edge(p, dl, rec);
            new
        };
        if is_call {
            self.seg_mut(b).set_call_dst(dl, true);
        }
        if new {
            self.n_edges += 1;
        }
        self.finish(&[a, b])?;
        Ok(new)
    }

    /// Local index of `dst` as seen from `src`'s segment (itself, or its proxy), if any.
    fn local_in(&self, slot: u32, other: u64) -> Option<u32> {
        let (s, l) = split_id(other);
        if s == slot {
            Some(l)
        } else {
            self.seg(slot).proxy_of.get(&other).copied()
        }
    }

    pub fn has_edge(&mut self, src: u64, dst: u64) -> SResult<bool> {
        let (a, sl) = split_id(src);
        if (a as usize) >= self.slots.len() {
            return Ok(false);
        }
        self.ensure(&[a])?;
        if !self.seg(a).is_live(sl) {
            return Ok(false);
        }
        Ok(match self.local_in(a, dst) {
            Some(dl) => self.seg(a).g.find_edge(nx(sl), nx(dl)).is_some(),
            None => false,
        })
    }

    pub fn edge_rec(&mut self, src: u64, dst: u64) -> SResult<Option<EdgeRec>> {
        let (a, sl) = split_id(src);
        if (a as usize) >= self.slots.len() {
            return Ok(None);
        }
        self.ensure(&[a])?;
        if !self.seg(a).is_live(sl) {
            return Ok(None);
        }
        Ok(match self.local_in(a, dst) {
            Some(dl) => self.seg(a).rec(sl, dl),
            None => None,
        })
    }

    pub fn remove_edge(&mut self, src: u64, dst: u64) -> SResult<bool> {
        let (a, sl) = split_id(src);
        let (b, dl) = split_id(dst);
        if (a as usize) >= self.slots.len() || (b as usize) >= self.slots.len() {
            return Ok(false);
        }
        self.ensure(&[a, b])?;
        if !self.seg(a).is_live(sl) || !self.seg(b).is_live(dl) {
            return Ok(false);
        }
        let Some(dl_in_a) = self.local_in(a, dst) else {
            return Ok(false);
        };
        let Some(rec) = self.seg_mut(a).del_edge(sl, dl_in_a) else {
            return Ok(false);
        };
        if a != b {
            self.seg_mut(a).gc_proxy(dl_in_a);
            let sl_in_b = self.local_in(b, src).expect("mirror proxy missing");
            let seg = self.seg_mut(b);
            seg.del_edge(sl_in_b, dl);
            seg.gc_proxy(sl_in_b);
        }
        if self.rec_is_call(&rec) {
            self.recheck_call_dst(b, dl);
        }
        self.n_edges -= 1;
        self.finish(&[a, b])?;
        Ok(true)
    }

    pub fn successors(&mut self, id: u64) -> SResult<Vec<u64>> {
        let (slot, local) = self.check_live_loaded(id)?;
        let seg = self.seg(slot);
        Ok(seg
            .out_locals(local)
            .into_iter()
            .map(|l| seg.id_of_local(slot, l))
            .collect())
    }

    pub fn predecessors(&mut self, id: u64) -> SResult<Vec<u64>> {
        let (slot, local) = self.check_live_loaded(id)?;
        let seg = self.seg(slot);
        Ok(seg
            .in_locals(local)
            .into_iter()
            .map(|l| seg.id_of_local(slot, l))
            .collect())
    }

    pub fn out_edges_rec(&mut self, id: u64) -> SResult<Vec<(u64, EdgeRec)>> {
        let (slot, local) = self.check_live_loaded(id)?;
        let seg = self.seg(slot);
        Ok(seg
            .out_with_rec(local)
            .into_iter()
            .map(|(l, r)| (seg.id_of_local(slot, l), r))
            .collect())
    }

    pub fn in_edges_rec(&mut self, id: u64) -> SResult<Vec<(u64, EdgeRec)>> {
        let (slot, local) = self.check_live_loaded(id)?;
        let seg = self.seg(slot);
        Ok(seg
            .in_with_rec(local)
            .into_iter()
            .map(|(l, r)| (seg.id_of_local(slot, l), r))
            .collect())
    }

    pub fn out_degree(&mut self, id: u64) -> SResult<usize> {
        let (slot, local) = self.check_live_loaded(id)?;
        Ok(self.seg(slot).g.edges_directed(nx(local), Outgoing).count())
    }

    pub fn in_degree(&mut self, id: u64) -> SResult<usize> {
        let (slot, local) = self.check_live_loaded(id)?;
        Ok(self.seg(slot).g.edges_directed(nx(local), Incoming).count())
    }

    fn check_live_loaded(&mut self, id: u64) -> SResult<(u32, u32)> {
        let (slot, _) = split_id(id);
        if (slot as usize) >= self.slots.len() {
            return Err(StoreError::NotLive(id));
        }
        self.ensure(&[slot])?;
        self.check_live(id)
    }

    /// `(src, dst, rec)` for every edge: nodes in insertion order, successors in insertion order.
    pub fn edges_rec(&mut self) -> SResult<Vec<(u64, u64, EdgeRec)>> {
        let mut out = Vec::with_capacity(self.n_edges);
        if self.all_resident() {
            for &id in &self.order {
                if id == NIL_ID {
                    continue;
                }
                let (slot, local) = split_id(id);
                let seg = self.seg(slot);
                for (l, r) in seg.out_with_rec(local) {
                    out.push((id, seg.id_of_local(slot, l), r));
                }
            }
            return Ok(out);
        }
        for (_, slot, local) in self.live_by_seq()? {
            self.ensure(&[slot])?;
            let seg = self.seg(slot);
            let id = node_id(slot, local);
            for (l, r) in seg.out_with_rec(local) {
                out.push((id, seg.id_of_local(slot, l), r));
            }
        }
        Ok(out)
    }

    pub fn is_call_destination(&mut self, id: u64) -> SResult<bool> {
        let (slot, local) = split_id(id);
        if (slot as usize) >= self.slots.len() {
            return Ok(false);
        }
        self.ensure(&[slot])?;
        let seg = self.seg(slot);
        Ok(seg.is_live(local) && seg.live_fields(local).3)
    }

    pub fn call_destinations(&mut self) -> SResult<Vec<u64>> {
        let mut out: Vec<(u32, u64)> = Vec::new();
        for slot in 0..self.slots.len() as u32 {
            self.ensure(&[slot])?;
            let seg = self.seg(slot);
            for n in seg.g.node_indices() {
                if let Some(NodeRec::Live {
                    seq,
                    call_dst: true,
                    ..
                }) = seg.g.node_weight(n)
                {
                    out.push((*seq, node_id(slot, n.index() as u32)));
                }
            }
        }
        out.sort_unstable();
        Ok(out.into_iter().map(|(_, id)| id).collect())
    }

    // --- whole-store operations ------------------------------------------------------------------

    pub fn clear(&mut self) -> SResult<()> {
        if let Some(b) = self.backend.as_mut() {
            b.delete_all()?;
        }
        let shift = self.shift;
        let backend = self.backend.take();
        let budget = self.budget;
        *self = Store::new(shift);
        self.backend = backend;
        self.budget = budget;
        Ok(())
    }

    /// A fully resident copy without a backend.
    pub fn copy(&mut self) -> SResult<Store> {
        let mut slots = Vec::with_capacity(self.slots.len());
        for i in 0..self.slots.len() {
            slots.push(match &self.slots[i] {
                Slot::Resident(s) => Slot::Resident(s.clone()),
                Slot::Cold(d) => Slot::Cold(d.clone()),
                Slot::Evicted => Slot::Cold(self.blob_of(i as u32)?),
            });
        }
        Ok(Store {
            shift: self.shift,
            windows: self.windows.clone(),
            slot_windows: self.slot_windows.clone(),
            slots,
            order: self.order.clone(),
            n_live: self.n_live,
            n_edges: self.n_edges,
            jumpkinds: self.jumpkinds.clone(),
            jk_index: self.jk_index.clone(),
            jk_is_call: self.jk_is_call.clone(),
            backend: None,
            budget: usize::MAX,
            resident_bytes: 0,
            tick: 0,
            stats: Stats::default(),
        }
        .with_resident_bytes())
    }

    fn with_resident_bytes(mut self) -> Store {
        self.resident_bytes = self
            .slots
            .iter()
            .map(|s| match s {
                Slot::Resident(seg) => seg.bytes,
                _ => 0,
            })
            .sum();
        self
    }

    /// The postcard blob of one segment (encoded, cloned or fetched; never decoded).
    fn blob_of(&mut self, slot: u32) -> SResult<Vec<u8>> {
        match &self.slots[slot as usize] {
            Slot::Resident(s) => s.encode(),
            Slot::Cold(d) => Ok(d.clone()),
            Slot::Evicted => {
                let window = self.slot_windows[slot as usize];
                self.backend
                    .as_mut()
                    .expect("evicted without backend")
                    .get(window)?
                    .ok_or_else(|| StoreError::Backend(format!("segment {window:#x} missing")))
            }
        }
    }

    pub fn header_bytes(&self) -> SResult<Vec<u8>> {
        let h = Header {
            shift: self.shift,
            slot_windows: self.slot_windows.clone(),
            order: self.order.clone(),
            n_live: self.n_live,
            n_edges: self.n_edges,
            jumpkinds: self.jumpkinds.clone(),
        };
        let mut out = vec![FORMAT_VERSION];
        postcard::to_io(&h, &mut out).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(out)
    }

    pub fn segment_blobs(&mut self) -> SResult<Vec<Vec<u8>>> {
        (0..self.slots.len() as u32)
            .map(|s| self.blob_of(s))
            .collect()
    }

    /// Rebuild from a header and one blob per segment; segments stay cold until first touched.
    pub fn from_blobs(header: &[u8], blobs: Vec<Vec<u8>>) -> SResult<Store> {
        let h: Header = match header.split_first() {
            Some((&FORMAT_VERSION, rest)) => {
                postcard::from_bytes(rest).map_err(|e| StoreError::Corrupt(e.to_string()))?
            }
            Some((v, _)) => {
                return Err(StoreError::Corrupt(format!(
                    "unsupported blob format version {v}; only version {FORMAT_VERSION} is readable"
                )));
            }
            None => return Err(StoreError::Corrupt("empty header".into())),
        };
        if h.slot_windows.len() != blobs.len() {
            return Err(StoreError::Corrupt("segment count mismatch".into()));
        }
        let mut s = Store::new(h.shift);
        for jk in &h.jumpkinds {
            s.intern_jk(Some(jk));
        }
        for (i, &w) in h.slot_windows.iter().enumerate() {
            s.windows.insert(w, i as u32);
        }
        s.slot_windows = h.slot_windows;
        s.slots = blobs.into_iter().map(Slot::Cold).collect();
        s.order = h.order;
        s.n_live = h.n_live;
        s.n_edges = h.n_edges;
        Ok(s)
    }

    pub fn to_bytes(&mut self) -> SResult<Vec<u8>> {
        let blobs = self.segment_blobs()?;
        let header = self.header_bytes()?;
        postcard::to_stdvec(&(header, blobs)).map_err(|e| StoreError::Corrupt(e.to_string()))
    }

    pub fn from_bytes(data: &[u8]) -> SResult<Store> {
        let (header, blobs): (Vec<u8>, Vec<Vec<u8>>) =
            postcard::from_bytes(data).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Store::from_blobs(&header, blobs)
    }
}

// --- Python class ------------------------------------------------------------------------------

#[pyclass(module = "angr.rustylib.cfg_graph", frozen, skip_from_py_object)]
pub struct CfgGraph {
    /// Backend calls run Python (py-lmdb releases the GIL), so another thread may call in while an operation
    /// is in flight; a mutex (not pyo3's borrow checker) makes that wait instead of raising.
    inner: Mutex<Inner>,
    /// Token of the thread holding `inner` (0: none); see `lock`.
    owner: AtomicU64,
}

struct Inner {
    store: Store,
    /// Interned jumpkind strings, parallel to `Store::jumpkinds`.
    jk_py: Vec<Py<PyString>>,
}

static NEXT_THREAD_TOKEN: AtomicU64 = AtomicU64::new(1);
thread_local! {
    static THREAD_TOKEN: u64 = NEXT_THREAD_TOKEN.fetch_add(1, Ordering::Relaxed);
}

fn thread_token() -> u64 {
    THREAD_TOKEN.with(|t| *t)
}

/// A held `CfgGraph` lock; records the owning thread for re-entrancy detection.
struct Locked<'a> {
    guard: MutexGuard<'a, Inner>,
    owner: &'a AtomicU64,
}

impl<'a> Locked<'a> {
    fn new(guard: MutexGuard<'a, Inner>, owner: &'a AtomicU64, me: u64) -> Self {
        owner.store(me, Ordering::Release);
        Locked { guard, owner }
    }
}

impl Deref for Locked<'_> {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.guard
    }
}

impl DerefMut for Locked<'_> {
    fn deref_mut(&mut self) -> &mut Inner {
        &mut self.guard
    }
}

impl Drop for Locked<'_> {
    fn drop(&mut self) {
        self.owner.store(0, Ordering::Release);
    }
}

impl CfgGraph {
    fn wrap(py: Python<'_>, store: Store) -> CfgGraph {
        let jk_py = store
            .jumpkinds
            .iter()
            .map(|s| PyString::new(py, s).unbind())
            .collect();
        CfgGraph {
            inner: Mutex::new(Inner { store, jk_py }),
            owner: AtomicU64::new(0),
        }
    }

    /// Lock without holding the GIL while waiting, so a thread blocked inside a backend call can finish. The
    /// thread that holds the lock must not re-enter (e.g. from a finalizer run inside a backend call): that would
    /// spin forever, so it raises instead.
    fn lock(&self) -> PyResult<Locked<'_>> {
        let me = thread_token();
        loop {
            match self.inner.try_lock() {
                Ok(g) => return Ok(Locked::new(g, &self.owner, me)),
                Err(TryLockError::Poisoned(p)) => {
                    return Ok(Locked::new(p.into_inner(), &self.owner, me));
                }
                Err(TryLockError::WouldBlock) => {
                    if self.owner.load(Ordering::Acquire) == me {
                        return Err(PyRuntimeError::new_err(
                            "re-entrant CfgGraph access: the graph is being modified by a call on this thread",
                        ));
                    }
                    Python::attach(|py| py.detach(std::thread::yield_now));
                }
            }
        }
    }
}

impl Inner {
    fn sync_jk(&mut self, py: Python<'_>) {
        while self.jk_py.len() < self.store.jumpkinds.len() {
            let s = &self.store.jumpkinds[self.jk_py.len()];
            self.jk_py.push(PyString::new(py, s).unbind());
        }
    }

    fn budget_bytes(&self) -> Option<usize> {
        self.store.is_paged().then_some(self.store.budget())
    }

    fn blobs_out<'py>(&mut self, py: Python<'py>) -> PyResult<ReduceArgs<'py>> {
        let blobs = self.store.segment_blobs()?;
        let header = PyBytes::new(py, &self.store.header_bytes()?);
        let list = PyList::new(py, blobs.iter().map(|b| PyBytes::new(py, b)))?;
        Ok((header, list))
    }

    fn edge_dict<'py>(&self, py: Python<'py>, e: &EdgeRec) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        if e.has(PRESENT_JUMPKIND) {
            if e.jk == NO_JK {
                d.set_item(intern!(py, "jumpkind"), py.None())?;
            } else {
                d.set_item(intern!(py, "jumpkind"), self.jk_py[e.jk as usize].bind(py))?;
            }
        }
        if e.has(PRESENT_INS_ADDR) {
            d.set_item(
                intern!(py, "ins_addr"),
                (e.ins_addr != NO_INS_ADDR).then_some(e.ins_addr),
            )?;
        }
        if e.has(PRESENT_STMT_IDX) {
            d.set_item(
                intern!(py, "stmt_idx"),
                (e.stmt_idx != NO_STMT_IDX).then_some(e.stmt_idx),
            )?;
        }
        Ok(d)
    }

    /// `(jumpkind, ins_addr, stmt_idx)` with None for absent or None-valued attributes.
    fn rec_tuple<'py>(&self, py: Python<'py>, e: &EdgeRec) -> EdgeTuple<'py> {
        let jk = (e.has(PRESENT_JUMPKIND) && e.jk != NO_JK)
            .then(|| self.jk_py[e.jk as usize].bind(py).clone());
        let ins = (e.has(PRESENT_INS_ADDR) && e.ins_addr != NO_INS_ADDR).then_some(e.ins_addr);
        let si =
            (e.has(PRESENT_STMT_IDX) && e.stmt_idx != NO_STMT_IDX).then_some(e.stmt_idx as i64);
        (jk, ins, si)
    }
}

type EdgeTuple<'py> = (Option<Bound<'py, PyString>>, Option<u64>, Option<i64>);
type EdgeRow<'py> = (
    u64,
    u64,
    Option<Bound<'py, PyString>>,
    Option<u64>,
    Option<i64>,
);
type ReduceArgs<'py> = (Bound<'py, PyBytes>, Bound<'py, PyList>);

#[pymethods]
impl CfgGraph {
    #[new]
    #[pyo3(signature = (window_shift=DEFAULT_WINDOW_SHIFT))]
    pub fn new(window_shift: u32) -> PyResult<Self> {
        if !(1..=32).contains(&window_shift) {
            return Err(PyValueError::new_err("window_shift must be in 1..=32"));
        }
        Python::attach(|py| Ok(Self::wrap(py, Store::new(window_shift))))
    }

    /// A fully resident copy (no backend).
    pub fn copy(&self, py: Python<'_>) -> PyResult<Self> {
        let mut g = self.lock()?;
        Ok(Self::wrap(py, g.store.copy()?))
    }

    fn __repr__(&self) -> PyResult<String> {
        let g = self.lock()?;
        Ok(format!(
            "<CfgGraph: {} nodes, {} edges, {} segments{}>",
            g.store.n_live,
            g.store.n_edges,
            g.store.segment_count(),
            if g.store.is_paged() { ", paged" } else { "" }
        ))
    }

    pub fn clear(&self) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store.clear()?)
    }

    #[getter]
    pub fn window_shift(&self) -> PyResult<u32> {
        let g = self.lock()?;
        Ok(g.store.shift())
    }

    // --- paging ----------------------------------------------------------------------------------

    /// Attach a segment backend (`get(window) -> bytes | None`, `put(window, bytes)`, `delete(window)`,
    /// `delete_all()`) and keep resident segments under `budget_bytes`.
    pub fn attach_backend(&self, backend: Py<PyAny>, budget_bytes: usize) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store
            .attach_backend(Box::new(PyBackend { obj: backend }), budget_bytes)?)
    }

    /// Attach an in-process backend (tests).
    pub fn attach_memory_backend(&self, budget_bytes: usize) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store
            .attach_backend(Box::new(MemoryBackend::default()), budget_bytes)?)
    }

    /// Load everything back and drop the backend.
    pub fn detach_backend(&self) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store.detach_backend()?)
    }

    #[getter]
    pub fn paged(&self) -> PyResult<bool> {
        let g = self.lock()?;
        Ok(g.store.is_paged())
    }

    #[getter]
    pub fn budget_bytes(&self) -> PyResult<Option<usize>> {
        let g = self.lock()?;
        Ok(g.store.is_paged().then_some(g.store.budget()))
    }

    #[setter]
    pub fn set_budget_bytes(&self, value: usize) -> PyResult<()> {
        let mut g = self.lock()?;
        if !g.store.is_paged() {
            return Err(PyValueError::new_err("no backend attached"));
        }
        g.store.budget = value;
        Ok(g.store.evict_beyond_budget(&[])?)
    }

    pub fn flush(&self) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store.flush()?)
    }

    pub fn evict_all(&self) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store.evict_all()?)
    }

    /// Drop allocation slack in every resident segment (call once a graph stops changing).
    pub fn compact(&self) -> PyResult<()> {
        let mut g = self.lock()?;
        Ok(g.store.compact()?)
    }

    pub fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let g = self.lock()?;
        let d = PyDict::new(py);
        let s = g.store.stats();
        d.set_item("loads", s.loads)?;
        d.set_item("evictions", s.evictions)?;
        d.set_item("writebacks", s.writebacks)?;
        d.set_item("segments", g.store.segment_count())?;
        d.set_item("resident_segments", g.store.resident_segments())?;
        d.set_item("resident_bytes", g.store.resident_bytes())?;
        d.set_item("paged", g.store.is_paged())?;
        d.set_item("budget_bytes", g.budget_bytes())?;
        Ok(d)
    }

    // --- nodes -----------------------------------------------------------------------------------

    pub fn number_of_nodes(&self) -> PyResult<usize> {
        let g = self.lock()?;
        Ok(g.store.number_of_nodes())
    }

    pub fn number_of_edges(&self) -> PyResult<usize> {
        let g = self.lock()?;
        Ok(g.store.number_of_edges())
    }

    /// Insert `(addr, size)` (networkx `add_node`). Returns `(id, created)`.
    pub fn add_node(&self, addr: u64, size: i64) -> PyResult<(u64, bool)> {
        let mut g = self.lock()?;
        Ok(g.store.add_node(addr, size)?)
    }

    pub fn find_node(&self, addr: u64, size: i64) -> PyResult<Option<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.find_node(addr, size)?)
    }

    pub fn contains_node(&self, idx: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.contains_node(idx)?)
    }

    /// `(addr, size)` of a live node id.
    pub fn node_key(&self, idx: u64) -> PyResult<(u64, i64)> {
        let mut g = self.lock()?;
        Ok(g.store.node_key(idx)?)
    }

    pub fn node_addr(&self, idx: u64) -> PyResult<u64> {
        let mut g = self.lock()?;
        Ok(g.store.node_key(idx)?.0)
    }

    /// Live node ids in insertion order.
    pub fn nodes(&self) -> PyResult<Vec<u64>> {
        let g = self.lock()?;
        Ok(g.store.nodes())
    }

    /// `(addr, size)` keys of live nodes in insertion order.
    pub fn node_keys(&self) -> PyResult<Vec<(u64, i64)>> {
        let mut g = self.lock()?;
        Ok(g.store.node_keys()?)
    }

    /// Remove a node and its edges. Returns False if the id is not a live node.
    pub fn remove_node(&self, idx: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.remove_node(idx)?)
    }

    pub fn nodes_at_addr(&self, addr: u64) -> PyResult<Vec<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.nodes_at_addr(addr)?)
    }

    pub fn first_node_at_addr(&self, addr: u64) -> PyResult<Option<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.first_node_at_addr(addr)?)
    }

    pub fn has_addr(&self, addr: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.has_addr(addr)?)
    }

    /// Distinct addresses of live nodes.
    pub fn addrs(&self) -> PyResult<Vec<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.addrs()?)
    }

    // --- edges -----------------------------------------------------------------------------------

    /// networkx `add_edge`: attributes whose `present` bit is set overwrite, the others are kept.
    /// Both endpoints must be live nodes. Returns True if the edge is new.
    #[pyo3(signature = (src, dst, present=0, jumpkind=None, ins_addr=None, stmt_idx=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn add_edge(
        &self,
        py: Python<'_>,
        src: u64,
        dst: u64,
        present: u8,
        jumpkind: Option<&str>,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
    ) -> PyResult<bool> {
        let mut g = self.lock()?;
        let r = g
            .store
            .add_edge(src, dst, present, jumpkind, ins_addr, stmt_idx)?;
        if g.jk_py.len() < g.store.jumpkinds.len() {
            g.sync_jk(py);
        }
        Ok(r)
    }

    pub fn remove_edge(&self, src: u64, dst: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.remove_edge(src, dst)?)
    }

    pub fn has_edge(&self, src: u64, dst: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.has_edge(src, dst)?)
    }

    /// The edge-data dict of an edge, or None.
    pub fn edge_data<'py>(
        &self,
        py: Python<'py>,
        src: u64,
        dst: u64,
    ) -> PyResult<Option<Bound<'py, PyDict>>> {
        let mut g = self.lock()?;
        match g.store.edge_rec(src, dst)? {
            Some(e) => Ok(Some(g.edge_dict(py, &e)?)),
            None => Ok(None),
        }
    }

    /// `(jumpkind, ins_addr, stmt_idx)` of an edge (None for absent attributes), or None.
    pub fn edge_tuple<'py>(
        &self,
        py: Python<'py>,
        src: u64,
        dst: u64,
    ) -> PyResult<Option<EdgeTuple<'py>>> {
        let mut g = self.lock()?;
        Ok(g.store.edge_rec(src, dst)?.map(|e| g.rec_tuple(py, &e)))
    }

    pub fn edge_jumpkind<'py>(
        &self,
        py: Python<'py>,
        src: u64,
        dst: u64,
    ) -> PyResult<Option<Bound<'py, PyString>>> {
        let mut g = self.lock()?;
        Ok(g.store
            .edge_rec(src, dst)?
            .and_then(|e| (e.jk != NO_JK).then(|| g.jk_py[e.jk as usize].bind(py).clone())))
    }

    /// `(src, dst)` pairs: nodes in insertion order, successors in insertion order.
    pub fn edges(&self) -> PyResult<Vec<(u64, u64)>> {
        let mut g = self.lock()?;
        Ok(g.store
            .edges_rec()?
            .into_iter()
            .map(|(s, d, _)| (s, d))
            .collect())
    }

    pub fn edges_with_data<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Vec<(u64, u64, Bound<'py, PyDict>)>> {
        let mut g = self.lock()?;
        g.store
            .edges_rec()?
            .into_iter()
            .map(|(s, d, e)| Ok((s, d, g.edge_dict(py, &e)?)))
            .collect()
    }

    /// `(src, dst, jumpkind, ins_addr, stmt_idx)` for every edge; cheaper than `edges_with_data`.
    pub fn edges_with_tuples<'py>(&self, py: Python<'py>) -> PyResult<Vec<EdgeRow<'py>>> {
        let mut g = self.lock()?;
        Ok(g.store
            .edges_rec()?
            .into_iter()
            .map(|(s, d, e)| {
                let (jk, ia, si) = g.rec_tuple(py, &e);
                (s, d, jk, ia, si)
            })
            .collect())
    }

    pub fn out_edges(&self, idx: u64) -> PyResult<Vec<(u64, u64)>> {
        let mut g = self.lock()?;
        Ok(g.store
            .out_edges_rec(idx)?
            .into_iter()
            .map(|(d, _)| (idx, d))
            .collect())
    }

    pub fn in_edges(&self, idx: u64) -> PyResult<Vec<(u64, u64)>> {
        let mut g = self.lock()?;
        Ok(g.store
            .in_edges_rec(idx)?
            .into_iter()
            .map(|(s, _)| (s, idx))
            .collect())
    }

    pub fn out_edges_with_data<'py>(
        &self,
        py: Python<'py>,
        idx: u64,
    ) -> PyResult<Vec<(u64, u64, Bound<'py, PyDict>)>> {
        let mut g = self.lock()?;
        g.store
            .out_edges_rec(idx)?
            .into_iter()
            .map(|(d, e)| Ok((idx, d, g.edge_dict(py, &e)?)))
            .collect()
    }

    pub fn in_edges_with_data<'py>(
        &self,
        py: Python<'py>,
        idx: u64,
    ) -> PyResult<Vec<(u64, u64, Bound<'py, PyDict>)>> {
        let mut g = self.lock()?;
        g.store
            .in_edges_rec(idx)?
            .into_iter()
            .map(|(s, e)| Ok((s, idx, g.edge_dict(py, &e)?)))
            .collect()
    }

    /// `(dst, jumpkind)` of every out-edge.
    pub fn out_edges_jumpkinds<'py>(
        &self,
        py: Python<'py>,
        idx: u64,
    ) -> PyResult<Vec<(u64, Option<Bound<'py, PyString>>)>> {
        let mut g = self.lock()?;
        Ok(g.store
            .out_edges_rec(idx)?
            .into_iter()
            .map(|(d, e)| (d, g.rec_tuple(py, &e).0))
            .collect())
    }

    /// `(src, jumpkind)` of every in-edge.
    pub fn in_edges_jumpkinds<'py>(
        &self,
        py: Python<'py>,
        idx: u64,
    ) -> PyResult<Vec<(u64, Option<Bound<'py, PyString>>)>> {
        let mut g = self.lock()?;
        Ok(g.store
            .in_edges_rec(idx)?
            .into_iter()
            .map(|(s, e)| (s, g.rec_tuple(py, &e).0))
            .collect())
    }

    pub fn successors(&self, idx: u64) -> PyResult<Vec<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.successors(idx)?)
    }

    pub fn predecessors(&self, idx: u64) -> PyResult<Vec<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.predecessors(idx)?)
    }

    pub fn out_degree(&self, idx: u64) -> PyResult<usize> {
        let mut g = self.lock()?;
        Ok(g.store.out_degree(idx)?)
    }

    pub fn in_degree(&self, idx: u64) -> PyResult<usize> {
        let mut g = self.lock()?;
        Ok(g.store.in_degree(idx)?)
    }

    // --- call destinations -----------------------------------------------------------------------

    pub fn is_call_destination(&self, idx: u64) -> PyResult<bool> {
        let mut g = self.lock()?;
        Ok(g.store.is_call_destination(idx)?)
    }

    pub fn call_destinations(&self) -> PyResult<Vec<u64>> {
        let mut g = self.lock()?;
        Ok(g.store.call_destinations()?)
    }

    // --- serialization ---------------------------------------------------------------------------

    /// One blob holding the header and every segment.
    pub fn to_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut g = self.lock()?;
        Ok(PyBytes::new(py, &g.store.to_bytes()?))
    }

    #[classmethod]
    pub fn from_bytes(_cls: &Bound<'_, PyType>, py: Python<'_>, data: &[u8]) -> PyResult<Self> {
        Ok(Self::wrap(py, Store::from_bytes(data)?))
    }

    /// `(header, [segment blob, ...])`: segment blobs come straight from the backend when evicted, so
    /// saving never needs the whole graph resident.
    pub fn to_blobs<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyList>)> {
        let mut g = self.lock()?;
        let blobs = g.store.segment_blobs()?;
        let header = PyBytes::new(py, &g.store.header_bytes()?);
        let list = PyList::new(py, blobs.iter().map(|b| PyBytes::new(py, b)))?;
        Ok((header, list))
    }

    /// Inverse of `to_blobs`; segments are decoded lazily on first touch.
    #[classmethod]
    pub fn from_blobs(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        header: &[u8],
        blobs: Vec<Vec<u8>>,
    ) -> PyResult<Self> {
        Ok(Self::wrap(py, Store::from_blobs(header, blobs)?))
    }

    fn __reduce__<'py>(slf: Bound<'py, Self>) -> PyResult<(Bound<'py, PyAny>, ReduceArgs<'py>)> {
        let py = slf.py();
        let (header, blobs) = slf.get().lock()?.blobs_out(py)?;
        let from_blobs = slf.get_type().getattr("from_blobs")?;
        Ok((from_blobs, (header, blobs)))
    }
}

pub fn cfg_graph(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<CfgGraph>()?;
    m.add("PRESENT_JUMPKIND", PRESENT_JUMPKIND)?;
    m.add("PRESENT_INS_ADDR", PRESENT_INS_ADDR)?;
    m.add("PRESENT_STMT_IDX", PRESENT_STMT_IDX)?;
    m.add("DEFAULT_WINDOW_SHIFT", DEFAULT_WINDOW_SHIFT)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u8 = PRESENT_JUMPKIND | PRESENT_INS_ADDR | PRESENT_STMT_IDX;

    fn edge(g: &mut Store, a: u64, b: u64, jk: &str) -> bool {
        g.add_edge(a, b, PRESENT_JUMPKIND, Some(jk), None, None)
            .unwrap()
    }

    #[test]
    fn nodes_edges_and_addr_index() {
        let mut g = Store::new(DEFAULT_WINDOW_SHIFT);
        let (a, _) = g.add_node(0x1000, 8).unwrap();
        let (b, _) = g.add_node(0x1008, 4).unwrap();
        let (b2, created) = g.add_node(0x1008, 6).unwrap();
        assert!(created);
        assert_eq!(g.add_node(0x1000, 8).unwrap(), (a, false));
        assert_eq!(g.nodes_at_addr(0x1008).unwrap(), vec![b, b2]);
        assert!(
            g.add_edge(a, b, ALL, Some("Ijk_Boring"), Some(0x1004), Some(3))
                .unwrap()
        );
        assert!(
            !g.add_edge(a, b, PRESENT_JUMPKIND, Some("Ijk_Call"), None, None)
                .unwrap()
        );
        let e = g.edge_rec(a, b).unwrap().unwrap();
        assert_eq!(g.jumpkind_str(e.jk), Some("Ijk_Call"));
        assert_eq!(e.ins_addr, 0x1004);
        assert_eq!(e.present.bits(), ALL);
        assert_eq!(g.out_degree(a).unwrap(), 1);
        assert_eq!(g.in_degree(b).unwrap(), 1);
        assert!(g.is_call_destination(b).unwrap());
        assert!(g.remove_edge(a, b).unwrap());
        assert!(!g.is_call_destination(b).unwrap());
        assert!(!g.remove_edge(a, b).unwrap());
        assert_eq!(g.node_key(a).unwrap(), (0x1000, 8));
    }

    #[test]
    fn remove_node_detaches_and_keeps_order() {
        let mut g = Store::new(DEFAULT_WINDOW_SHIFT);
        let (a, _) = g.add_node(0x10, 2).unwrap();
        let (b, _) = g.add_node(0x12, 2).unwrap();
        let (c, _) = g.add_node(0x14, 2).unwrap();
        edge(&mut g, a, b, "Ijk_Call");
        edge(&mut g, c, b, "Ijk_Call");
        assert!(g.remove_node(a).unwrap());
        assert!(g.is_call_destination(b).unwrap());
        assert!(g.remove_node(c).unwrap());
        assert!(!g.is_call_destination(b).unwrap());
        assert_eq!(g.number_of_edges(), 0);
        assert_eq!(g.nodes(), vec![b]);
        assert!(!g.has_addr(0x10).unwrap());
        let (a2, created) = g.add_node(0x10, 2).unwrap();
        assert!(created);
        assert_eq!(g.nodes(), vec![b, a2]);
        assert_eq!(g.node_keys().unwrap(), vec![(0x12, 2), (0x10, 2)]);
        assert_eq!(g.nodes_at_addr(0x10).unwrap(), vec![a2]);
    }

    #[test]
    fn sticky_call_destination_survives_jumpkind_change() {
        let mut g = Store::new(DEFAULT_WINDOW_SHIFT);
        let (a, _) = g.add_node(1, 1).unwrap();
        let (b, _) = g.add_node(2, 1).unwrap();
        edge(&mut g, a, b, "Ijk_Sys_syscall");
        edge(&mut g, a, b, "Ijk_Boring");
        assert!(g.is_call_destination(b).unwrap());
        // only re-checked when the removed edge is a call at removal time
        assert!(g.remove_edge(a, b).unwrap());
        assert!(g.is_call_destination(b).unwrap());
        assert!(g.remove_node(b).unwrap());
        assert!(!g.is_call_destination(b).unwrap());
    }

    /// Two windows of 16 bytes: nodes straddle the boundary, edges cross it.
    fn cross_graph() -> (Store, u64, u64, u64, u64) {
        let mut g = Store::new(4);
        let (a, _) = g.add_node(0x0c, 8).unwrap(); // window 0, extends into window 1
        let (b, _) = g.add_node(0x14, 4).unwrap(); // window 1
        let (c, _) = g.add_node(0x18, 4).unwrap(); // window 1
        let (d, _) = g.add_node(0x02, 2).unwrap(); // window 0
        assert_ne!(split_id(a).0, split_id(b).0);
        g.add_edge(a, b, ALL, Some("Ijk_Call"), Some(0x10), Some(1))
            .unwrap();
        edge(&mut g, b, c, "Ijk_Boring");
        edge(&mut g, c, a, "Ijk_Ret");
        edge(&mut g, c, d, "Ijk_Boring");
        edge(&mut g, a, a, "Ijk_Boring");
        (g, a, b, c, d)
    }

    #[test]
    fn cross_segment_edges() {
        let (mut g, a, b, c, d) = cross_graph();
        assert_eq!(g.number_of_edges(), 5);
        assert_eq!(g.successors(a).unwrap(), vec![b, a]);
        assert_eq!(g.predecessors(a).unwrap(), vec![c, a]);
        assert_eq!(g.out_degree(c).unwrap(), 2);
        assert_eq!(g.in_degree(a).unwrap(), 2);
        assert!(g.has_edge(a, b).unwrap() && !g.has_edge(b, a).unwrap());
        let e = g.edge_rec(a, b).unwrap().unwrap();
        assert_eq!((e.ins_addr, e.stmt_idx), (0x10, 1));
        // merge through the mirror: data must agree from both sides
        g.add_edge(a, b, PRESENT_STMT_IDX, None, None, Some(7))
            .unwrap();
        assert_eq!(g.edge_rec(a, b).unwrap().unwrap().stmt_idx, 7);
        assert_eq!(g.in_edges_rec(b).unwrap()[0].1.stmt_idx, 7);
        assert!(g.is_call_destination(b).unwrap());
        let pairs: Vec<(u64, u64)> = g.edges_rec().unwrap().iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(pairs, vec![(a, b), (a, a), (b, c), (c, a), (c, d)]);

        assert!(g.remove_edge(a, b).unwrap());
        assert!(!g.is_call_destination(b).unwrap());
        assert_eq!(g.predecessors(b).unwrap(), Vec::<u64>::new());
        assert_eq!(g.number_of_edges(), 4);
        assert_eq!(g.seg(split_id(a).0).proxy_of.len(), 1); // only c remains foreign to a's segment

        assert!(g.remove_node(c).unwrap());
        assert_eq!(g.number_of_edges(), 1);
        assert_eq!(g.predecessors(a).unwrap(), vec![a]);
        assert_eq!(g.successors(b).unwrap(), Vec::<u64>::new());
        assert_eq!(g.predecessors(d).unwrap(), Vec::<u64>::new());
        assert!(g.seg(split_id(a).0).proxy_of.is_empty());
        assert!(g.seg(split_id(b).0).proxy_of.is_empty());
        assert_eq!(g.nodes(), vec![a, b, d]);
    }

    #[test]
    fn blob_round_trip() {
        let (mut g, a, b, c, d) = cross_graph();
        let header = g.header_bytes().unwrap();
        let blobs = g.segment_blobs().unwrap();
        let mut back = Store::from_blobs(&header, blobs).unwrap();
        assert_eq!(back.nodes(), g.nodes());
        assert_eq!(back.edges_rec().unwrap(), g.edges_rec().unwrap());
        assert_eq!(back.node_keys().unwrap(), g.node_keys().unwrap());
        assert_eq!(back.call_destinations().unwrap(), vec![b]);
        assert_eq!(back.predecessors(a).unwrap(), vec![c, a]);
        assert_eq!(back.successors(a).unwrap(), vec![b, a]);
        assert_eq!(back.find_node(0x02, 2).unwrap(), Some(d));
        assert_eq!(back.number_of_edges(), 5);
        let bytes = g.to_bytes().unwrap();
        let mut back2 = Store::from_bytes(&bytes).unwrap();
        assert_eq!(back2.edges_rec().unwrap(), g.edges_rec().unwrap());
    }

    #[test]
    fn address_chains_survive_reload() {
        let mut g = Store::new(4);
        let (a, _) = g.add_node(0x10, 4).unwrap();
        let (b, _) = g.add_node(0x10, 8).unwrap();
        let (c, _) = g.add_node(0x10, 2).unwrap();
        g.attach_backend(Box::new(MemoryBackend::default()), 1)
            .unwrap();
        assert_eq!(g.nodes_at_addr(0x10).unwrap(), vec![a, b, c]);
        assert!(g.remove_node(a).unwrap());
        assert_eq!(g.nodes_at_addr(0x10).unwrap(), vec![b, c]);
        assert_eq!(g.first_node_at_addr(0x10).unwrap(), Some(b));
        assert!(g.remove_node(c).unwrap());
        assert_eq!(g.nodes_at_addr(0x10).unwrap(), vec![b]);
        assert_eq!(g.find_node(0x10, 8).unwrap(), Some(b));
        assert_eq!(g.find_node(0x10, 2).unwrap(), None);
        let (d, _) = g.add_node(0x10, 6).unwrap();
        assert_eq!(g.nodes_at_addr(0x10).unwrap(), vec![b, d]);
        assert!(g.remove_node(b).unwrap());
        assert!(g.remove_node(d).unwrap());
        assert!(!g.has_addr(0x10).unwrap());
    }

    #[test]
    fn paged_matches_resident() {
        let (mut r, a, b, c, d) = cross_graph();
        let mut p = Store::new(4);
        p.attach_backend(Box::new(MemoryBackend::default()), 1)
            .unwrap(); // at most one segment resident
        let (pa, _) = p.add_node(0x0c, 8).unwrap();
        let (pb, _) = p.add_node(0x14, 4).unwrap();
        let (pc, _) = p.add_node(0x18, 4).unwrap();
        let (pd, _) = p.add_node(0x02, 2).unwrap();
        assert_eq!((pa, pb, pc, pd), (a, b, c, d));
        p.add_edge(a, b, ALL, Some("Ijk_Call"), Some(0x10), Some(1))
            .unwrap();
        edge(&mut p, b, c, "Ijk_Boring");
        edge(&mut p, c, a, "Ijk_Ret");
        edge(&mut p, c, d, "Ijk_Boring");
        edge(&mut p, a, a, "Ijk_Boring");
        assert!(p.stats().evictions > 0 && p.stats().loads > 0);
        assert!(p.resident_segments() <= 1);
        assert_eq!(p.edges_rec().unwrap(), r.edges_rec().unwrap());
        assert_eq!(p.node_keys().unwrap(), r.node_keys().unwrap());
        assert_eq!(
            p.call_destinations().unwrap(),
            r.call_destinations().unwrap()
        );
        p.remove_node(c).unwrap();
        r.remove_node(c).unwrap();
        assert_eq!(p.edges_rec().unwrap(), r.edges_rec().unwrap());
        assert_eq!(p.number_of_edges(), r.number_of_edges());
        // promotion mid-build: attach after the fact, then detach
        let mut q = cross_graph().0;
        q.attach_backend(Box::new(MemoryBackend::default()), 1)
            .unwrap();
        assert!(q.resident_segments() <= 1);
        q.remove_node(c).unwrap();
        assert_eq!(q.edges_rec().unwrap(), r.edges_rec().unwrap());
        q.detach_backend().unwrap();
        assert!(!q.is_paged() && q.all_resident());
        assert_eq!(q.edges_rec().unwrap(), r.edges_rec().unwrap());
        q.compact().unwrap();
        assert_eq!(q.edges_rec().unwrap(), r.edges_rec().unwrap());
        assert_eq!(q.node_keys().unwrap(), r.node_keys().unwrap());
        assert_eq!(q.predecessors(a).unwrap(), r.predecessors(a).unwrap());
    }
}
