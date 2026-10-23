//! Index-encoded ports of the deterministic graph utilities in `angr.utils.graph`.
//!
//! Exposed as `angr.rustylib.graph_utils`. Every entry point takes the graph's successor mapping (`DiGraph._succ`:
//! a dict of dicts, or a RegionOverlayGraph's lazy atlas), indexes the nodes in iteration order and the successors in
//! adjacency order, and returns node objects; the algorithms reproduce the Python implementations step by step,
//! including their `sort_node` / `sort_edge` tie-breaks.

use std::cmp::Ordering;
use std::collections::VecDeque;

use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyString};
use rustc_hash::{FxHashMap, FxHashSet};

/// `sys.maxsize`: nodes without an idx sort after every idx-carrying node at the same address.
const NO_IDX: i64 = i64::MAX;
const DEFAULT_PANIC_MODE_THRESHOLD: usize = 3000;

/// Successor lists in adjacency order.
struct Csr {
    offsets: Vec<u32>,
    targets: Vec<u32>,
}

impl Csr {
    fn len(&self) -> usize {
        self.offsets.len() - 1
    }

    fn succ(&self, u: usize) -> &[u32] {
        &self.targets[self.offsets[u] as usize..self.offsets[u + 1] as usize]
    }

    fn edge_count(&self) -> usize {
        self.targets.len()
    }

    fn in_degrees(&self) -> Vec<u32> {
        let mut indeg = vec![0u32; self.len()];
        for &t in &self.targets {
            indeg[t as usize] += 1;
        }
        indeg
    }

    /// Induced subgraph on `nodes` (local index = position in `nodes`), without the edges in `removed`.
    fn induced(&self, nodes: &[u32], removed: &FxHashSet<(u32, u32)>) -> Csr {
        let mut local = FxHashMap::default();
        for (i, &n) in nodes.iter().enumerate() {
            local.insert(n, i as u32);
        }
        let mut offsets = Vec::with_capacity(nodes.len() + 1);
        let mut targets = Vec::new();
        offsets.push(0u32);
        for &u in nodes {
            for &v in self.succ(u as usize) {
                if let Some(&lv) = local.get(&v)
                    && !removed.contains(&(u, v))
                {
                    targets.push(lv);
                }
            }
            offsets.push(targets.len() as u32);
        }
        Csr { offsets, targets }
    }
}

/// (node, index of its non-trivial strongly connected component) pairs.
type SccMembership<'py> = Vec<(Bound<'py, PyAny>, i64)>;

/// A graph read through its successor mapping: nodes in iteration order, their indices, successors in adjacency order.
struct Encoded<'py> {
    nodes: Vec<Bound<'py, PyAny>>,
    index: Bound<'py, PyDict>,
    csr: Csr,
}

impl<'py> Encoded<'py> {
    fn from_successors(succ: &Bound<'py, PyAny>) -> PyResult<Self> {
        let py = succ.py();
        let index = PyDict::new(py);
        let mut nodes: Vec<Bound<'py, PyAny>> = Vec::new();
        let mut inners: Vec<Bound<'py, PyAny>> = Vec::new();
        if let Ok(dict) = succ.cast::<PyDict>() {
            for (node, inner) in dict.iter() {
                index.set_item(&node, nodes.len())?;
                nodes.push(node);
                inners.push(inner);
            }
        } else {
            for node in succ.try_iter()? {
                let node = node?;
                let inner = succ.get_item(&node)?;
                index.set_item(&node, nodes.len())?;
                nodes.push(node);
                inners.push(inner);
            }
        }
        let mut offsets = Vec::with_capacity(nodes.len() + 1);
        let mut targets: Vec<u32> = Vec::new();
        offsets.push(0u32);
        let lookup = |target: Bound<'py, PyAny>| -> PyResult<u32> {
            match index.get_item(&target)? {
                Some(i) => i.extract::<u32>(),
                None => Err(PyKeyError::new_err("successor is not a node of the graph")),
            }
        };
        for inner in &inners {
            if let Ok(dict) = inner.cast::<PyDict>() {
                for (target, _) in dict.iter() {
                    targets.push(lookup(target)?);
                }
            } else {
                for target in inner.try_iter()? {
                    targets.push(lookup(target?)?);
                }
            }
            offsets.push(targets.len() as u32);
        }
        Ok(Encoded {
            nodes,
            index,
            csr: Csr { offsets, targets },
        })
    }

    fn position(&self, node: &Bound<'py, PyAny>) -> PyResult<Option<u32>> {
        match self.index.get_item(node)? {
            Some(i) => Ok(Some(i.extract::<u32>()?)),
            None => Ok(None),
        }
    }

    fn require(&self, node: &Bound<'py, PyAny>) -> PyResult<u32> {
        self.position(node)?
            .ok_or_else(|| PyKeyError::new_err("node is not in the graph"))
    }
}

/// `GraphUtils.sort_node` keys of the graph's nodes plus the `sort_edge` / SCC-address key.
struct Keys {
    kinds: Vec<u8>,
    addrs: Vec<i64>,
    idxs: Vec<i64>,
    texts: Vec<u32>,
    table: Vec<String>,
    /// `node.addr if hasattr(node, "addr") else node`; None when neither is an int.
    edge_keys: Vec<Option<i64>>,
}

impl Keys {
    fn extract(nodes: &[Bound<'_, PyAny>]) -> PyResult<Self> {
        let mut keys = Keys {
            kinds: Vec::new(),
            addrs: Vec::new(),
            idxs: Vec::new(),
            texts: Vec::new(),
            table: Vec::new(),
            edge_keys: Vec::new(),
        };
        let mut interned: FxHashMap<String, u32> = FxHashMap::default();
        for node in nodes {
            let py = node.py();
            // sort_node: `node.addr`, with AttributeError/TypeError meaning "no address"
            let addr = match node.getattr_opt(intern!(py, "addr")) {
                Ok(a) => a,
                Err(e) if e.is_instance_of::<PyTypeError>(py) => None,
                Err(e) => return Err(e),
            };
            let (kind, addr_i, idx, text, edge_key) = match addr {
                Some(a) if a.is_instance_of::<PyInt>() => {
                    let addr_i: i64 = a.extract()?;
                    let idx = match node.getattr_opt(intern!(py, "idx"))? {
                        Some(v) if v.is_instance_of::<PyInt>() => v.extract::<i64>()?,
                        _ => NO_IDX,
                    };
                    (
                        0u8,
                        addr_i,
                        idx,
                        node.get_type().name()?.to_string(),
                        Some(addr_i),
                    )
                }
                Some(_) => (2u8, 0, 0, node.get_type().name()?.to_string(), None),
                None if node.is_instance_of::<PyInt>() => {
                    let v: i64 = node.extract()?;
                    (0u8, v, NO_IDX, String::new(), Some(v))
                }
                None if node.is_instance_of::<PyString>() => (
                    1u8,
                    0,
                    0,
                    node.cast::<PyString>()?.to_str()?.to_owned(),
                    None,
                ),
                None => (2u8, 0, 0, node.get_type().name()?.to_string(), None),
            };
            let text_id = match interned.get(&text) {
                Some(&id) => id,
                None => {
                    let id = keys.table.len() as u32;
                    keys.table.push(text.clone());
                    interned.insert(text, id);
                    id
                }
            };
            keys.kinds.push(kind);
            keys.addrs.push(addr_i);
            keys.idxs.push(idx);
            keys.texts.push(text_id);
            keys.edge_keys.push(edge_key);
        }
        Ok(keys)
    }

    /// Register an extra key (SCC placeholders), returning its id.
    fn push(&mut self, kind: u8, addr: i64, idx: i64, text: &str) -> u32 {
        let text_id = match self.table.iter().position(|t| t == text) {
            Some(p) => p as u32,
            None => {
                self.table.push(text.to_owned());
                (self.table.len() - 1) as u32
            }
        };
        self.kinds.push(kind);
        self.addrs.push(addr);
        self.idxs.push(idx);
        self.texts.push(text_id);
        self.edge_keys.push(None);
        (self.kinds.len() - 1) as u32
    }

    fn cmp(&self, a: u32, b: u32) -> Ordering {
        let (a, b) = (a as usize, b as usize);
        self.kinds[a]
            .cmp(&self.kinds[b])
            .then(self.addrs[a].cmp(&self.addrs[b]))
            .then(self.idxs[a].cmp(&self.idxs[b]))
            .then_with(|| {
                self.table[self.texts[a] as usize].cmp(&self.table[self.texts[b] as usize])
            })
    }

    fn edge_key(&self, a: u32) -> PyResult<i64> {
        self.edge_keys[a as usize]
            .ok_or_else(|| PyTypeError::new_err("node without an integer address key"))
    }
}

/// Tarjan's algorithm, iterative; every component as a list of local ids in ascending order.
fn strongly_connected_components(g: &Csr) -> Vec<Vec<u32>> {
    let n = g.len();
    let mut index = vec![u32::MAX; n];
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut sccs = Vec::new();
    let mut counter = 0u32;
    for root in 0..n {
        if index[root] != u32::MAX {
            continue;
        }
        let mut work: Vec<(u32, usize)> = vec![(root as u32, 0)];
        index[root] = counter;
        lowlink[root] = counter;
        counter += 1;
        stack.push(root as u32);
        on_stack[root] = true;
        while let Some(&mut (v, ref mut pos)) = work.last_mut() {
            let succ = g.succ(v as usize);
            if *pos < succ.len() {
                let w = succ[*pos];
                *pos += 1;
                if index[w as usize] == u32::MAX {
                    index[w as usize] = counter;
                    lowlink[w as usize] = counter;
                    counter += 1;
                    stack.push(w);
                    on_stack[w as usize] = true;
                    work.push((w, 0));
                } else if on_stack[w as usize] {
                    lowlink[v as usize] = lowlink[v as usize].min(index[w as usize]);
                }
                continue;
            }
            work.pop();
            if let Some(&(parent, _)) = work.last() {
                lowlink[parent as usize] = lowlink[parent as usize].min(lowlink[v as usize]);
            }
            if lowlink[v as usize] == index[v as usize] {
                let mut comp = Vec::new();
                loop {
                    let w = stack.pop().unwrap();
                    on_stack[w as usize] = false;
                    comp.push(w);
                    if w == v {
                        break;
                    }
                }
                comp.sort_unstable();
                sccs.push(comp);
            }
        }
    }
    sccs
}

/// `GraphUtils.dfs_postorder_nodes_deterministic_multi` over an arbitrary successor function.
fn dfs_postorder_sorted(
    n: usize,
    succ: impl Fn(u32) -> Vec<u32>,
    sources: &[u32],
    keys: &Keys,
) -> Vec<u32> {
    let mut visited = vec![false; n];
    let mut order = Vec::new();
    let mut seeds = sources.to_vec();
    seeds.sort_by(|&a, &b| keys.cmp(a, b));
    let mut stack: Vec<(u32, bool)> = seeds.into_iter().map(|s| (s, true)).collect();
    while let Some((node, pre_visit)) = stack.pop() {
        if pre_visit {
            if visited[node as usize] {
                continue;
            }
            visited[node as usize] = true;
            stack.push((node, false));
            let mut succs = succ(node);
            succs.sort_by(|&a, &b| keys.cmp(a, b));
            for s in succs {
                if !visited[s as usize] {
                    stack.push((s, true));
                }
            }
        } else {
            order.push(node);
        }
    }
    order
}

/// `angr.utils.graph.dfs_back_edges` on a CSR.
fn back_edges(
    g: &Csr,
    keys: &Keys,
    node_ids: &[u32],
    start: u32,
    visit_all_nodes: bool,
) -> Vec<(u32, u32)> {
    let n = g.len();
    let mut visited = vec![false; n];
    let mut finished = vec![false; n];
    let mut n_visited = 0usize;
    let mut out = Vec::new();
    let sorted_succ = |v: u32| {
        let mut s = g.succ(v as usize).to_vec();
        s.sort_by(|&a, &b| keys.cmp(node_ids[a as usize], node_ids[b as usize]));
        s
    };
    let mut start = start;
    loop {
        // like the Python version, restarts share `visited` and `finished`: an edge into a node finished by an
        // earlier traversal is not a back edge
        let mut stack: Vec<(u32, Vec<u32>, usize)> = vec![(start, sorted_succ(start), 0)];
        while let Some(top) = stack.last_mut() {
            let node = top.0;
            if !visited[node as usize] {
                visited[node as usize] = true;
                n_visited += 1;
            }
            if top.2 < top.1.len() {
                let child = top.1[top.2];
                top.2 += 1;
                if visited[child as usize] {
                    if !finished[child as usize] {
                        out.push((node, child));
                    }
                } else if !finished[child as usize] {
                    stack.push((child, sorted_succ(child), 0));
                }
            } else {
                stack.pop();
                finished[node as usize] = true;
            }
        }
        if !visit_all_nodes || n_visited >= n {
            break;
        }
        // min(unvisited, key=sort_node); the first minimum in node order
        let mut best: Option<u32> = None;
        for v in 0..n as u32 {
            if !visited[v as usize]
                && best.is_none_or(|b| {
                    keys.cmp(node_ids[v as usize], node_ids[b as usize]) == Ordering::Less
                })
            {
                best = Some(v);
            }
        }
        start = best.unwrap();
    }
    out
}

/// BFS distances from `src` (u32::MAX = unreachable).
fn bfs_distances(g: &Csr, src: u32) -> Vec<u32> {
    let mut dist = vec![u32::MAX; g.len()];
    dist[src as usize] = 0;
    let mut queue = VecDeque::from([src]);
    while let Some(u) = queue.pop_front() {
        for &v in g.succ(u as usize) {
            if dist[v as usize] == u32::MAX {
                dist[v as usize] = dist[u as usize] + 1;
                queue.push_back(v);
            }
        }
    }
    dist
}

/// `GraphUtils.quasi_topological_sort_nodes` on a local CSR; `node_ids` maps local ids to key ids.
fn quasi_topological_sort(
    g: &Csr,
    keys: &mut Keys,
    node_ids: &[u32],
    loop_heads: Option<&[u32]>,
    panic_mode_threshold: usize,
    mut scc_membership: Option<&mut Vec<i64>>,
) -> PyResult<Vec<u32>> {
    let m = g.len();
    if m == 0 {
        return Ok(Vec::new());
    }
    if m == 1 {
        return Ok(vec![0]);
    }

    // non-trivial SCCs, sorted by (size, min address)
    let mut sccs: Vec<(Vec<u32>, i64)> = Vec::new();
    for comp in strongly_connected_components(g) {
        if comp.len() > 1 {
            let mut min_addr = i64::MAX;
            for &v in &comp {
                min_addr = min_addr.min(keys.edge_key(node_ids[v as usize])?);
            }
            sccs.push((comp, min_addr));
        }
    }
    sccs.sort_by_key(|(comp, min_addr)| (comp.len(), *min_addr));
    let mut comp_index = vec![-1i64; m];
    for (i, (comp, _)) in sccs.iter().enumerate() {
        for &v in comp {
            comp_index[v as usize] = i as i64;
            if let Some(out) = scc_membership.as_deref_mut() {
                out[node_ids[v as usize] as usize] = i as i64;
            }
        }
    }

    // placeholder key ids: (0, scc_addr, NO_IDX, "SCCPlaceholder")
    let placeholder_keys: Vec<u32> = sccs
        .iter()
        .map(|(_, addr)| keys.push(0, *addr, NO_IDX, "SCCPlaceholder"))
        .collect();
    let key_of = |v: u32| -> u32 {
        if (v as usize) < m {
            node_ids[v as usize]
        } else {
            placeholder_keys[v as usize - m]
        }
    };

    // collapse the SCCs: edges in sort_edge order, graph_copy ids = local ids, then placeholders, then the head
    let mut edges: Vec<(u32, u32, i128)> = Vec::with_capacity(g.edge_count());
    for u in 0..m {
        let ku = keys.edge_key(node_ids[u])? as i128;
        for &v in g.succ(u) {
            edges.push((
                u as u32,
                v,
                ku + keys.edge_key(node_ids[v as usize])? as i128,
            ));
        }
    }
    edges.sort_by_key(|e| e.2);
    let k = sccs.len();
    let total = m + k + 1;
    let mut present = vec![false; total];
    let mut insertion: Vec<u32> = Vec::new();
    let mut adj: Vec<Vec<u32>> = vec![Vec::new(); total];
    let mut indeg = vec![0u32; total];
    let mut edge_set: FxHashSet<(u32, u32)> = FxHashSet::default();
    let ensure = |v: u32, present: &mut Vec<bool>, insertion: &mut Vec<u32>| {
        if !present[v as usize] {
            present[v as usize] = true;
            insertion.push(v);
        }
    };
    let mapped = |v: u32| -> u32 {
        let c = comp_index[v as usize];
        if c >= 0 { (m as i64 + c) as u32 } else { v }
    };
    for (src, dst, _) in edges {
        let (s, d) = (mapped(src), mapped(dst));
        if s == d {
            ensure(s, &mut present, &mut insertion);
            continue;
        }
        ensure(s, &mut present, &mut insertion);
        ensure(d, &mut present, &mut insertion);
        if edge_set.insert((s, d)) {
            adj[s as usize].push(d);
            indeg[d as usize] += 1;
        }
    }
    let orig_indeg = g.in_degrees();
    for (u, &indeg_u) in orig_indeg.iter().enumerate() {
        if g.succ(u).is_empty() && indeg_u == 0 {
            ensure(u as u32, &mut present, &mut insertion);
        }
    }

    let heads: Vec<u32> = insertion
        .iter()
        .copied()
        .filter(|&v| indeg[v as usize] == 0)
        .collect();
    let synthetic = (m + k) as u32;
    let head = if heads.len() > 1 {
        adj[synthetic as usize] = heads;
        synthetic
    } else {
        *heads
            .first()
            .ok_or_else(|| PyValueError::new_err("condensation has no source node"))?
    };

    // the deterministic post-order DFS compares graph_copy nodes by their sort_node keys
    let postorder = {
        let mut visited = vec![false; total];
        let mut order = Vec::new();
        let mut stack: Vec<(u32, bool)> = vec![(head, true)];
        while let Some((node, pre_visit)) = stack.pop() {
            if pre_visit {
                if visited[node as usize] {
                    continue;
                }
                visited[node as usize] = true;
                stack.push((node, false));
                let mut succs = adj[node as usize].clone();
                succs.sort_by(|&a, &b| keys.cmp(key_of(a), key_of(b)));
                for s in succs {
                    if !visited[s as usize] {
                        stack.push((s, true));
                    }
                }
            } else {
                order.push(node);
            }
        }
        order
    };

    let mut ordered: Vec<u32> = Vec::with_capacity(m);
    for &node in postorder.iter().rev() {
        if node == synthetic {
            continue;
        }
        if (node as usize) >= m {
            let scc = &sccs[node as usize - m].0;
            append_scc(
                g,
                keys,
                node_ids,
                &mut ordered,
                scc,
                loop_heads,
                panic_mode_threshold,
            )?;
        } else {
            ordered.push(node);
        }
    }
    Ok(ordered)
}

/// `GraphUtils._append_scc`.
fn append_scc(
    g: &Csr,
    keys: &mut Keys,
    node_ids: &[u32],
    ordered: &mut Vec<u32>,
    scc: &[u32],
    loop_head_candidates: Option<&[u32]>,
    panic_mode_threshold: usize,
) -> PyResult<()> {
    let in_scc: FxHashSet<u32> = scc.iter().copied().collect();
    let mut loop_head: Option<u32> = None;

    if let Some(cands) = loop_head_candidates {
        let cand_set: FxHashSet<u32> = cands.iter().copied().collect();
        loop_head = scc.iter().copied().find(|v| cand_set.contains(v));
    }

    if loop_head.is_none() {
        for &parent in ordered.iter().rev() {
            let mut scc_succs: Vec<u32> = Vec::new();
            for &s in g.succ(parent as usize) {
                if in_scc.contains(&s) && !scc_succs.contains(&s) {
                    scc_succs.push(s);
                }
            }
            if scc_succs.len() == 1 {
                loop_head = Some(scc_succs[0]);
                break;
            }
            if scc_succs.len() > 1 {
                // the node with the smallest total distance to the others; ties go to the last one in sort order
                scc_succs.sort_by(|&a, &b| keys.cmp(node_ids[a as usize], node_ids[b as usize]));
                let mut best: Option<(u64, u32)> = None;
                for &s in &scc_succs {
                    let dist = bfs_distances(g, s);
                    let mut total = 0u64;
                    for &o in &scc_succs {
                        if o != s {
                            let d = dist[o as usize];
                            if d == u32::MAX {
                                return Err(PyValueError::new_err(
                                    "no path between nodes of one SCC",
                                ));
                            }
                            total += d as u64;
                        }
                    }
                    if best.is_none_or(|(bt, _)| total <= bt) {
                        best = Some((total, s));
                    }
                }
                loop_head = best.map(|(_, s)| s);
                break;
            }
        }
    }

    let loop_head = loop_head.unwrap_or_else(|| {
        *scc.iter()
            .min_by(|&&a, &&b| keys.cmp(node_ids[a as usize], node_ids[b as usize]))
            .unwrap()
    });

    // subgraph without the loop head's in-edges
    let mut removed: FxHashSet<(u32, u32)> = FxHashSet::default();
    for &u in scc {
        if g.succ(u as usize).contains(&loop_head) {
            removed.insert((u, loop_head));
        }
    }
    let mut sub = g.induced(scc, &removed);

    // panic mode: aggressively remove back edges of a dense component
    let limit = (scc.len() as f64) * 1.4;
    if scc.len() > panic_mode_threshold && (sub.edge_count() as f64) > limit {
        let local_head = scc.iter().position(|&v| v == loop_head).unwrap() as u32;
        let sub_ids: Vec<u32> = scc.iter().map(|&v| node_ids[v as usize]).collect();
        let mut back = back_edges(&sub, keys, &sub_ids, local_head, false);
        let key = |v: u32| keys.edge_key(sub_ids[v as usize]).map(|k| k as i128);
        let mut keyed: Vec<((u32, u32), i128)> = Vec::with_capacity(back.len());
        for (a, b) in back.drain(..) {
            keyed.push(((a, b), key(a)? + key(b)?));
        }
        keyed.sort_by_key(|e| e.1);
        let mut n_edges = sub.edge_count();
        for ((a, b), _) in keyed {
            removed.insert((scc[a as usize], scc[b as usize]));
            n_edges -= 1;
            if (n_edges as f64) <= limit {
                break;
            }
        }
        sub = g.induced(scc, &removed);
    }

    let sub_ids: Vec<u32> = scc.iter().map(|&v| node_ids[v as usize]).collect();
    let inner = quasi_topological_sort(
        &sub,
        keys,
        &sub_ids,
        None,
        DEFAULT_PANIC_MODE_THRESHOLD,
        None,
    )?;
    ordered.extend(inner.into_iter().map(|v| scc[v as usize]));
    Ok(())
}

/// `GraphUtils.quasi_topological_sort_nodes`: the ordered nodes and, if requested, (node, index of its non-trivial
/// strongly connected component) for every node of such a component.
#[pyfunction]
#[pyo3(signature = (successors, loop_heads=None, panic_mode_threshold=DEFAULT_PANIC_MODE_THRESHOLD, scc_membership=false))]
fn quasi_topological_sort_nodes<'py>(
    successors: &Bound<'py, PyAny>,
    loop_heads: Option<Vec<Bound<'py, PyAny>>>,
    panic_mode_threshold: usize,
    scc_membership: bool,
) -> PyResult<(Vec<Bound<'py, PyAny>>, Option<SccMembership<'py>>)> {
    let enc = Encoded::from_successors(successors)?;
    let mut keys = Keys::extract(&enc.nodes)?;
    let n = enc.nodes.len();
    let heads = match loop_heads {
        None => None,
        Some(hs) => {
            let mut ids = Vec::with_capacity(hs.len());
            for h in &hs {
                if let Some(i) = enc.position(h)? {
                    ids.push(i);
                }
            }
            Some(ids)
        }
    };
    let node_ids: Vec<u32> = (0..n as u32).collect();
    let mut membership = if scc_membership {
        Some(vec![-1i64; n])
    } else {
        None
    };
    let order = quasi_topological_sort(
        &enc.csr,
        &mut keys,
        &node_ids,
        heads.as_deref(),
        panic_mode_threshold,
        membership.as_mut(),
    )?;
    let ordered = order
        .into_iter()
        .map(|i| enc.nodes[i as usize].clone())
        .collect();
    let membership = membership.map(|m| {
        m.into_iter()
            .enumerate()
            .filter(|(_, scc)| *scc >= 0)
            .map(|(i, scc)| (enc.nodes[i].clone(), scc))
            .collect()
    });
    Ok((ordered, membership))
}

/// `GraphUtils.dfs_postorder_nodes_deterministic_multi` (a single source is the single-source variant).
#[pyfunction]
fn dfs_postorder_nodes_deterministic<'py>(
    successors: &Bound<'py, PyAny>,
    sources: Vec<Bound<'py, PyAny>>,
) -> PyResult<Vec<Bound<'py, PyAny>>> {
    let enc = Encoded::from_successors(successors)?;
    let keys = Keys::extract(&enc.nodes)?;
    let mut seeds = Vec::with_capacity(sources.len());
    for s in &sources {
        seeds.push(enc.require(s)?);
    }
    let order = dfs_postorder_sorted(
        enc.nodes.len(),
        |v| enc.csr.succ(v as usize).to_vec(),
        &seeds,
        &keys,
    );
    Ok(order
        .into_iter()
        .map(|i| enc.nodes[i as usize].clone())
        .collect())
}

/// `angr.utils.graph.dfs_back_edges`.
#[pyfunction]
#[pyo3(signature = (successors, start, visit_all_nodes=false))]
fn dfs_back_edges<'py>(
    successors: &Bound<'py, PyAny>,
    start: &Bound<'py, PyAny>,
    visit_all_nodes: bool,
) -> PyResult<Vec<(Bound<'py, PyAny>, Bound<'py, PyAny>)>> {
    let enc = Encoded::from_successors(successors)?;
    let keys = Keys::extract(&enc.nodes)?;
    let start = enc.require(start)?;
    let node_ids: Vec<u32> = (0..enc.nodes.len() as u32).collect();
    let edges = back_edges(&enc.csr, &keys, &node_ids, start, visit_all_nodes);
    Ok(edges
        .into_iter()
        .map(|(a, b)| (enc.nodes[a as usize].clone(), enc.nodes[b as usize].clone()))
        .collect())
}

#[pymodule]
pub fn graph_utils(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(quasi_topological_sort_nodes, m)?)?;
    m.add_function(wrap_pyfunction!(dfs_postorder_nodes_deterministic, m)?)?;
    m.add_function(wrap_pyfunction!(dfs_back_edges, m)?)?;
    Ok(())
}
