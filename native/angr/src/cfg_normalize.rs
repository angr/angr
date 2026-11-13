//! `CFGBase.normalize` in Rust, for CFGFast's integer-keyed graphs.
//!
//! The Python algorithm works on CFGNode objects: views of graph records, or detached objects (removed nodes and
//! the new nodes it creates before they are added). Here every such object is a handle with its key, its fields
//! and the record id it is attached to. Graph operations follow `SpillingCFG`: an object is found by its record
//! id while attached and by its key otherwise, adding a detached object writes its fields into the record of its
//! key, and a record that is removed or overwritten first detaches its view (the `detach(id)` callback does the
//! same for the Python view of that id). The side tables the Python code updates (`_blockid_to_blockkey`,
//! `_block_addrs_with_return`, jump tables, indirect jumps) are returned as event lists for Python to apply.

use pyo3::exceptions::{PyIndexError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rustc_hash::FxHashMap;

use crate::cfg_graph::{
    BYTES_NONE, CfgGraph, EdgeRec, NodeFields, PRESENT_INS_ADDR, PRESENT_JUMPKIND,
};
use crate::ordered_map::OrderedMap;

type Key = (u64, i64);

struct Obj {
    addr: u64,
    size: i64,
    fields: NodeFields,
    attached: Option<u64>,
}

impl Obj {
    fn key(&self) -> Key {
        (self.addr, self.size)
    }

    fn end(&self) -> u64 {
        self.addr.wrapping_add(self.size as u64)
    }

    fn ins_len(&self) -> usize {
        self.fields.ins_sizes.len()
    }

    /// `instruction_addrs[-1]`
    fn ins_last(&self) -> u64 {
        let s = &self.fields.ins_sizes;
        self.fields.ins_base + s[..s.len() - 1].iter().map(|&x| x as u64).sum::<u64>()
    }

    /// `CFGBase._last_decoded_ins_addr`: the last instruction address, skipping the IMark VEX emits at the end of a
    /// NoDecode block for the undecodable instruction.
    fn ins_last_decoded(&self) -> Option<u64> {
        let n = self.ins_len();
        if n == 0 {
            return None;
        }
        let last = self.ins_last();
        if last < self.end() {
            return Some(last);
        }
        if n == 1 {
            return None;
        }
        let s = &self.fields.ins_sizes;
        Some(last.wrapping_sub(s[n - 2] as u64))
    }

    /// `addr in instruction_addrs`
    fn ins_contains(&self, addr: u64) -> bool {
        let base = self.fields.ins_base;
        if self.fields.ins_sizes.is_empty() || addr < base {
            return false;
        }
        let mut cur = base;
        for &s in &self.fields.ins_sizes {
            if cur == addr {
                return true;
            }
            cur = cur.wrapping_add(s as u64);
        }
        false
    }

    fn ins_iter(&self) -> impl Iterator<Item = u64> + '_ {
        let mut cur = self.fields.ins_base;
        self.fields.ins_sizes.iter().map(move |&s| {
            let a = cur;
            cur = cur.wrapping_add(s as u64);
            a
        })
    }
}

/// `InsAddrList.from_addr_list`
fn ins_from_addrs(addrs: &[u64]) -> PyResult<(u64, Vec<u8>)> {
    if addrs.is_empty() {
        return Ok((0, Vec::new()));
    }
    let mut sizes = Vec::with_capacity(addrs.len());
    for w in addrs.windows(2) {
        let d = w[1].wrapping_sub(w[0]);
        sizes.push(
            u8::try_from(d).map_err(|_| PyValueError::new_err("byte must be in range(0, 256)"))?,
        );
    }
    sizes.push(0);
    Ok((addrs[0], sizes))
}

struct Normalizer<'py> {
    py: Python<'py>,
    graph: &'py CfgGraph,
    detach_cb: Bound<'py, PyAny>,
    is_arm: bool,
    objs: Vec<Obj>,
    /// record id -> the object attached to it
    by_id: FxHashMap<u64, usize>,
    end_to_nodes: OrderedMap<u64, Vec<usize>>,
    smallest: OrderedMap<u64, usize>,
    // results
    block_keys: Vec<(u64, Key)>,
    no_return: Vec<u64>,
    groups: Vec<(u64, Vec<u64>)>,
    warnings: Vec<(u8, u64, u64)>,
}

/// warning kinds
const WARN_NO_INS_ADDR: u8 = 0;
const WARN_OVERLAP: u8 = 1;

impl<'py> Normalizer<'py> {
    fn id_of(&self, h: usize) -> PyResult<Option<u64>> {
        if let Some(id) = self.objs[h].attached {
            return Ok(Some(id));
        }
        let (a, s) = self.objs[h].key();
        self.graph.with_store(|st| st.find_node(a, s))
    }

    /// Detach the views of a record that is about to be removed or overwritten.
    fn detach_id(&mut self, id: u64) -> PyResult<()> {
        self.detach_cb.call1((id,))?;
        if let Some(h) = self.by_id.remove(&id) {
            self.objs[h].attached = None;
        }
        Ok(())
    }

    /// `_IntKeys.add_node`
    fn add_node(&mut self, h: usize) -> PyResult<u64> {
        if let Some(id) = self.objs[h].attached {
            return Ok(id);
        }
        let (a, s) = self.objs[h].key();
        if let Some(existing) = self.graph.with_store(|st| st.find_node(a, s))? {
            self.detach_id(existing)?;
        }
        let fields = &self.objs[h].fields;
        let id = self
            .graph
            .with_store(|st| Ok(st.add_node_rec(a, s, fields)?.0))?;
        self.objs[h].attached = Some(id);
        self.by_id.insert(id, h);
        Ok(id)
    }

    /// `SpillingCFG.remove_node`
    fn remove_node(&mut self, h: usize) -> PyResult<()> {
        if let Some(id) = self.id_of(h)? {
            self.detach_id(id)?;
            self.graph.with_store(|st| st.remove_node(id))?;
        }
        Ok(())
    }

    fn in_graph(&self, h: usize) -> PyResult<bool> {
        Ok(self.id_of(h)?.is_some())
    }

    fn edges(&self, h: usize, incoming: bool) -> PyResult<Vec<(u64, EdgeRec)>> {
        match self.id_of(h)? {
            None => Ok(Vec::new()),
            Some(id) => self.graph.with_store(|st| {
                if incoming {
                    st.in_edges_rec(id)
                } else {
                    st.out_edges_rec(id)
                }
            }),
        }
    }

    fn add_edge_ids(&self, src: u64, dst: u64, rec: &EdgeRec) -> PyResult<()> {
        self.graph
            .with_store(|st| st.add_edge_like(src, dst, rec))?;
        Ok(())
    }

    fn real_addr(&self, a: u64) -> u64 {
        if self.is_arm { a & !1 } else { a }
    }

    fn contains_key(list: &[usize], objs: &[Obj], k: Key) -> bool {
        list.iter().any(|&x| objs[x].key() == k)
    }

    fn run(&mut self) -> PyResult<()> {
        // bucket the nodes by end address
        let recs = self.graph.with_store(|st| st.node_records())?;
        let mut end_to_node: OrderedMap<u64, usize> = OrderedMap::new();
        for (id, addr, size, fields) in recs {
            if fields.simprocedure_name.is_some() {
                continue;
            }
            let h = self.objs.len();
            self.objs.push(Obj {
                addr,
                size,
                fields,
                attached: Some(id),
            });
            self.by_id.insert(id, h);
            let end = self.objs[h].end();
            match end_to_node.get(&end) {
                None => {
                    end_to_node.insert(end, h);
                }
                Some(&first) => {
                    let list = self.end_to_nodes.get_or_insert_default(end);
                    if list.is_empty() {
                        list.push(first);
                    }
                    list.push(h);
                }
            }
        }
        for (&k, &h) in end_to_node.iter() {
            if !self.end_to_nodes.contains_key(&k) {
                self.smallest.insert(k, h);
            }
        }
        drop(end_to_node);

        while !self.end_to_nodes.is_empty() {
            let snapshot: Vec<u64> = self.end_to_nodes.keys().copied().collect();
            let mut progressed = false;
            for key in snapshot {
                let list = self.end_to_nodes.get_or_insert_default(key).clone();
                if list.len() <= 1 {
                    continue;
                }
                progressed = true;
                let mut all = list;
                all.sort_by(|&a, &b| self.objs[b].addr.cmp(&self.objs[a].addr));
                let smallest = all[0];
                let mut others: Vec<usize> = all[1..].to_vec();
                if self.objs[smallest].ins_len() > 0 {
                    others.retain(|&n| {
                        self.objs[n]
                            .ins_last_decoded()
                            .is_some_and(|a| self.objs[smallest].ins_contains(a))
                    });
                }
                if others.is_empty() {
                    self.end_to_nodes.shift_remove(&key);
                    continue;
                }
                self.normalize_core(smallest, &others)?;
                self.end_to_nodes.shift_remove(&key);
                self.smallest.insert(key, smallest);
                if self.end_to_nodes.is_empty() {
                    self.corner_case();
                }
            }
            if !progressed {
                return Err(PyRuntimeError::new_err("normalize() does not terminate"));
            }
        }
        self.graph.sync_jumpkinds(self.py)
    }

    fn normalize_core(&mut self, smallest: usize, others: &[usize]) -> PyResult<()> {
        for &n in others {
            let n_addr = self.objs[n].addr;
            let new_size =
                self.real_addr(self.objs[smallest].addr) as i64 - self.real_addr(n_addr) as i64;
            if new_size == 0 {
                continue;
            }
            let key = n_addr.wrapping_add(new_size as u64);

            let mut new_node = self
                .end_to_nodes
                .get(&key)
                .and_then(|l| l.iter().copied().find(|&i| self.objs[i].addr == n_addr));
            if new_node.is_none()
                && let Some(&s) = self.smallest.get(&key)
                && self.objs[s].addr == n_addr
            {
                new_node = Some(s);
            }
            let new_node = match new_node {
                Some(h) => h,
                None => {
                    let end = n_addr.wrapping_add(new_size as u64);
                    let mut ins: Vec<u64> = Vec::new();
                    for a in self.objs[n].ins_iter() {
                        if n_addr <= a && a < end {
                            ins.push(a);
                        } else if a == end {
                            break;
                        } else if a > end {
                            if ins.pop().is_none() {
                                return Err(PyIndexError::new_err("pop from empty list"));
                            }
                            break;
                        } else {
                            break;
                        }
                    }
                    let (ins_base, ins_sizes) = ins_from_addrs(&ins)?;
                    let fields = NodeFields {
                        func: self.objs[n].fields.func,
                        ins_base,
                        ins_sizes,
                        thumb: self.objs[n].fields.thumb,
                        is_syscall: false,
                        no_ret: Some(false),
                        bytes_mode: BYTES_NONE,
                        manual_bytes: None,
                        name: None,
                        simprocedure_name: None,
                    };
                    let h = self.objs.len();
                    self.objs.push(Obj {
                        addr: n_addr,
                        size: new_size,
                        fields,
                        attached: None,
                    });
                    if let Some(&s) = self.smallest.get(&key) {
                        let (sk, hk) = (self.objs[s].key(), self.objs[h].key());
                        let list = self.end_to_nodes.get_or_insert_default(key);
                        if !Self::contains_key(list, &self.objs, sk) {
                            list.push(s);
                        }
                        if !Self::contains_key(list, &self.objs, hk) {
                            list.push(h);
                        }
                    } else {
                        self.smallest.insert(key, h);
                    }
                    h
                }
            };

            let preds = self.edges(n, true)?;
            let pred_keys: Vec<Key> = self
                .graph
                .with_store(|st| preds.iter().map(|(p, _)| st.node_key(*p)).collect())?;
            let succs = self.edges(n, false)?;
            // `d is n`: the view of n's record is n itself while n is attached
            let n_id_then = self.objs[n].attached;
            if !self.in_graph(smallest)? {
                continue;
            }
            let smallest_addr = self.objs[smallest].addr;
            for (d, rec) in &succs {
                let ins_addr = rec.ins_addr_opt();
                if ins_addr.is_none() {
                    let jk = rec.jumpkind_code();
                    let is_fakeret = self.graph.with_store(|st| {
                        Ok(jk.and_then(|c| st.jumpkind_str(c)) == Some("Ijk_FakeRet"))
                    })?;
                    if !is_fakeret {
                        self.warnings.push((WARN_NO_INS_ADDR, n_addr, *d));
                    }
                }
                if let Some(a) = ins_addr
                    && a < smallest_addr
                {
                    continue;
                }
                let s_id = self
                    .id_of(smallest)?
                    .expect("smallest node is in the graph");
                if !self.graph.with_store(|st| st.has_edge(s_id, *d))? {
                    if n_id_then == Some(*d) {
                        let s = self.add_node(smallest)?;
                        let t = self.add_node(new_node)?;
                        self.add_edge_ids(s, t, rec)?;
                    } else {
                        let s = self.add_node(smallest)?;
                        self.add_edge_ids(s, *d, rec)?;
                    }
                }
            }
            for (p, _) in &preds {
                let n_id = self.id_of(n)?;
                let removed = match n_id {
                    Some(n_id) => self.graph.with_store(|st| st.remove_edge(*p, n_id))?,
                    None => false,
                };
                if !removed {
                    return Err(PyRuntimeError::new_err(
                        "normalize(): the edge to remove is not in the graph",
                    ));
                }
            }
            if self.in_graph(n)? {
                self.remove_node(n)?;
            }
            // model.remove_node() and model.add_node()
            self.remove_node(n)?;
            self.block_keys.push((n_addr, self.objs[new_node].key()));
            self.add_node(new_node)?;
            self.no_return.push(self.objs[new_node].addr);

            for ((p, rec), p_key) in preds.iter().zip(&pred_keys) {
                if !others.iter().any(|&o| self.objs[o].key() == *p_key) {
                    let t = self.add_node(new_node)?;
                    self.add_edge_ids(*p, t, rec)?;
                }
            }

            let nn = &self.objs[new_node];
            let ins_addr = if nn.ins_len() > 0 {
                nn.ins_last()
            } else {
                nn.addr
            };
            let src = self.add_node(new_node)?;
            let dst = self.add_node(smallest)?;
            self.graph.with_store(|st| {
                st.add_edge(
                    src,
                    dst,
                    PRESENT_JUMPKIND | PRESENT_INS_ADDR,
                    Some("Ijk_Boring"),
                    Some(ins_addr),
                    None,
                )
            })?;
        }
        self.groups.push((
            self.objs[smallest].addr,
            others.iter().map(|&o| self.objs[o].addr).collect(),
        ));
        Ok(())
    }

    /// Overlapping smallest nodes with different end addresses (blocks cut short by the VEX limits).
    fn corner_case(&mut self) {
        let mut lst: Vec<usize> = self.smallest.values().copied().collect();
        lst.sort_by_key(|&h| self.objs[h].addr);
        for i in 0..lst.len().saturating_sub(1) {
            let (node, next) = (lst[i], lst[i + 1]);
            let (na, ns) = self.objs[node].key();
            let nxa = self.objs[next].addr;
            if node != next && na <= nxa && (nxa as i128) < na as i128 + ns as i128 {
                let a = self.objs[node].end();
                let b = self.objs[next].end();
                if a == b {
                    self.warnings.push((WARN_OVERLAP, na, nxa));
                    continue;
                }
                if self.smallest.contains_key(&a) && self.smallest.contains_key(&b) {
                    let (nk, xk) = (self.objs[node].key(), self.objs[next].key());
                    let list = self.end_to_nodes.get_or_insert_default(a);
                    if !Self::contains_key(list, &self.objs, nk) {
                        list.push(node);
                    }
                    if !Self::contains_key(list, &self.objs, xk) {
                        list.push(next);
                    }
                }
                self.smallest.shift_remove(&a);
                self.smallest.shift_remove(&b);
            }
        }
    }
}

type NormalizeResult = (
    Vec<(u64, Key)>,
    Vec<u64>,
    Vec<(u64, Vec<u64>)>,
    Vec<(u8, u64, u64)>,
);

/// `CFGBase.normalize()` on a CfgGraph. `detach(id)` must detach the Python view of a record before Rust removes or
/// overwrites it. Returns the side-table updates, in order: `_blockid_to_blockkey` assignments `(block_id, key)`,
/// addresses to drop from `_block_addrs_with_return`, `(smallest node address, other node addresses)` of every
/// group for the jump-table and indirect-jump updates, and warnings `(kind, addr_a, addr_b)`.
#[pyfunction]
pub fn normalize_cfg_graph(
    py: Python<'_>,
    graph: &Bound<'_, CfgGraph>,
    detach: &Bound<'_, PyAny>,
    is_arm: bool,
) -> PyResult<NormalizeResult> {
    let mut n = Normalizer {
        py,
        graph: graph.get(),
        detach_cb: detach.clone(),
        is_arm,
        objs: Vec::new(),
        by_id: FxHashMap::default(),
        end_to_nodes: OrderedMap::new(),
        smallest: OrderedMap::new(),
        block_keys: Vec::new(),
        no_return: Vec::new(),
        groups: Vec::new(),
        warnings: Vec::new(),
    };
    n.run()?;
    Ok((n.block_keys, n.no_return, n.groups, n.warnings))
}

pub fn cfg_normalize(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(normalize_cfg_graph, m)?)?;
    Ok(())
}
