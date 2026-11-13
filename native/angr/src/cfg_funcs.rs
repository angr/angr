//! `CFGBase.make_functions` in Rust.
//!
//! `FunctionsBuilder` (`angr.rustylib.cfg_funcs.FunctionsBuilder`) rebuilds the functions of a CFG from the
//! `CfgGraph` and the scan-time `RecoveryFunctions` store: the block-to-function map, `_addr_to_funcaddr`, the
//! traversal of `_graph_bfs_custom` / `_graph_traversal_handler` and the `FunctionManager._add_*` calls it makes.
//! The new functions are records of a private `RecoveryFunctions` store (graphs, flags, callgraph, all with the
//! mutation semantics of `Function` and `FunctionManager`). `finish` hands them to Python in creation order, so
//! Python can create the `Function` objects in one bulk call and fill the networkx callgraph.

use std::collections::VecDeque;

use indexmap::IndexMap;
use pyo3::exceptions::{PyKeyError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PySet};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::cfg_graph::{CfgGraph, EdgeRec, FLAG_SYSCALL, FLAG_THUMB};
use crate::cfg_scan::LoaderSnapshot;
use crate::function_graph::{FunctionGraph, NodeKind};
use crate::recovery_functions::{
    CG_CALL, CG_EXCEPTION, CG_FAKERET, CG_TRANSITION, InfoValue, NodeSpec, RecoveryFunctions,
};

type Key = (u64, i64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Jk {
    Call,
    Sys,
    Ret,
    /// Ijk_Boring, Ijk_InvalICache, Ijk_Privileged
    Boring,
    Exception,
    FakeRet,
    Other,
    /// absent or None: the Python handler raises on these
    Missing,
}

impl Jk {
    fn of(s: Option<&str>) -> Jk {
        match s {
            None => Jk::Missing,
            Some("Ijk_Call") => Jk::Call,
            Some("Ijk_Ret") => Jk::Ret,
            Some("Ijk_Boring" | "Ijk_InvalICache" | "Ijk_Privileged") => Jk::Boring,
            Some("Ijk_Exception") => Jk::Exception,
            Some("Ijk_FakeRet") => Jk::FakeRet,
            Some(s) if s.starts_with("Ijk_Sys") => Jk::Sys,
            Some(_) => Jk::Other,
        }
    }
}

#[derive(Clone, Copy)]
struct OutEdge {
    dst: u64,
    dst_addr: u64,
    jk: Jk,
    ins_addr: Option<u64>,
    stmt_idx: Option<i64>,
}

/// A node argument of the `FunctionManager._add_*` calls: a node spec, or a bare address that Python turns into a
/// snippet.
#[derive(Clone, Copy)]
enum Snip {
    Spec(NodeSpec),
    Addr(u64),
}

/// `(addr, size, flags, instruction count, has a simprocedure name)`
type Brief = (u64, i64, u16, usize, bool);

#[pyclass(module = "angr.rustylib.cfg_funcs")]
pub struct FunctionsBuilder {
    graph: Py<CfgGraph>,
    /// the scan-time functions (`known_functions`); read only
    known: Py<RecoveryFunctions>,
    /// the new functions
    store: Py<RecoveryFunctions>,
    /// new function addresses in creation order
    order: Vec<u64>,
    /// `is_plt` copied from a known function
    is_plt: FxHashMap<u64, bool>,
    /// `info` copies, in the order they were made
    info_events: Vec<(u64, IndexMap<String, InfoValue>)>,
    /// names of functions created through `new_function` (hooks and syscalls); others have default names
    names: FxHashMap<u64, String>,
    b2f: FxHashMap<u64, u64>,
    traversed: FxHashSet<u64>,
    updated_nonreturning: Vec<u64>,
    /// hooked address -> length of the hook node
    hooks: FxHashMap<u64, u32>,
    syscall_from: Option<u64>,
    syscall_cache: FxHashMap<u64, bool>,
    is_syscall_addr: Py<PyAny>,
    /// `new_function(addr) -> (is_syscall, is_simprocedure, returning, name)`, for hooks and syscalls
    new_function: Py<PyAny>,
    /// `snippet(addr, size, thumb, mode) -> spec | None` for the snippets Rust does not build; `mode` is one of the
    /// `SNIP_*` constants
    snippet: Py<PyAny>,
    snapshot: Option<Py<LoaderSnapshot>>,
    /// `CFGBase._addrs_belong_to_same_section` when there is no snapshot
    same_section: Py<PyAny>,
    is_arm: bool,
    skip_unmapped_addrs: bool,
    jk_cache: Vec<Option<Jk>>,
    tail_calls: Vec<u64>,
}

/// `CFGBase._to_snippet(addr=..., size=..., thumb=..., base_state=...)`
const SNIP_CFG: u8 = 0;
/// the same, None on SimEngineError
const SNIP_CFG_MAY_FAIL: u8 = 1;
/// `project.factory.snippet(addr)` (a bare address passed to `FunctionManager._add_*`)
const SNIP_FM: u8 = 2;
/// the same, None on SimEngineError
const SNIP_FM_MAY_FAIL: u8 = 3;

impl FunctionsBuilder {
    // --- CFG queries ----------------------------------------------------------------------------

    fn brief(&self, py: Python<'_>, id: u64) -> PyResult<Brief> {
        self.graph.bind(py).get().with_store(|s| s.node_brief(id))
    }

    fn find_node(&self, py: Python<'_>, key: Key) -> PyResult<Option<u64>> {
        self.graph
            .bind(py)
            .get()
            .with_store(|s| s.find_node(key.0, key.1))
    }

    /// `model.get_any_node(addr, is_syscall=..., force_fastpath=True)`
    fn any_node(
        &self,
        py: Python<'_>,
        addr: u64,
        is_syscall: Option<bool>,
    ) -> PyResult<Option<u64>> {
        self.graph.bind(py).get().with_store(|s| match is_syscall {
            None => s.first_node_at_addr(addr),
            Some(want) => {
                for id in s.nodes_at_addr(addr)? {
                    if (s.node_flags(id)? & FLAG_SYSCALL != 0) == want {
                        return Ok(Some(id));
                    }
                }
                Ok(None)
            }
        })
    }

    fn has_node_addr(&self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        self.graph.bind(py).get().with_store(|s| s.has_addr(addr))
    }

    fn jk_of(&mut self, py: Python<'_>, rec: &EdgeRec) -> PyResult<Jk> {
        let Some(code) = rec.jumpkind_code() else {
            return Ok(Jk::Missing);
        };
        if let Some(Some(jk)) = self.jk_cache.get(code as usize) {
            return Ok(*jk);
        }
        let jk = self
            .graph
            .bind(py)
            .get()
            .with_store(|s| Ok(Jk::of(s.jumpkind_str(code))))?;
        if code != u16::MAX {
            let i = code as usize;
            if self.jk_cache.len() <= i {
                self.jk_cache.resize(i + 1, None);
            }
            self.jk_cache[i] = Some(jk);
        }
        Ok(jk)
    }

    fn out_edges(&mut self, py: Python<'_>, id: u64) -> PyResult<Vec<OutEdge>> {
        let recs = self.graph.bind(py).get().with_store(|s| {
            let mut out = Vec::new();
            for (dst, rec) in s.out_edges_rec(id)? {
                out.push((dst, s.node_key(dst)?.0, rec));
            }
            Ok(out)
        })?;
        let mut out = Vec::with_capacity(recs.len());
        for (dst, dst_addr, rec) in recs {
            out.push(OutEdge {
                dst,
                dst_addr,
                jk: self.jk_of(py, &rec)?,
                ins_addr: rec.ins_addr_opt(),
                stmt_idx: rec.stmt_idx_opt(),
            });
        }
        Ok(out)
    }

    fn is_syscall_addr(&mut self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        match self.syscall_from {
            Some(from) if addr >= from => {}
            _ => return Ok(false),
        }
        if let Some(&v) = self.syscall_cache.get(&addr) {
            return Ok(v);
        }
        let v: bool = self.is_syscall_addr.call1(py, (addr,))?.extract(py)?;
        self.syscall_cache.insert(addr, v);
        Ok(v)
    }

    fn same_section(&self, py: Python<'_>, a: u64, b: u64) -> PyResult<bool> {
        match &self.snapshot {
            Some(snap) => Ok(snap.bind(py).get().inner.addrs_belong_to_same_section(a, b)),
            None => self.same_section.call1(py, (a, b))?.extract(py),
        }
    }

    fn size_u32(size: i64) -> PyResult<u32> {
        u32::try_from(size).map_err(|_| PyValueError::new_err(format!("invalid block size {size}")))
    }

    /// `CFGBase._to_snippet(cfg_node=n)`
    fn snippet_of_node(&mut self, py: Python<'_>, id: u64) -> PyResult<Snip> {
        let (addr, size, flags, _, has_sp) = self.brief(py, id)?;
        if let Some(&len) = self.hooks.get(&addr) {
            return Ok(Snip::Spec((NodeKind::Hook, addr, len, false)));
        }
        let thumb = flags & FLAG_THUMB != 0;
        if !has_sp && flags & FLAG_SYSCALL == 0 {
            return Ok(Snip::Spec((
                NodeKind::Block,
                addr,
                Self::size_u32(size)?,
                thumb,
            )));
        }
        self.snip(py, addr, Some(size), thumb, SNIP_CFG)
            .map(Snip::Spec)
    }

    /// `CFGBase._node_key_to_snippet(key)`
    fn snippet_of_key(&mut self, py: Python<'_>, key: Key) -> PyResult<Snip> {
        let (addr, size) = key;
        if let Some(&len) = self.hooks.get(&addr) {
            return Ok(Snip::Spec((NodeKind::Hook, addr, len, false)));
        }
        let thumb = self.is_arm && addr % 2 == 1;
        if self.is_syscall_addr(py, addr)? {
            return self
                .snip(py, addr, Some(size), thumb, SNIP_CFG)
                .map(Snip::Spec);
        }
        Ok(Snip::Spec((
            NodeKind::Block,
            addr,
            Self::size_u32(size)?,
            thumb,
        )))
    }

    /// `model.get_any_node(addr)` converted with `_to_snippet`, or the bare address
    fn snippet_at(&mut self, py: Python<'_>, addr: u64) -> PyResult<Snip> {
        match self.any_node(py, addr, None)? {
            Some(id) => self.snippet_of_node(py, id),
            None => Ok(Snip::Addr(addr)),
        }
    }

    fn call_snippet(
        &self,
        py: Python<'_>,
        addr: u64,
        size: Option<i64>,
        thumb: bool,
        mode: u8,
    ) -> PyResult<Option<NodeSpec>> {
        self.snippet
            .call1(py, (addr, size, thumb, mode))?
            .extract::<Option<NodeSpec>>(py)
    }

    /// `call_snippet` in a mode that raises instead of returning None.
    fn snip(
        &self,
        py: Python<'_>,
        addr: u64,
        size: Option<i64>,
        thumb: bool,
        mode: u8,
    ) -> PyResult<NodeSpec> {
        self.call_snippet(py, addr, size, thumb, mode)?
            .ok_or_else(|| PyRuntimeError::new_err("snippet() returned None"))
    }

    /// The spec of a node argument; a bare address becomes `project.factory.snippet(addr)`.
    fn resolve(&self, py: Python<'_>, s: Snip) -> PyResult<NodeSpec> {
        match s {
            Snip::Spec(spec) => Ok(spec),
            Snip::Addr(a) => self.snip(py, a, None, false, SNIP_FM),
        }
    }

    // --- the new function manager ---------------------------------------------------------------

    fn has_func(&self, py: Python<'_>, addr: u64) -> bool {
        self.store.borrow(py).funcs.contains_key(&addr)
    }

    /// Creates the function as `Function(function_manager, addr)` would.
    fn create_func(&mut self, py: Python<'_>, addr: u64) -> PyResult<()> {
        let special = self.hooks.contains_key(&addr) || self.is_syscall_addr(py, addr)?;
        let (is_syscall, is_simprocedure, returning, name) = if special {
            let (a, b, c, d): (bool, bool, Option<bool>, String) =
                self.new_function.call1(py, (addr,))?.extract(py)?;
            (a, b, c, Some(d))
        } else {
            (false, false, None, None)
        };
        let mut st = self.store.bind(py).borrow_mut();
        st.create_record(py, addr)?;
        let rec = st.rec_mut(addr)?;
        rec.is_syscall = is_syscall;
        rec.is_simprocedure = is_simprocedure;
        rec.returning = returning;
        drop(st);
        if let Some(name) = name {
            self.names.insert(addr, name);
        }
        self.order.push(addr);
        Ok(())
    }

    /// `function_map[addr]`: get or create
    fn ensure_func(&mut self, py: Python<'_>, addr: u64) -> PyResult<()> {
        if !self.has_func(py, addr) {
            self.create_func(py, addr)?;
        }
        Ok(())
    }

    /// `FunctionManager.function(addr, create=True, syscall=syscall)`
    fn function_create(&mut self, py: Python<'_>, addr: u64, syscall: bool) -> PyResult<()> {
        if self.has_func(py, addr) {
            return Ok(());
        }
        self.create_func(py, addr)?;
        if syscall {
            self.store.bind(py).borrow_mut().rec_mut(addr)?.is_syscall = true;
        }
        Ok(())
    }

    fn returning(&self, py: Python<'_>, addr: u64) -> PyResult<Option<bool>> {
        Ok(self.store.borrow(py).rec(addr)?.returning)
    }

    fn set_returning_true(&self, py: Python<'_>, addr: u64) -> PyResult<()> {
        self.store.bind(py).borrow_mut().rec_mut(addr)?.returning = Some(true);
        Ok(())
    }

    fn is_local(&self, py: Python<'_>, func: u64, addr: u64) -> PyResult<bool> {
        let st = self.store.borrow(py);
        Ok(st.rec(func)?.graph.borrow(py).is_local(addr))
    }

    /// `FunctionManager._add_node`
    fn add_node(
        &mut self,
        py: Python<'_>,
        func: u64,
        node: Snip,
        syscall: Option<bool>,
    ) -> PyResult<()> {
        let spec = self.resolve(py, node)?;
        self.ensure_func(py, func)?;
        let mut st = self.store.bind(py).borrow_mut();
        if let Some(s) = syscall {
            st.rec_mut(func)?.is_syscall = s;
        }
        st.ops(py, func)?.register(true, spec);
        Ok(())
    }

    /// `FunctionManager._add_return_from`
    fn add_return_from(&mut self, py: Python<'_>, func: u64, node: Snip) -> PyResult<()> {
        let spec = self.resolve(py, node)?;
        let mut st = self.store.bind(py).borrow_mut();
        st.ops(py, func)?.add_return_site(spec);
        Ok(())
    }

    /// `FunctionManager._add_call_to`
    #[allow(clippy::too_many_arguments)]
    fn add_call_to(
        &mut self,
        py: Python<'_>,
        func: u64,
        from: NodeSpec,
        to_addr: u64,
        retn: Option<NodeSpec>,
        syscall: bool,
        stmt_idx: Option<i64>,
        ins_addr: Option<u64>,
        return_to_outside: bool,
    ) -> PyResult<()> {
        self.function_create(py, to_addr, syscall)?;
        self.ensure_func(py, func)?;
        let mut st = self.store.bind(py).borrow_mut();
        {
            let mut ops = st.ops(py, func)?;
            ops.g
                .add_call_site(from.1, Some(to_addr), retn.map(|n| n.1));
            ops.call_to(
                from,
                (NodeKind::Func, to_addr, 0, false),
                retn,
                stmt_idx,
                ins_addr,
                return_to_outside,
                syscall,
            );
            if return_to_outside {
                ops.add_retout_site(from);
            }
        }
        st.callgraph.add_edge(func, to_addr, CG_CALL);
        Ok(())
    }

    /// `FunctionManager._add_fakeret_to`
    #[allow(clippy::too_many_arguments)]
    fn add_fakeret_to(
        &mut self,
        py: Python<'_>,
        func: u64,
        from: Snip,
        to: Snip,
        confirmed: Option<bool>,
        to_outside: bool,
        to_function_addr: Option<u64>,
    ) -> PyResult<()> {
        let from = self.resolve(py, from)?;
        let to = self.resolve(py, to)?;
        let mut st = self.store.bind(py).borrow_mut();
        st.ops(py, func)?
            .fakeret_to(from, to, confirmed, to_outside);
        if to_outside && let Some(t) = to_function_addr {
            st.callgraph.add_edge(func, t, CG_FAKERET);
        }
        Ok(())
    }

    /// `FunctionManager._add_transition_to`
    #[allow(clippy::too_many_arguments)]
    fn add_transition_to(
        &mut self,
        py: Python<'_>,
        func: u64,
        from: Snip,
        to: Snip,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        is_exception: bool,
    ) -> PyResult<()> {
        let from = self.resolve(py, from)?;
        let to = self.resolve(py, to)?;
        let mut st = self.store.bind(py).borrow_mut();
        st.ops(py, func)?
            .transit_to(from, Some(to), false, ins_addr, stmt_idx, is_exception);
        Ok(())
    }

    /// `FunctionManager._add_outside_transition_to`
    #[allow(clippy::too_many_arguments)]
    fn add_outside_transition_to(
        &mut self,
        py: Python<'_>,
        func: u64,
        from: Snip,
        to: Snip,
        to_function_addr: Option<u64>,
        ins_addr: Option<u64>,
        stmt_idx: Option<i64>,
        is_exception: bool,
    ) -> PyResult<()> {
        let from = self.resolve(py, from)?;
        let to = match to {
            Snip::Spec(s) => Some(s),
            Snip::Addr(a) => self.call_snippet(py, a, None, false, SNIP_FM_MAY_FAIL)?,
        };
        let mut st = self.store.bind(py).borrow_mut();
        {
            let mut ops = st.ops(py, func)?;
            let Some(to) = to else {
                ops.add_jumpout_site(from);
                return Ok(());
            };
            ops.transit_to(from, Some(to), true, ins_addr, stmt_idx, is_exception);
        }
        if let Some(t) = to_function_addr {
            st.callgraph.add_edge(
                func,
                t,
                if is_exception {
                    CG_EXCEPTION
                } else {
                    CG_TRANSITION
                },
            );
        }
        Ok(())
    }

    /// Copies `is_plt`, `info` and a True `returning` of a known function; returns whether it was returning.
    fn copy_known_meta(&mut self, py: Python<'_>, addr: u64) -> PyResult<bool> {
        let (is_plt, info, returning) = {
            let known = self.known.borrow(py);
            let Some(k) = known.funcs.get(&addr) else {
                return Ok(false);
            };
            let info: IndexMap<String, InfoValue> = k
                .info
                .iter()
                .map(|(key, v)| {
                    let v = match v {
                        InfoValue::Other(o) => InfoValue::Other(o.clone_ref(py)),
                        other => other.clone(),
                    };
                    (key.clone(), v)
                })
                .collect();
            (k.is_plt, info, k.returning == Some(true))
        };
        self.store.bind(py).borrow_mut().rec_mut(addr)?.is_plt = is_plt;
        self.is_plt.insert(addr, is_plt);
        self.info_events.push((addr, info));
        if returning {
            self.set_returning_true(py, addr)?;
        }
        Ok(returning)
    }

    fn known_contains(&self, py: Python<'_>, addr: u64) -> bool {
        self.known.borrow(py).funcs.contains_key(&addr)
    }

    /// `CFGBase._addr_to_funcaddr`
    fn addr_to_funcaddr_impl(&mut self, py: Python<'_>, addr: u64) -> PyResult<u64> {
        if let Some(&f) = self.b2f.get(&addr) {
            return Ok(f);
        }
        let is_syscall = self.is_syscall_addr(py, addr)?;
        let node = match self.any_node(py, addr, Some(is_syscall))? {
            Some(id) => self.snippet_of_node(py, id)?,
            None => Snip::Addr(addr),
        };
        self.add_node(py, addr, node, Some(is_syscall))?;
        let returning = self.copy_known_meta(py, addr)?;
        self.b2f.insert(addr, addr);
        if !returning {
            self.updated_nonreturning.push(addr);
        }
        Ok(addr)
    }

    fn name_of(&self, addr: u64) -> Option<&str> {
        self.names.get(&addr).map(String::as_str)
    }

    // --- the traversal ------------------------------------------------------------------------

    /// `CFGBase._graph_bfs_custom` from one start node.
    fn bfs(&mut self, py: Python<'_>, start: u64, has_return: &FxHashSet<u64>) -> PyResult<()> {
        let mut queue: VecDeque<u64> = VecDeque::from([start]);
        let mut queued: FxHashSet<u64> = FxHashSet::from_iter([start]);
        while let Some(id) = queue.pop_front() {
            queued.remove(&id);
            if !self.traversed.insert(id) {
                continue;
            }
            let (addr, size, ..) = self.brief(py, id)?;
            let key = (addr, size);
            if has_return.contains(&addr) {
                self.handle(py, key, None, Some(Jk::Ret), &[])?;
            }
            let edges = self.out_edges(py, id)?;
            if edges.is_empty() {
                self.handle(py, key, None, None, &[])?;
                continue;
            }
            for e in &edges {
                self.handle(py, key, Some(e), Some(e.jk), &edges)?;
                if !matches!(e.jk, Jk::Call | Jk::Ret | Jk::Sys)
                    && !queued.contains(&e.dst)
                    && !self.traversed.contains(&e.dst)
                {
                    queue.push_back(e.dst);
                    queued.insert(e.dst);
                }
            }
        }
        Ok(())
    }

    /// `CFGBase._graph_traversal_handler`; `jk` is None for a lone node.
    fn handle(
        &mut self,
        py: Python<'_>,
        src_key: Key,
        edge: Option<&OutEdge>,
        jk: Option<Jk>,
        all_edges: &[OutEdge],
    ) -> PyResult<()> {
        let src_addr = src_key.0;
        let src_func = self.addr_to_funcaddr_impl(py, src_addr)?;

        if !self.is_local(py, src_func, src_addr)? {
            let node = self.snippet_at(py, src_addr)?;
            self.add_node(py, src_func, node, None)?;
        }

        let Some(jk) = jk else {
            return Ok(());
        };
        if jk == Jk::Missing {
            return Err(PyKeyError::new_err("jumpkind"));
        }
        if jk == Jk::Ret {
            let node = self.snippet_at(py, src_addr)?;
            self.add_return_from(py, src_func, node)?;
        }
        let Some(edge) = edge else {
            return Ok(());
        };
        let dst_addr = edge.dst_addr;
        let ins_addr = edge.ins_addr;
        let stmt_idx = edge.stmt_idx;

        match jk {
            Jk::Call | Jk::Sys => {
                let is_syscall = jk == Jk::Sys;
                let dst_func = self.addr_to_funcaddr_impl(py, dst_addr)?;
                let dst_returning = self.returning(py, dst_func)?;
                let src_snippet = if !self.has_node_addr(py, src_addr)? {
                    self.snip(py, src_addr, None, false, SNIP_CFG)?
                } else {
                    let s = self.snippet_of_key(py, src_key)?;
                    self.resolve(py, s)?
                };
                let fakeret_dst = if all_edges.is_empty()
                    || (dst_returning == Some(false)
                        && self.name_of(dst_func) != Some("UnresolvableCallTarget"))
                {
                    None
                } else {
                    all_edges
                        .iter()
                        .find(|e| e.jk == Jk::FakeRet)
                        .map(|e| e.dst)
                };
                let mut return_to_outside = false;
                let mut returning_snippet: Option<NodeSpec> = None;
                if dst_returning == Some(true) && fakeret_dst.is_some() {
                    let returning_target = (src_addr as i128 + src_key.1 as i128) as u64;
                    if !self.b2f.contains_key(&returning_target) {
                        if !self.known_contains(py, returning_target) {
                            self.b2f.insert(returning_target, src_func);
                        } else {
                            self.addr_to_funcaddr_impl(py, returning_target)?;
                        }
                    }
                    return_to_outside = self.b2f[&returning_target] != src_func;
                    returning_snippet = match self.any_node(py, returning_target, None)? {
                        None => {
                            self.call_snippet(py, returning_target, None, false, SNIP_CFG_MAY_FAIL)?
                        }
                        Some(id) => {
                            let s = self.snippet_of_node(py, id)?;
                            Some(self.resolve(py, s)?)
                        }
                    };
                }
                self.add_call_to(
                    py,
                    src_func,
                    src_snippet,
                    dst_addr,
                    returning_snippet,
                    is_syscall,
                    stmt_idx,
                    ins_addr,
                    return_to_outside,
                )?;
                if let Some(r) = returning_snippet {
                    self.add_fakeret_to(
                        py,
                        src_func,
                        Snip::Spec(src_snippet),
                        Snip::Spec(r),
                        Some(true),
                        return_to_outside,
                        None,
                    )?;
                }
            }
            Jk::Boring | Jk::Exception => {
                let is_exception = jk == Jk::Exception;
                let src_node = if !self.has_node_addr(py, src_addr)? {
                    Snip::Addr(src_addr)
                } else {
                    self.snippet_of_key(py, src_key)?
                };
                let dst_key = self
                    .graph
                    .bind(py)
                    .get()
                    .with_store(|s| s.node_key(edge.dst))?;
                let dst_node = if !self.has_node_addr(py, dst_addr)? {
                    Snip::Addr(dst_addr)
                } else {
                    self.snippet_of_key(py, dst_key)?
                };
                if self.skip_unmapped_addrs && !self.same_section(py, src_addr, dst_addr)? {
                    self.addr_to_funcaddr_impl(py, dst_addr)?;
                }
                if self.b2f.get(&dst_addr) == Some(&dst_addr) {
                    // a tail call: detect_tail_calls is handled in Python
                    self.addr_to_funcaddr_impl(py, dst_addr)?;
                    self.add_outside_transition_to(
                        py,
                        src_func,
                        src_node,
                        dst_node,
                        Some(dst_addr),
                        None,
                        None,
                        false,
                    )?;
                    self.tail_calls.push(dst_addr);
                }
                let is_known = self.known_contains(py, dst_addr);
                let b2f_dst = self.b2f.get(&dst_addr).copied();
                if (is_known && dst_addr != src_func) || b2f_dst.is_some_and(|f| f != src_func) {
                    let dst_function_addr = b2f_dst.unwrap_or(dst_addr);
                    self.add_outside_transition_to(
                        py,
                        src_func,
                        src_node,
                        dst_node,
                        Some(dst_function_addr),
                        ins_addr,
                        stmt_idx,
                        is_exception,
                    )?;
                    self.addr_to_funcaddr_impl(py, dst_addr)?;
                } else {
                    self.b2f.entry(dst_addr).or_insert(src_func);
                    self.add_transition_to(
                        py,
                        src_func,
                        src_node,
                        dst_node,
                        ins_addr,
                        stmt_idx,
                        is_exception,
                    )?;
                }
            }
            Jk::FakeRet => {
                let src_node = self.snippet_at(py, src_addr)?;
                let dst_node = self.snippet_at(py, dst_addr)?;
                let target_func = match self.b2f.get(&dst_addr) {
                    Some(&f) => f,
                    None => {
                        if !self.known_contains(py, dst_addr) {
                            self.b2f.insert(dst_addr, src_func);
                            src_func
                        } else {
                            self.addr_to_funcaddr_impl(py, dst_addr)?
                        }
                    }
                };
                let mut called: Option<u64> = None;
                for e in all_edges {
                    if e.jk == Jk::Call && self.b2f.contains_key(&e.dst_addr) {
                        self.function_create(py, e.dst_addr, false)?;
                        called = Some(e.dst_addr);
                        break;
                    }
                }
                let called_returning = match called {
                    Some(c) => self.returning(py, c)?,
                    None => None,
                };
                if called.is_some() && called_returning == Some(false) {
                    return Ok(());
                }
                let to_outside = target_func != src_func;
                let confirmed = called.is_none() || called_returning == Some(true);
                self.add_fakeret_to(
                    py,
                    src_func,
                    src_node,
                    dst_node,
                    Some(confirmed),
                    to_outside,
                    called,
                )?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[pymethods]
impl FunctionsBuilder {
    #[new]
    #[pyo3(signature = (graph, known, hooks, syscall_from, is_syscall_addr, new_function, snippet, snapshot,
                        same_section, is_arm, skip_unmapped_addrs))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        graph: Py<CfgGraph>,
        known: Py<RecoveryFunctions>,
        hooks: FxHashMap<u64, u32>,
        syscall_from: Option<u64>,
        is_syscall_addr: Py<PyAny>,
        new_function: Py<PyAny>,
        snippet: Py<PyAny>,
        snapshot: Option<Py<LoaderSnapshot>>,
        same_section: Py<PyAny>,
        is_arm: bool,
        skip_unmapped_addrs: bool,
    ) -> PyResult<Self> {
        Ok(FunctionsBuilder {
            graph,
            known,
            store: Py::new(py, RecoveryFunctions::new())?,
            order: Vec::new(),
            is_plt: FxHashMap::default(),
            info_events: Vec::new(),
            names: FxHashMap::default(),
            b2f: FxHashMap::default(),
            traversed: FxHashSet::default(),
            updated_nonreturning: Vec::new(),
            hooks,
            syscall_from,
            syscall_cache: FxHashMap::default(),
            is_syscall_addr,
            new_function,
            snippet,
            snapshot,
            same_section,
            is_arm,
            skip_unmapped_addrs,
            jk_cache: Vec::new(),
            tail_calls: Vec::new(),
        })
    }

    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        visit.call(&self.graph)?;
        visit.call(&self.known)?;
        visit.call(&self.store)?;
        visit.call(&self.is_syscall_addr)?;
        visit.call(&self.new_function)?;
        visit.call(&self.snippet)?;
        visit.call(&self.same_section)?;
        if let Some(s) = &self.snapshot {
            visit.call(s)?;
        }
        for (_, info) in &self.info_events {
            for v in info.values() {
                if let InfoValue::Other(o) = v {
                    visit.call(o)?;
                }
            }
        }
        Ok(())
    }

    // --- blockaddr_to_funcaddr as a mapping, for the Python helpers -------------------------------

    fn __contains__(&self, addr: u64) -> bool {
        self.b2f.contains_key(&addr)
    }

    fn __getitem__(&self, addr: u64) -> PyResult<u64> {
        self.b2f
            .get(&addr)
            .copied()
            .ok_or_else(|| PyKeyError::new_err(addr))
    }

    fn __setitem__(&mut self, addr: u64, func: u64) {
        self.b2f.insert(addr, func);
    }

    fn __delitem__(&mut self, addr: u64) -> PyResult<()> {
        self.b2f
            .remove(&addr)
            .map(|_| ())
            .ok_or_else(|| PyKeyError::new_err(addr))
    }

    fn __len__(&self) -> usize {
        self.b2f.len()
    }

    #[pyo3(signature = (addr, default=None))]
    fn get(&self, addr: u64, default: Option<u64>) -> Option<u64> {
        self.b2f.get(&addr).copied().or(default)
    }

    // --- make_functions steps ----------------------------------------------------------------------

    /// `CFGBase._addr_to_funcaddr(addr, blockaddr_to_funcaddr, known_functions)`
    fn addr_to_funcaddr(&mut self, py: Python<'_>, addr: u64) -> PyResult<u64> {
        self.addr_to_funcaddr_impl(py, addr)
    }

    /// The loop over `predetermined_function_addrs` in `make_functions`, for one address.
    fn add_predetermined(&mut self, py: Python<'_>, addr: u64) -> PyResult<()> {
        self.function_create(py, addr, false)?;
        if self.known_contains(py, addr) {
            self.copy_known_meta(py, addr)?;
        }
        self.b2f.insert(addr, addr);
        if self.returning(py, addr)? != Some(true) {
            self.updated_nonreturning.push(addr);
        }
        Ok(())
    }

    /// `_graph_bfs_custom` from each start key in turn. `has_return` is `model._block_addrs_with_return`;
    /// `progress(i)` is called before each start when given.
    #[pyo3(signature = (starts, has_return, progress=None))]
    fn traverse(
        &mut self,
        py: Python<'_>,
        starts: Vec<Key>,
        has_return: &Bound<'_, PySet>,
        progress: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let mut ret: FxHashSet<u64> = FxHashSet::default();
        for a in has_return.iter() {
            if let Ok(a) = a.extract::<u64>() {
                ret.insert(a);
            }
        }
        for (i, key) in starts.into_iter().enumerate() {
            if let Some(p) = &progress {
                p.call1(py, (i,))?;
            }
            let id = self
                .find_node(py, key)?
                .ok_or_else(|| PyKeyError::new_err(format!("no CFG node {key:?}")))?;
            self.bfs(py, id, &ret)?;
        }
        Ok(())
    }

    /// The secondary start nodes of `make_functions`, sorted by address: the first node of every known function
    /// whose address is not mapped yet, and every untraversed node that has a function address. Returns
    /// `(keys, ambiguous)`; `ambiguous` is True when two of them share an address, so that their order depends on
    /// Python's set order and the caller must compute it.
    fn secondary_starts(&self, py: Python<'_>) -> PyResult<(Vec<Key>, bool)> {
        let known_addrs: Vec<u64> = self.known.borrow(py).funcs.keys().copied().collect();
        let traversed = &self.traversed;
        let b2f = &self.b2f;
        let mut ids: Vec<(u64, i64, u64)> = self.graph.bind(py).get().with_store(|s| {
            let mut seen: FxHashSet<u64> = FxHashSet::default();
            let mut out = Vec::new();
            for a in known_addrs {
                if let Some(id) = s.first_node_at_addr(a)? {
                    let (addr, size) = s.node_key(id)?;
                    if !b2f.contains_key(&addr) && seen.insert(id) {
                        out.push((addr, size, id));
                    }
                }
            }
            for id in s.nodes() {
                if traversed.contains(&id) || s.node_func(id)?.is_none() {
                    continue;
                }
                if seen.insert(id) {
                    let (addr, size) = s.node_key(id)?;
                    out.push((addr, size, id));
                }
            }
            Ok(out)
        })?;
        ids.sort_by_key(|&(a, s, _)| (a, s));
        let ambiguous = ids.windows(2).any(|w| w[0].0 == w[1].0);
        Ok((ids.into_iter().map(|(a, s, _)| (a, s)).collect(), ambiguous))
    }

    /// Keys of the CFG nodes, in node order, whose address is a known function or in `removed`.
    fn function_node_keys(&self, py: Python<'_>, removed: FxHashSet<u64>) -> PyResult<Vec<Key>> {
        let known = self.known.borrow(py);
        self.graph.bind(py).get().with_store(|s| {
            Ok(s.node_keys()?
                .into_iter()
                .filter(|(a, _)| known.funcs.contains_key(a) || removed.contains(a))
                .collect())
        })
    }

    /// Addresses of the new functions that have no startpoint, in creation order.
    fn empty_functions(&self, py: Python<'_>) -> PyResult<Vec<u64>> {
        let st = self.store.borrow(py);
        let mut out = Vec::new();
        for &addr in &self.order {
            if st.rec(addr)?.graph.borrow(py).get_startpoint().is_none() {
                out.push(addr);
            }
        }
        Ok(out)
    }

    /// Keys of the traversed nodes.
    fn traversed_keys(&self, py: Python<'_>) -> PyResult<Vec<Key>> {
        let ids: Vec<u64> = self.traversed.iter().copied().collect();
        self.graph
            .bind(py)
            .get()
            .with_store(|s| ids.iter().map(|&id| s.node_key(id)).collect())
    }

    fn updated_nonreturning(&self) -> Vec<u64> {
        self.updated_nonreturning.clone()
    }

    fn tail_calls(&self) -> Vec<u64> {
        self.tail_calls.clone()
    }

    /// The new functions in creation order:
    /// `[(addr, graph, is_syscall, is_simprocedure, is_plt or None, returning)]`, and the `info` copies in the
    /// order they were made: `[(addr, info dict)]`.
    #[allow(clippy::type_complexity)]
    fn functions<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(
        Vec<(
            u64,
            Py<FunctionGraph>,
            bool,
            bool,
            Option<bool>,
            Option<bool>,
        )>,
        Vec<(u64, Bound<'py, PyDict>)>,
    )> {
        let st = self.store.borrow(py);
        let mut funcs = Vec::with_capacity(self.order.len());
        for &addr in &self.order {
            let r = st.rec(addr)?;
            funcs.push((
                addr,
                r.graph.clone_ref(py),
                r.is_syscall,
                r.is_simprocedure,
                self.is_plt.get(&addr).copied(),
                r.returning,
            ));
        }
        let mut infos = Vec::with_capacity(self.info_events.len());
        for (addr, info) in &self.info_events {
            let d = PyDict::new(py);
            for (k, v) in info {
                d.set_item(k, v.to_py(py)?)?;
            }
            infos.push((*addr, d));
        }
        Ok((funcs, infos))
    }

    /// Fills an empty networkx MultiDiGraph with the callgraph, with the node, adjacency and key order that
    /// `FunctionManager`'s `add_node`/`add_edge` calls would have given.
    fn fill_callgraph(&self, py: Python<'_>, callgraph: &Bound<'_, PyAny>) -> PyResult<()> {
        let node_d = callgraph.getattr("_node")?.cast_into::<PyDict>()?;
        let succ_d = callgraph.getattr("_succ")?.cast_into::<PyDict>()?;
        let pred_d = callgraph.getattr("_pred")?.cast_into::<PyDict>()?;
        if !node_d.is_empty() {
            return Err(PyValueError::new_err("the callgraph is not empty"));
        }
        let st = self.store.borrow(py);
        let cg = &st.callgraph;
        let ty_name = |t: u8| match t {
            CG_CALL => "call",
            CG_FAKERET => "fakeret",
            CG_TRANSITION => "transition",
            _ => "exception",
        };
        let mut succ_of: FxHashMap<u64, Bound<'_, PyDict>> = FxHashMap::default();
        let mut pred_of: FxHashMap<u64, Bound<'_, PyDict>> = FxHashMap::default();
        for n in cg.succ.keys() {
            node_d.set_item(n, PyDict::new(py))?;
            let s = PyDict::new(py);
            let p = PyDict::new(py);
            succ_d.set_item(n, &s)?;
            pred_d.set_item(n, &p)?;
            succ_of.insert(*n, s);
            pred_of.insert(*n, p);
        }
        let mut keydicts: FxHashMap<(u64, u64), Bound<'_, PyDict>> = FxHashMap::default();
        for (u, m) in cg.succ.iter() {
            for (v, types) in m.iter() {
                let keydict = PyDict::new(py);
                for (i, &t) in types.iter().enumerate() {
                    let data = PyDict::new(py);
                    data.set_item("type", ty_name(t))?;
                    keydict.set_item(i, data)?;
                }
                succ_of[u].set_item(v, &keydict)?;
                keydicts.insert((*u, *v), keydict);
            }
        }
        for (v, m) in cg.pred.iter() {
            for u in m.keys() {
                pred_of[v].set_item(u, &keydicts[&(*u, *v)])?;
            }
        }
        Ok(())
    }

    /// The end of `make_functions`: `node.function_address = blockaddr_to_funcaddr[node.addr]` for every CFG node.
    fn update_node_functions(&self, py: Python<'_>) -> PyResult<()> {
        let b2f = &self.b2f;
        self.graph.bind(py).get().with_store(|s| {
            for id in s.nodes() {
                let (addr, _) = s.node_key(id)?;
                if let Some(&f) = b2f.get(&addr)
                    && s.node_func(id)? != Some(f)
                {
                    s.set_node_func(id, Some(f))?;
                    s.set_node_name(id, None)?;
                }
            }
            Ok(())
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "<FunctionsBuilder: {} functions, {} mapped blocks, {} traversed nodes>",
            self.order.len(),
            self.b2f.len(),
            self.traversed.len()
        )
    }
}

pub fn cfg_funcs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<FunctionsBuilder>()?;
    Ok(())
}
