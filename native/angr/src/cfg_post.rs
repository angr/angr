//! Drivers for CFGFast post-analysis passes.
//!
//! `OverlapScan` (`angr.rustylib.cfg_post.OverlapScan`) runs the two walks of
//! `CFGFast._remove_redundant_overlapping_blocks` over the sorted node keys of a `CfgGraph`: it picks the
//! function heads that may start with alignment nops, then yields the pairs of overlapping blocks in the order the
//! Python loop visits them. Python lifts and mutates the graph and the functions for each candidate, so every
//! filter is evaluated against the current graph when the walk reaches it, as in the Python loop.

use std::collections::HashSet;
use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::cfg_graph::CfgGraph;
use crate::cfg_scan::{LoaderSnapshot, Snapshot};
use crate::function_graph::{FunctionGraph, NodeKind};
use crate::recovery_functions::RecoveryFunctions;

type Key = (u64, i64);

// ---------------------------------------------------------------------------------------------------------------
// x86 first-instruction classification
// ---------------------------------------------------------------------------------------------------------------

/// What the first x86 instruction of some bytes can be, as far as the overlap pass cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum X86Head {
    /// May be what `CFGBase._is_noop_insn` calls a nop (capstone `nop`, `lea r, [r]`, `mov r, r`, `ud0/1/2`), or
    /// may start a block that `CFGBase._is_noop_block` accepts; only lifting can tell.
    Unknown,
    /// Certainly not a nop in the `_is_noop_insn` sense, but the block might still lift to a VEX no-op block.
    NotNopInsn,
    /// Certainly not a nop, and it writes a register other than the PC, writes memory or leaves the block, so no
    /// block starting with it is a no-op block.
    Effectful,
}

fn is_legacy_prefix(b: u8) -> bool {
    matches!(
        b,
        0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
    )
}

/// Classify the first instruction in `bytes` (decoded in 64-bit mode if `is_64`). Conservative: anything not
/// recognized is `Unknown`.
pub fn classify_x86_head(bytes: &[u8], is_64: bool) -> X86Head {
    let mut i = 0usize;
    let mut rex = 0u8;
    let mut opsize_or_addrsize = false;
    loop {
        let Some(&b) = bytes.get(i) else {
            return X86Head::Unknown;
        };
        if is_legacy_prefix(b) {
            // a REX prefix that is not right before the opcode is ignored
            rex = 0;
            opsize_or_addrsize |= b == 0x66 || b == 0x67;
        } else if is_64 && (0x40..=0x4F).contains(&b) {
            rex = b;
        } else {
            break;
        }
        i += 1;
        if i >= 15 {
            return X86Head::Unknown;
        }
    }
    let op = bytes[i];
    let modrm = bytes.get(i + 1).copied();
    match op {
        // nop, xchg r8, rax, pause; int3 (an int3 run is accepted by _is_noop_block)
        0x90 | 0xCC => X86Head::Unknown,
        0x0F => match modrm {
            // ud2, prefetch, hint nops, ud1, ud0
            Some(0x0B | 0x0D | 0x18..=0x1F | 0xB9 | 0xFF) | None => X86Head::Unknown,
            // endbr, prefetch-like encodings and SSE nops lift to nothing; jumps may go to the next instruction
            Some(_) => X86Head::NotNopInsn,
        },
        // mov r/m, r and mov r, r/m: a nop only between one register and itself
        0x88..=0x8B => match modrm {
            Some(m) if m >> 6 == 3 => {
                let reg = ((m >> 3) & 7) | ((rex & 4) << 1);
                let rm = (m & 7) | ((rex & 1) << 3);
                if reg == rm {
                    X86Head::Unknown
                } else {
                    X86Head::Effectful
                }
            }
            Some(_) => X86Head::Effectful,
            None => X86Head::Unknown,
        },
        // lea: a nop only for lea r, [r + 0]
        0x8D => match modrm {
            Some(m) if opsize_or_addrsize || m >> 6 == 3 || m & 7 == 4 => X86Head::Unknown,
            Some(m) => {
                let mode = m >> 6;
                let reg = ((m >> 3) & 7) | ((rex & 4) << 1);
                let base = (m & 7) | ((rex & 1) << 3);
                if mode == 0 && m & 7 == 5 {
                    // rip-relative or absolute
                    return X86Head::Effectful;
                }
                if reg != base {
                    return X86Head::Effectful;
                }
                let zero_disp = match mode {
                    0 => true,
                    1 => bytes.get(i + 2).map(|&d| d == 0).unwrap_or(true),
                    _ => bytes
                        .get(i + 2..i + 6)
                        .map(|d| d.iter().all(|&x| x == 0))
                        .unwrap_or(true),
                };
                if zero_disp {
                    X86Head::Unknown
                } else {
                    X86Head::Effectful
                }
            }
            None => X86Head::Unknown,
        },
        // xchg r, r may lift to nothing; fwait and x87 (fnop) may too; hlt; jmp may go to the next instruction
        0x86 | 0x87 | 0x91..=0x97 | 0x9B | 0xD8..=0xDF | 0xF4 | 0xE9 | 0xEB => X86Head::NotNopInsn,
        // VEX/EVEX encodings never decode to `nop`, `lea` or `mov`, but may lift to nothing
        0xC4 | 0xC5 | 0x62 => X86Head::NotNopInsn,
        _ => X86Head::Effectful,
    }
}

/// The nop encodings compilers pad with, on which pyvex (a no-op block) and capstone (`nop`) agree in both x86
/// modes; `tests/analyses/cfg/test_cfgfast_overlapping_blocks.py` checks that they still do.
pub const X86_NOPS: [&[u8]; 17] = [
    b"\x90",
    b"\x66\x90",
    b"\x0f\x1f\x00",
    b"\x0f\x1f\x40\x00",
    b"\x0f\x1f\x44\x00\x00",
    b"\x66\x0f\x1f\x44\x00\x00",
    b"\x0f\x1f\x80\x00\x00\x00\x00",
    b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    b"\x66\x66\x66\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
];

/// The length of the nop from `X86_NOPS` that `bytes` starts with.
pub fn x86_nop_len(bytes: &[u8]) -> Option<usize> {
    X86_NOPS
        .iter()
        .find(|n| bytes.starts_with(n))
        .map(|n| n.len())
}

/// The nop length `_remove_redundant_overlapping_blocks` computes for a block lifted at `addr` with at most
/// `max_size` bytes (`_lift`, `_is_noop_block`, `_get_nop_length`), when the bytes alone decide it: the leading
/// nops from `X86_NOPS`, followed by an effectful instruction or by the end of the block. None otherwise.
pub fn x86_leading_nop_len(bytes: &[u8], max_size: usize, is_64: bool) -> Option<usize> {
    let mut pos = 0usize;
    while pos < max_size {
        let rest = bytes.get(pos..)?;
        match x86_nop_len(rest) {
            // VEX lifts only whole instructions that fit; the block then is nops only
            Some(len) if pos + len > max_size => return Some(pos),
            Some(len) => pos += len,
            None => {
                return (classify_x86_head(rest, is_64) == X86Head::Effectful).then_some(pos);
            }
        }
    }
    Some(pos)
}

/// Whether capstone decodes `bytes` into nothing but nops (`block.capstone.insns and all(_is_noop_insn(...))`):
/// true for a sequence of nops from `X86_NOPS`, false when the first instruction is not a nop. None if unknown.
pub fn x86_all_nops(bytes: &[u8], is_64: bool) -> Option<bool> {
    if bytes.is_empty() {
        return Some(false);
    }
    if x86_nop_len(bytes).is_none() {
        // capstone decodes a non-nop first instruction, or nothing at all when it is cut off
        return match classify_x86_head(bytes, is_64) {
            X86Head::Unknown => None,
            _ => Some(false),
        };
    }
    let mut pos = 0usize;
    while pos < bytes.len() {
        match x86_nop_len(&bytes[pos..]) {
            Some(len) if pos + len <= bytes.len() => pos += len,
            // a cut-off or unknown instruction after the first nop: capstone may or may not decode it
            _ => return None,
        }
    }
    Some(true)
}

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
    /// x86 only (64-bit mode flag), when blocks are lifted from the loader's bytes: skip the lifting for blocks
    /// whose first instruction decides the outcome.
    x86: Option<(Arc<Snapshot>, bool)>,
    /// First walk: blocks are lifted up to the next multiple of this.
    function_alignment: u64,
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

    fn x86_bytes(&self, addr: u64, n: usize) -> Option<(Vec<u8>, bool)> {
        let (snap, is_64) = self.x86.as_ref()?;
        Some((snap.load_bytes(addr, n)?, *is_64))
    }

    /// Whether `_split_leading_nops` would leave the head at `addr` (first node `id`) alone; false if unknown.
    fn head_is_untouched(&self, graph: &CfgGraph, addr: u64, id: u64) -> PyResult<bool> {
        let max_size = (self.function_alignment - addr % self.function_alignment) as usize;
        // a hook inside the block ends it early
        if (1..max_size as u64).any(|d| self.hooked.contains(&addr.wrapping_add(d))) {
            return Ok(false);
        }
        let Some((bytes, is_64)) = self.x86_bytes(addr, max_size + 16) else {
            return Ok(false);
        };
        let Some(nop_length) = x86_leading_nop_len(&bytes, max_size, is_64) else {
            return Ok(false);
        };
        if nop_length == 0 {
            return Ok(true);
        }
        graph.with_store(|s| {
            let (_, a_size) = s.node_key(id)?;
            if nop_length as i64 >= a_size {
                return Ok(true);
            }
            s.has_addr(addr + nop_length as u64)
        })
    }

    /// `block.capstone.insns and all(_is_noop_insn(...))` for the bytes between a and b, if the bytes tell.
    fn big_nop(&self, a_addr: u64, len: u64) -> Option<bool> {
        let (bytes, is_64) = self.x86_bytes(a_addr, len as usize)?;
        if bytes.len() as u64 != len {
            return None;
        }
        x86_all_nops(&bytes, is_64)
    }

    /// Whether `_resolve_overlapping_blocks` would leave a and b alone, given that the bytes between them are not
    /// all nops. None when it would change the graph (or cannot find the nodes), so Python must handle the pair.
    fn pair_is_untouched(graph: &CfgGraph, a: Key, b: Key) -> PyResult<Option<()>> {
        graph.with_store(|s| {
            let (Some(a_id), Some(b_id)) = (s.find_node(a.0, a.1)?, s.find_node(b.0, b.1)?) else {
                return Ok(None);
            };
            if a.0 as i128 + a.1 as i128 == b.0 as i128 + b.1 as i128 && s.in_degree(b_id)? == 0 {
                return Ok(None);
            }
            let (b_base, b_sizes) = s.node_ins(b_id)?;
            if b_sizes.is_empty() {
                return Ok(None);
            }
            // InsAddrList.__contains__
            let (a_base, a_sizes) = s.node_ins(a_id)?;
            let mut cur = a_base;
            for &size in &a_sizes {
                if cur == b_base {
                    return Ok(Some(()));
                }
                cur = cur.wrapping_add(size as u64);
            }
            Ok(None)
        })
    }
}

#[pymethods]
impl OverlapScan {
    #[new]
    #[pyo3(signature = (graph, hooked, plt_stubs, syscall_from, is_syscall_addr, is_arm, function_alignment=16,
                        x86_snapshot=None, x86_64=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        graph: &CfgGraph,
        hooked: HashSet<u64>,
        plt_stubs: HashSet<u64>,
        syscall_from: Option<u64>,
        is_syscall_addr: Option<Py<PyAny>>,
        is_arm: bool,
        function_alignment: u64,
        x86_snapshot: Option<&Bound<'_, LoaderSnapshot>>,
        x86_64: bool,
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
            x86: x86_snapshot.map(|snap| (snap.get().inner.clone(), x86_64)),
            function_alignment: function_alignment.max(1),
            pair_pos: 0,
            a_key: None,
            pending_b: None,
            removed: HashSet::new(),
        })
    }

    /// The next function head (in key order) that is not a PLT stub, hook or syscall and has no incoming call edge:
    /// `(addr, id of model.get_any_node(addr))`. Heads that cannot start with alignment nops are skipped on x86.
    /// `functions` is the scan-time function store or any object supporting `in`.
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
            let Some(id) = found else {
                continue;
            };
            if self.x86.is_some() && self.head_is_untouched(graph, addr, id)? {
                continue;
            }
            return Ok(Some((addr, id)));
        }
        Ok(None)
    }

    /// Adds the keys of the nodes created by the first walk; the second walk visits all keys in order.
    fn append_keys(&mut self, keys: Vec<Key>) {
        self.keys.extend(keys);
        self.keys.sort();
    }

    /// The next overlapping `(a_key, b_key, big_nop)` that Python must handle; `resolve` must be called before
    /// asking for the next one. `big_nop` tells whether the bytes between a and b are all nops, None if they must be
    /// lifted to find out. Pairs that the Python code would leave alone are skipped here.
    fn next_overlap(
        &mut self,
        py: Python<'_>,
        graph: &CfgGraph,
    ) -> PyResult<Option<(Key, Key, Option<bool>)>> {
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
                let big_nop = if b_real > a_real {
                    self.big_nop(a.0, b_real - a_real)
                } else {
                    None
                };
                if big_nop == Some(false) && Self::pair_is_untouched(graph, a, b)?.is_some() {
                    self.a_key = Some(b);
                    continue;
                }
                self.pending_b = Some(b);
                return Ok(Some((a, b, big_nop)));
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

/// The verdicts of `CFGBase.mark_function_alignments` for single-block x86 functions, from the bytes, the CFG nodes
/// and the function graphs: True (an alignment), False (not one), or None when only lifting can tell.
#[pyfunction]
pub fn x86_alignment_verdicts(
    py: Python<'_>,
    snapshot: &Bound<'_, LoaderSnapshot>,
    cfg_graph: &Bound<'_, CfgGraph>,
    graphs: Vec<Py<FunctionGraph>>,
    is_64: bool,
) -> PyResult<Vec<Option<bool>>> {
    let snap = &snapshot.get().inner;
    let cfg_graph = cfg_graph.get();
    let mut out = Vec::with_capacity(graphs.len());
    for g in graphs {
        let g = g.bind(py).borrow();
        out.push(x86_alignment_verdict(snap, cfg_graph, &g, is_64)?);
    }
    Ok(out)
}

/// push/pop reg, cwde/cdq, leave, ret: one byte, no operands, never a nop.
fn is_complete_one_byte_insn(b: u8) -> bool {
    matches!(b, 0x50..=0x5F | 0x98 | 0x99 | 0xC9 | 0xC3)
}

/// The length of the first instruction of the CFG node `(addr, size)`, from its instruction list.
fn first_insn_len(cfg_graph: &CfgGraph, addr: u64, size: u32) -> PyResult<Option<usize>> {
    cfg_graph.with_store(|s| {
        let Some(id) = s.find_node(addr, size as i64)? else {
            return Ok(None);
        };
        let (base, sizes) = s.node_ins(id)?;
        if base != addr || sizes.is_empty() {
            return Ok(None);
        }
        // the size of the last instruction is not recorded, and a node may end inside it (shrunk nodes)
        if sizes.len() < 2 {
            return Ok(None);
        }
        let len = sizes[0] as usize;
        Ok((len >= 1 && len < size as usize).then_some(len))
    })
}

fn x86_alignment_verdict(
    snap: &Snapshot,
    cfg_graph: &CfgGraph,
    g: &FunctionGraph,
    is_64: bool,
) -> PyResult<Option<bool>> {
    let items = g.local_items();
    let [(addr, idx)] = items.as_slice() else {
        return Ok(None);
    };
    let (kind, _, size, _) = g.node(*idx)?;
    if kind != NodeKind::Block || g.has_node_bytes(*idx) || size == 0 {
        return Ok(None);
    }
    let Some(bytes) = snap.load_bytes(*addr, size as usize) else {
        return Ok(None);
    };
    if bytes.len() != size as usize {
        return Ok(None);
    }
    // _is_noop_block: int3 or nop runs, then a VEX no-op block; or all capstone instructions are nops
    if bytes.iter().all(|&b| b == 0x90) || bytes.iter().all(|&b| b == 0xCC) {
        return Ok(Some(true));
    }
    match x86_all_nops(&bytes, is_64) {
        Some(true) => return Ok(Some(true)),
        // a complete effectful first instruction: VEX does not see a no-op block, and capstone decodes a non-nop
        Some(false) if x86_nop_len(&bytes).is_none() => {
            let len = match first_insn_len(cfg_graph, *addr, size)? {
                Some(len) => len,
                // one-byte instructions are complete in any node
                None if is_complete_one_byte_insn(bytes[0]) => 1,
                None => return Ok(None),
            };
            if classify_x86_head(&bytes[..len], is_64) != X86Head::Effectful {
                return Ok(None);
            }
        }
        _ => return Ok(None),
    }
    // a single-node self loop
    let Some(node) = g.block_node_at(*addr) else {
        return Ok(None);
    };
    if !g.in_local_view(node) {
        return Ok(None);
    }
    let succs = g.local_successors(node)?;
    Ok(Some(
        succs.len() == 1 && g.node_addr(succs[0])? == g.node_addr(node)?,
    ))
}

/// `x86_leading_nop_len` for Python tests.
#[pyfunction]
#[pyo3(name = "x86_leading_nop_len")]
fn py_x86_leading_nop_len(bytes: &[u8], max_size: usize, is_64: bool) -> Option<usize> {
    x86_leading_nop_len(bytes, max_size, is_64)
}

/// `x86_all_nops` for Python tests.
#[pyfunction]
#[pyo3(name = "x86_all_nops")]
fn py_x86_all_nops(bytes: &[u8], is_64: bool) -> Option<bool> {
    x86_all_nops(bytes, is_64)
}

pub fn cfg_post(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OverlapScan>()?;
    m.add(
        "X86_NOPS",
        X86_NOPS.iter().map(|n| n.to_vec()).collect::<Vec<_>>(),
    )?;
    m.add_function(wrap_pyfunction!(py_x86_leading_nop_len, m)?)?;
    m.add_function(wrap_pyfunction!(py_x86_all_nops, m)?)?;
    m.add_function(wrap_pyfunction!(x86_alignment_verdicts, m)?)?;
    Ok(())
}
