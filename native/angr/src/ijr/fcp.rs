//! `FastConstantPropagation` (angr/analyses/fcp/fcp.py) over the Rust VEX view, with the same replacements.
//!
//! Python values map to [`Val`]: ints are [`U256`], `SpOffset` is [`Val::Sp`], and everything else that is not
//! None (the `SV` a stack load returns, float constants) is [`Val::Opaque`]. The replacement table is keyed like the
//! Python one: `CodeLocation(block.addr, stmt_idx, ins_addr)` -> `{VEXTmp | VEXReg: int}`, insertion-ordered,
//! last write wins.

use std::rc::Rc;

use indexmap::IndexMap;
use pyo3::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};

use super::cx::{IrSpec, ResolveCx};
use super::u256::U256;
use crate::ailment::vex_ffi::{
    self, ICO_F32, ICO_F32I, ICO_F64, ICO_F64I, ICO_U128, ICO_V128, ICO_V256, ICO_V512,
};
use crate::function_graph::NodeKind;
use crate::recovery_functions::RecoveryFunctions;
use crate::vexir::{Expr, ExprId, IrConst, Stmt, VexIrsb, op_name};
use crate::vexlift::jumpkind_name;

/// `CodeLocation(block_addr, stmt_idx, ins_addr=ins_addr)`.
pub type CodeLoc = (u64, i32, i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Var {
    /// `VEXTmp(tmp)`
    Tmp(u32),
    /// `VEXReg(offset, size)`
    Reg(i32, u32),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct FcpTable {
    pub entries: IndexMap<CodeLoc, IndexMap<Var, U256>>,
}

impl FcpTable {
    fn put(&mut self, loc: CodeLoc, var: Var, v: U256) {
        self.entries.entry(loc).or_default().insert(var, v);
    }

    pub fn get(&self, loc: &CodeLoc, var: &Var) -> Option<U256> {
        self.entries.get(loc)?.get(var).copied()
    }
}

/// A Python value of the propagation.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Val {
    Int(U256),
    Sp { bits: u32, off: u64, is_base: bool },
    Opaque,
}

/// `SV(value, bits)`
#[derive(Clone, Copy, Debug, PartialEq)]
struct Sv {
    value: U256,
    bits: u32,
}

/// `FCPState` without tmps (they live per block).
#[derive(Clone, Debug, Default, PartialEq)]
struct State {
    regs: FxHashMap<i64, Sv>,
    stack: FxHashMap<u64, Sv>,
    sp: u64,
    bp: u64,
}

fn overlaps(off: i128, len: i128, offset: i128, size: i128) -> bool {
    (off <= offset && offset < off + len) || (offset <= off && off < offset + size)
}

impl State {
    fn register_read(&self, offset: i64, size: u32) -> Option<U256> {
        let v = self.regs.get(&offset)?;
        (v.bits == size * 8).then_some(v.value)
    }

    fn register_written(&mut self, offset: i64, size: u32, value: Option<U256>) {
        match value {
            Some(v) => {
                self.regs.insert(
                    offset,
                    Sv {
                        value: v,
                        bits: size * 8,
                    },
                );
            }
            None => self.regs.retain(|&off, v| {
                !overlaps(
                    off as i128,
                    (v.bits / 8) as i128,
                    offset as i128,
                    size as i128,
                )
            }),
        }
    }

    fn stack_written(&mut self, offset: u64, size: u32, value: Option<U256>) {
        match value {
            Some(v) => {
                self.stack.insert(
                    offset,
                    Sv {
                        value: v,
                        bits: size * 8,
                    },
                );
            }
            None => self.stack.retain(|&off, v| {
                !overlaps(
                    off as i128,
                    (v.bits / 8) as i128,
                    offset as i128,
                    size as i128,
                )
            }),
        }
    }

    /// `_merge_states`: registers and stack slots that agree everywhere; the maximum sp and bp (starting at 0).
    fn meet(states: &[Rc<State>]) -> Rc<State> {
        let first = &states[0];
        let others: Vec<&Rc<State>> = states[1..]
            .iter()
            .filter(|s| !Rc::ptr_eq(s, first))
            .collect();
        if others.is_empty() {
            return first.clone();
        }
        let mut out = State {
            regs: first.regs.clone(),
            stack: first.stack.clone(),
            sp: first.sp,
            bp: first.bp,
        };
        for s in others {
            out.regs.retain(|k, v| s.regs.get(k) == Some(v));
            out.stack.retain(|k, v| s.stack.get(k) == Some(v));
            out.sp = out.sp.max(s.sp);
            out.bp = out.bp.max(s.bp);
        }
        Rc::new(out)
    }
}

/// What a load may read (FCP's `load_callback`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadPolicy {
    /// `PropagatorLoadCallback.propagator_load_callback`
    Propagator,
}

/// Why a propagation cannot be reproduced in Rust; the caller hands the call to Python.
pub type Decline = &'static str;

/// `cle.Clemory.unpack_word(addr, size, endness)`; Err for sizes the Python one raises on.
fn unpack_word(
    cx: &ResolveCx,
    addr: U256,
    size: u32,
    big_endian: bool,
) -> Result<Option<U256>, Decline> {
    let Some(addr) = addr.to_u64() else {
        return Ok(None);
    };
    if size > 8 {
        let sub = size >> 1;
        if size != sub << 1 || size > 32 {
            return Err("unpack_size");
        }
        let (lo_off, hi_off) = if big_endian {
            (sub as u64, 0)
        } else {
            (0, sub as u64)
        };
        let Some(lo) = unpack_word(
            cx,
            U256::from_u64(addr.wrapping_add(lo_off)),
            sub,
            big_endian,
        )?
        else {
            return Ok(None);
        };
        let Some(hi) = unpack_word(
            cx,
            U256::from_u64(addr.wrapping_add(hi_off)),
            sub,
            big_endian,
        )?
        else {
            return Ok(None);
        };
        let mut bytes = lo.to_le_bytes()[..sub as usize].to_vec();
        bytes.extend_from_slice(&hi.to_le_bytes()[..sub as usize]);
        return Ok(U256::from_le_bytes(&bytes));
    }
    if !matches!(size, 1 | 2 | 4 | 8) {
        return Err("unpack_size");
    }
    Ok(cx
        .snap
        .load_word_endian(addr, size as usize, big_endian)
        .map(U256::from_u64))
}

/// `PropagatorLoadCallback.propagator_load_callback(addr, size)`.
fn propagator_may_load(cx: &ResolveCx, addr: U256, size: u32) -> Result<bool, Decline> {
    let Some(a) = addr.to_u64() else {
        return Ok(false);
    };
    let snap = &cx.snap;
    let section = snap
        .find_section_containing(a)
        .map(|(o, s)| &snap.objects[o].sections[s]);
    let mut segment = None;
    match section {
        Some(sec) => {
            if sec.is_readable && !sec.is_writable {
                return Ok(true);
            }
        }
        None => {
            segment = snap
                .find_segment_containing(a)
                .map(|(o, s)| &snap.objects[o].segments[s]);
            if let Some(seg) = segment
                && seg.is_readable
                && !seg.is_writable
            {
                return Ok(true);
            }
        }
    }
    if (size == cx.arch.bytes && section.is_some_and(|s| s.is_readable))
        || segment.is_some_and(|s| s.is_readable)
    {
        let Some(target) = unpack_word(cx, addr, size, cx.arch.memory_be)? else {
            return Ok(false);
        };
        if target >= U256::from_u64(0x1000)
            && let Some(t) = target.to_u64()
            && snap.find_object_containing(t, true).is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One FCP block run (`SimEngineFCPVEX.process`).
struct Engine<'a> {
    cx: &'a ResolveCx,
    ir: &'a VexIrsb,
    bp_as_gpr: bool,
    load: LoadPolicy,
    table: &'a mut FcpTable,
    state: State,
    tmps: Vec<Option<Val>>,
    block_addr: u64,
    stmt_idx: i32,
    ins_addr: i64,
}

impl Engine<'_> {
    fn loc(&self) -> CodeLoc {
        (self.block_addr, self.stmt_idx, self.ins_addr)
    }

    fn size_bytes(&self, e: ExprId) -> u32 {
        self.ir.result_bits(e) / self.cx.arch.byte_width
    }

    fn konst(c: &IrConst) -> Result<Val, Decline> {
        Ok(match c.tag {
            ICO_F32 | ICO_F32I | ICO_F64 | ICO_F64I => Val::Opaque,
            ICO_V128 | ICO_V256 => {
                // pyvex: each set bit i becomes a 0xff byte i
                let n = c.bits() as usize / 8;
                let bytes: Vec<u8> = (0..n)
                    .map(|i| if (c.raw >> i) & 1 == 1 { 0xff } else { 0 })
                    .collect();
                Val::Int(U256::from_le_bytes(&bytes).ok_or("wide_const")?)
            }
            ICO_V512 => return Err("wide_const"),
            ICO_U128 => return Err("u128_const"),
            _ => Val::Int(U256::from_u64(c.raw)),
        })
    }

    fn expr(&mut self, id: ExprId) -> Result<Option<Val>, Decline> {
        let arch = &self.cx.arch;
        let Some(e) = self.ir.expr(id) else {
            return Err("null_expr");
        };
        Ok(match e {
            Expr::Const(c) => Some(Self::konst(c)?),
            Expr::RdTmp(t) => self.tmps.get(*t as usize).copied().flatten(),
            Expr::Get { offset, .. } => {
                if *offset == arch.sp_offset {
                    Some(Val::Sp {
                        bits: arch.bits,
                        off: self.state.sp,
                        is_base: false,
                    })
                } else if *offset == arch.bp_offset && !self.bp_as_gpr {
                    Some(Val::Sp {
                        bits: arch.bits,
                        off: self.state.bp,
                        is_base: false,
                    })
                } else {
                    let size = self.size_bytes(id);
                    let v = self.state.register_read(*offset as i64, size);
                    if let Some(v) = v {
                        let loc = self.loc();
                        self.table.put(loc, Var::Reg(*offset, size), v);
                    }
                    v.map(Val::Int)
                }
            }
            Expr::Load { end, addr, .. } => {
                let (end, addr) = (*end, *addr);
                match self.expr(addr)? {
                    Some(Val::Sp { off, .. }) => self.state.stack.get(&off).map(|_| Val::Opaque),
                    Some(Val::Int(a)) => {
                        let size = self.size_bytes(id);
                        let allowed = match self.load {
                            LoadPolicy::Propagator => propagator_may_load(self.cx, a, size)?,
                        };
                        if allowed {
                            unpack_word(self.cx, a, size, end == vex_ffi::IEND_BE)?.map(Val::Int)
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            Expr::Binop { op, args } => {
                let name = op_name(*op);
                let kind = if name.starts_with("Iop_Add") {
                    0
                } else if name.starts_with("Iop_Sub") {
                    1
                } else if name.starts_with("Iop_And") {
                    2
                } else {
                    return Ok(None);
                };
                let (a0, a1) = (args[0], args[1]);
                let op0 = self.expr(a0)?;
                let op1 = self.expr(a1)?;
                let bits = self.ir.result_bits(id);
                let sp_add = |bits: u32, off: u64, x: U256, sub: bool| -> u64 {
                    // s2u(off +/- x, bits): the result modulo 2**bits
                    let x = x.masked(bits.min(64)).low_u64();
                    let r = if sub {
                        off.wrapping_sub(x)
                    } else {
                        off.wrapping_add(x)
                    };
                    if bits >= 64 {
                        r
                    } else {
                        r & ((1u64 << bits) - 1)
                    }
                };
                match kind {
                    0 | 1 => {
                        let sub = kind == 1;
                        match (op0, op1) {
                            (
                                Some(Val::Sp {
                                    bits: b,
                                    off,
                                    is_base,
                                }),
                                Some(Val::Int(x)),
                            )
                            | (
                                Some(Val::Int(x)),
                                Some(Val::Sp {
                                    bits: b,
                                    off,
                                    is_base,
                                }),
                            ) => {
                                if b > 64 {
                                    return Err("wide_sp");
                                }
                                Some(Val::Sp {
                                    bits: b,
                                    off: sp_add(b, off, x, sub),
                                    is_base,
                                })
                            }
                            (Some(Val::Int(x)), Some(Val::Int(y))) => {
                                if bits > 256 {
                                    return Err("wide_op");
                                }
                                Some(Val::Int(
                                    if sub {
                                        x.wrapping_sub(y)
                                    } else {
                                        x.wrapping_add(y)
                                    }
                                    .masked(bits),
                                ))
                            }
                            _ => None,
                        }
                    }
                    _ => match (op0, op1) {
                        (Some(v @ Val::Sp { .. }), _) => Some(v),
                        (_, Some(v @ Val::Sp { .. })) => Some(v),
                        (Some(Val::Int(x)), Some(Val::Int(y))) => Some(Val::Int(x.and(y))),
                        _ => None,
                    },
                }
            }
            Expr::Binder(_) => return Err("binder"),
            // GetI, ITE, Unop, Triop, Qop, CCall, VECRET, GSPTR
            _ => None,
        })
    }

    fn stmt(&mut self, s: &Stmt) -> Result<(), Decline> {
        let arch = &self.cx.arch;
        match s {
            Stmt::WrTmp { tmp, data } => {
                if let Some(Expr::Binop { op, .. }) = self.ir.expr(*data) {
                    let name = op_name(*op);
                    if !(name.starts_with("Iop_Add")
                        || name.starts_with("Iop_Sub")
                        || name.starts_with("Iop_And"))
                    {
                        return Ok(());
                    }
                }
                if let Some(v) = self.expr(*data)? {
                    let t = *tmp as usize;
                    if t >= self.tmps.len() {
                        self.tmps.resize(t + 1, None);
                    }
                    self.tmps[t] = Some(v);
                    if let Val::Int(x) = v {
                        let loc = self.loc();
                        self.table.put(loc, Var::Tmp(*tmp), x);
                    }
                }
            }
            Stmt::Put { offset, data } => {
                let v = self.expr(*data)?;
                let size = self.size_bytes(*data);
                match v {
                    Some(Val::Sp { off, .. }) if *offset == arch.sp_offset => self.state.sp = off,
                    Some(Val::Sp { off, .. }) if *offset == arch.bp_offset && !self.bp_as_gpr => {
                        self.state.bp = off
                    }
                    Some(Val::Int(x)) => {
                        self.state.register_written(*offset as i64, size, Some(x));
                        if *offset != arch.ip_offset {
                            let loc = self.loc();
                            self.table.put(loc, Var::Reg(*offset, size), x);
                        }
                    }
                    _ => self.state.register_written(*offset as i64, size, None),
                }
            }
            Stmt::Store { addr, data, .. } => {
                if let Some(Val::Sp { off, .. }) = self.expr(*addr)? {
                    let d = self.expr(*data)?;
                    let size = self.size_bytes(*data);
                    match d {
                        Some(Val::Int(x)) => self.state.stack_written(off, size, Some(x)),
                        _ => self.state.stack_written(off, size, None),
                    }
                }
            }
            // Dirty statements end up as no-ops in FCP (top values are None); everything else is unhandled
            _ => {}
        }
        Ok(())
    }

    fn run(&mut self) -> Result<(), Decline> {
        self.stmt_idx = -1;
        self.ins_addr = -1;
        for (i, s) in self.ir.stmts.iter().enumerate() {
            self.stmt_idx = i as i32;
            if let Stmt::IMark { addr, delta, .. } = s {
                self.ins_addr = (*addr + *delta as u64) as i64;
            }
            self.stmt(s)?;
        }
        if jumpkind_name(self.ir.jumpkind) == "Ijk_Call" {
            let arch = &self.cx.arch;
            self.state
                .register_written(arch.ret_offset as i64, arch.bytes, None);
        }
        Ok(())
    }
}

/// The parameters of one FastConstantPropagation run.
pub struct FcpRequest<'a> {
    pub func_addr: u64,
    /// `blocks`: process only these block addresses (ConstantValueManager); None processes every block.
    pub blocks: Option<&'a FxHashSet<u64>>,
    pub cross_insn_opt: bool,
    pub load: LoadPolicy,
}

struct NodeInfo {
    kind: NodeKind,
    addr: u64,
    size: u32,
    preds: Vec<u32>,
    callee: Option<u64>,
}

/// `FastConstantPropagation(func, blocks, vex_cross_insn_opt, load_callback).replacements`.
///
/// `cx.callee_cc(addr)` returns the CALLER_SAVED_REGS of the function at `addr` (None: the default calling
/// convention); it is the only Python call.
pub fn run_fcp(
    py: Python<'_>,
    cx: &mut ResolveCx,
    store: &Py<RecoveryFunctions>,
    req: &FcpRequest<'_>,
) -> PyResult<Result<FcpTable, Decline>> {
    let callee_cc = cx.callee_cc.clone_ref(py);
    let callee_cc = callee_cc.bind(py);
    // read everything the walk needs from the function graph first; no borrow is held across Python calls
    let (bp_as_gpr, nodes, order) = {
        let st = store.bind(py).borrow();
        let Ok(rec) = st.rec(req.func_addr) else {
            return Ok(Err("no_function"));
        };
        let bp_as_gpr = match st.info_get(py, req.func_addr, "bp_as_gpr")? {
            Some(v) => v.bind(py).is_truthy()?,
            None => false,
        };
        let g = rec.graph.bind(py).borrow();
        let Some(start) = g.get_startpoint() else {
            return Ok(Err("no_startpoint"));
        };
        if !g.in_local_view(start) {
            return Ok(Err("startpoint_not_local"));
        }
        let mut order = g.local_dfs_postorder(start)?;
        order.reverse();
        let mut nodes: FxHashMap<u32, NodeInfo> = FxHashMap::default();
        for &n in &order {
            let (kind, addr, size, _thumb) = g.node(n)?;
            let callee = match g.first_callee_successor(n) {
                Some(c) => Some(g.node_addr(c)?),
                None => None,
            };
            nodes.insert(
                n,
                NodeInfo {
                    kind,
                    addr,
                    size,
                    preds: g.local_predecessors(n)?,
                    callee,
                },
            );
        }
        (bp_as_gpr, nodes, order)
    };

    // with `blocks`, only the processed nodes and the nodes whose states flow into them
    let order: Vec<u32> = match req.blocks {
        None => order,
        Some(blocks) => {
            let pos: FxHashMap<u32, usize> =
                order.iter().enumerate().map(|(i, &n)| (n, i)).collect();
            let mut needed: FxHashSet<u32> = order
                .iter()
                .copied()
                .filter(|n| blocks.contains(&nodes[n].addr))
                .collect();
            let mut work: Vec<u32> = needed.iter().copied().collect();
            while let Some(n) = work.pop() {
                let np = pos[&n];
                for &p in &nodes[&n].preds {
                    if !needed.contains(&p) && pos.get(&p).copied().unwrap_or(np) < np {
                        needed.insert(p);
                        work.push(p);
                    }
                }
            }
            order.into_iter().filter(|n| needed.contains(n)).collect()
        }
    };

    let mut init = State::default();
    if cx.arch.call_pushes_ret {
        init.sp = cx.arch.bytes as u64;
    }
    init.bp = init.sp;
    if let Some((off, size)) = cx.arch.ftop {
        init.register_written(off as i64, size, Some(U256::ZERO));
    }
    let init = Rc::new(init);

    let mut clobbers: FxHashMap<u64, Option<Vec<(i32, u32)>>> = FxHashMap::default();
    let mut table = FcpTable::default();
    let mut states: FxHashMap<u32, Rc<State>> = FxHashMap::default();
    for n in order {
        let info = &nodes[&n];
        let inputs: Vec<Rc<State>> = info
            .preds
            .iter()
            .filter_map(|p| states.get(p).cloned())
            .collect();
        let state = if inputs.is_empty() {
            init.clone()
        } else {
            State::meet(&inputs)
        };
        if let Some(blocks) = req.blocks
            && !blocks.contains(&info.addr)
        {
            states.insert(n, state);
            continue;
        }
        match info.kind {
            NodeKind::Block if info.size == 0 => continue,
            NodeKind::Func | NodeKind::Hook | NodeKind::Syscall => continue,
            NodeKind::Block => {}
        }
        let spec = IrSpec {
            addr: info.addr,
            max_size: info.size as i64,
            opt_level: cx.default_opt_level,
            cross_insn_opt: req.cross_insn_opt,
            extra_stops: false,
        };
        let ir = match cx.ir(py, &spec)? {
            Ok(ir) => ir,
            Err(fb) => return Ok(Err(fb.name())),
        };
        let mut eng = Engine {
            cx,
            ir: &ir,
            bp_as_gpr,
            load: req.load,
            table: &mut table,
            state: (*state).clone(),
            tmps: vec![None; ir.tyenv.len()],
            block_addr: info.addr,
            stmt_idx: -1,
            ins_addr: -1,
        };
        if let Err(d) = eng.run() {
            return Ok(Err(d));
        }
        let mut out = eng.state;
        if let Some(callee) = info.callee {
            let regs = match clobbers.get(&callee) {
                Some(r) => r.clone(),
                None => {
                    let r = callee_cc.call1((callee,))?;
                    let r: Option<Vec<(i32, u32)>> = if r.is_none() {
                        None
                    } else if r.is_instance_of::<pyo3::types::PyString>() {
                        return Ok(Err("callee_cc"));
                    } else {
                        Some(r.extract()?)
                    };
                    clobbers.insert(callee, r.clone());
                    r
                }
            };
            let regs = match regs.as_ref().or(cx.arch.default_clobbers.as_ref()) {
                Some(r) => r,
                None => return Ok(Err("no_default_cc")),
            };
            for &(off, size) in regs {
                out.register_written(off as i64, size, None);
            }
        }
        states.insert(n, Rc::new(out));
    }
    Ok(Ok(table))
}

/// The FCP table as Python rows `[((block_addr, stmt_idx, ins_addr), [(("tmp", t) | ("reg", off, size), v)])]`.
pub fn table_rows<'py>(py: Python<'py>, t: &FcpTable) -> PyResult<Bound<'py, pyo3::types::PyList>> {
    let out = pyo3::types::PyList::empty(py);
    for (loc, vars) in &t.entries {
        let row = pyo3::types::PyList::empty(py);
        for (var, v) in vars {
            let key = match var {
                Var::Tmp(t) => ("tmp", *t as i64, 0u32).into_pyobject(py)?,
                Var::Reg(o, s) => ("reg", *o as i64, *s).into_pyobject(py)?,
            };
            row.append((key, *v))?;
        }
        out.append((*loc, row))?;
    }
    Ok(out)
}
