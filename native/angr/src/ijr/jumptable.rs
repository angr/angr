//! `JumpTableResolver` (jumptable.py) for common jump tables, without claripy.
//!
//! For each jump, the backward predecessor paths (at most `MAX_DEPTH` blocks, `MAX_PATHS` paths) are executed
//! forward over VEX (`symex.rs`). The target must be `f(Load(A))` with `f` built from constants only; `A` is bounded
//! by a strided-interval evaluation under the path guards (`si.rs`), and every path must be bounded. The table is
//! read, `f` applied, and the answer is accepted only when every target is executable and decodes and the table
//! ends before the next referenced data. Everything else is declined to the Python resolver.

use std::rc::Rc;

use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use rustc_hash::{FxHashMap, FxHashSet};

use super::cvm::cvm_table;
use super::effects::{Effect, JtInfo};
use super::fcp::FcpTable;
use super::si::{MAX_ENTRIES, Ranges, Si, SiEval, gcd, path_ranges};
use super::symex::{Arena, BinOp, ConvKind, Id, Node, PathState, Step, SymArch};
use super::{Decision, Effects, IrSpec, JumpSite, Outcome, ResolveCx, Resolver};
use crate::cfg_scan::Snapshot;
use crate::vexir::{Expr, ExprId, Stmt, VexIrsb, op_name};
use crate::vexlift::{IJK_BORING, IJK_NODECODE, VEX_IRSB_MAX_SIZE, jumpkind_name};

const MAX_DEPTH: usize = 4;
const MAX_PATHS: usize = 8;
/// Tables no path bounds within those limits get a second look this deep and this wide.
const MAX_DEPTH_UNBOUNDED: usize = 6;
const MAX_PATHS_UNBOUNDED: usize = 32;
/// How far before the end of the jump block other entry blocks are looked for.
const ENTRY_LOOKBACK: u64 = 256;

/// A CFG node on a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PNode {
    id: u64,
    addr: u64,
    size: u32,
}

/// The shape of a jump target (also the skip classes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Const,
    /// A load from a constant (writable) address.
    ConstLoad,
    /// A register or arithmetic of registers.
    Reg,
    MultiLoad,
    Table,
    /// `[[x] + c]`: a word load from a loaded base.
    FieldOfLoad,
    /// `[reg + c]`.
    Field,
    /// An unscaled byte/halfword index load (tbb/tbh, AArch64 ldrb/ldrh).
    ByteIndex,
    /// A target computed from a scaled loaded value (`addls pc, pc, r, lsl #2` with a loaded r).
    Computed,
}

impl Shape {
    fn name(self) -> &'static str {
        match self {
            Shape::Const => "const",
            Shape::ConstLoad => "constload",
            Shape::Reg => "reg",
            Shape::MultiLoad => "multiload",
            Shape::Table => "table",
            Shape::FieldOfLoad => "field_of_load",
            Shape::Field => "field",
            Shape::ByteIndex => "byte_index",
            Shape::Computed => "computed",
        }
    }
}

/// A resolved table.
#[derive(Clone, Debug)]
pub struct Answer {
    pub table: u64,
    pub entry_size: u64,
    pub n: u64,
    pub targets: Vec<u64>,
    /// (base, size, entry size, raw entries) of the second-level table.
    pub table2: Option<(u64, u64, u64, Vec<u64>)>,
    pub unbounded: bool,
    pub depth: usize,
    pub stride: u64,
    /// The first entry is index 0: the lowest address is the constant base the index is added to.
    pub index_at_zero: bool,
    /// The constant the scaled index is added to, when there is one (shadow records).
    pub base: Option<u64>,
    /// The lower bound came from deeper paths (`raise_lower_bound`).
    pub raised: bool,
}

/// What a set of paths gives.
enum Try {
    Resolved(Answer),
    /// `stop`: deeper paths cannot change the answer.
    Fail {
        why: &'static str,
        stop: bool,
    },
    /// The table address is not bounded on some path.
    Unbounded {
        base_leaf: bool,
        /// The table base itself is not a constant (no constant addend outside the scaled index).
        base: bool,
    },
    Shape(Shape),
}

/// What `resolve` decided, for stats and shadow records.
#[derive(Clone, Debug)]
pub enum Verdict {
    Resolved(Answer),
    Deferred,
    Decline(String),
    /// Not a jump table (the skip classes): unresolved without the Python resolver.
    Skip {
        class: &'static str,
    },
}

// --- debug traces (`ResolverChain.debug_jumptable`) ----------------------------------------------------------------

thread_local! {
    static TRACE: std::cell::RefCell<Option<Vec<String>>> = const { std::cell::RefCell::new(None) };
}

fn tracing() -> bool {
    TRACE.with(|t| t.borrow().is_some())
}

fn trace(line: String) {
    TRACE.with(|t| {
        if let Some(v) = t.borrow_mut().as_mut() {
            v.push(line);
        }
    });
}

thread_local! {
    static TRACE_ADDRS: std::cell::RefCell<FxHashSet<u64>> = std::cell::RefCell::new(FxHashSet::default());
    static TRACE_OUT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Trace every resolution of the jumps at `addrs` during a run (empty stops); `jt_trace_take` returns the lines.
#[pyfunction]
#[pyo3(signature = (*addrs))]
pub fn jt_trace_addr(addrs: Vec<u64>) {
    TRACE_ADDRS.with(|t| *t.borrow_mut() = addrs.into_iter().collect());
}

#[pyfunction]
pub fn jt_trace_take() -> Vec<String> {
    TRACE_OUT.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// Start (`on`) or stop a trace; returns the lines collected so far.
pub fn set_trace(on: bool) -> Vec<String> {
    TRACE.with(|t| {
        let old = t.borrow_mut().take();
        if on {
            *t.borrow_mut() = Some(Vec::new());
        }
        old.unwrap_or_default()
    })
}

// --- expression shapes -------------------------------------------------------------------------------------------

fn find_table_loads(ar: &Arena, e: Id, out: &mut Vec<Id>) {
    match ar.get(e) {
        Node::Ld { addr, .. } => {
            if ar.const_val(addr).is_none() {
                out.push(e);
            }
        }
        Node::C { .. }
        | Node::R { .. }
        | Node::U { .. }
        | Node::Not1 { .. }
        | Node::Cmp { .. }
        | Node::Ite { .. } => {}
        Node::Conv { a, .. } | Node::Un { a, .. } => find_table_loads(ar, a, out),
        Node::Bin { a, b, .. } => {
            find_table_loads(ar, a, out);
            find_table_loads(ar, b, out);
        }
    }
}

fn table_loads(ar: &Arena, e: Id) -> Vec<Id> {
    let mut v = Vec::new();
    find_table_loads(ar, e, &mut v);
    v
}

/// Whether any leaf is a load (incl. constant-address loads).
fn has_load_leaf(ar: &Arena, e: Id) -> bool {
    match ar.get(e) {
        Node::Ld { .. } => true,
        Node::C { .. } | Node::R { .. } | Node::U { .. } => false,
        Node::Conv { a, .. } | Node::Not1 { a } | Node::Un { a, .. } => has_load_leaf(ar, a),
        Node::Ite { a, b, .. } => has_load_leaf(ar, a) || has_load_leaf(ar, b),
        Node::Cmp { a, b, .. } | Node::Bin { a, b, .. } => {
            has_load_leaf(ar, a) || has_load_leaf(ar, b)
        }
    }
}

fn has_scaled(ar: &Arena, e: Id) -> bool {
    match ar.get(e) {
        Node::Bin {
            op: BinOp::Shl | BinOp::Mul,
            a,
            b,
            ..
        } => {
            (ar.const_val(b).is_some() && ar.const_val(a).is_none())
                || (ar.const_val(a).is_some() && ar.const_val(b).is_none())
        }
        Node::Bin {
            op: BinOp::Add | BinOp::Sub | BinOp::And | BinOp::Or,
            a,
            b,
            ..
        } => has_scaled(ar, a) || has_scaled(ar, b),
        Node::Conv { a, .. } => has_scaled(ar, a),
        _ => false,
    }
}

fn load_parts(ar: &Arena, ld: Id) -> (u32, Id, bool) {
    match ar.get(ld) {
        Node::Ld { w, addr, be, .. } => (w as u32, addr, be),
        _ => unreachable!("not a load"),
    }
}

/// Whether `ld` appears under a scaling (Shl/Mul by a constant) in `e`.
fn scaled_load(ar: &Arena, e: Id, ld: Id, scaled: bool) -> bool {
    if e == ld {
        return scaled;
    }
    match ar.get(e) {
        Node::Bin {
            op: BinOp::Shl | BinOp::Mul,
            a,
            b,
            ..
        } => scaled_load(ar, a, ld, true) || scaled_load(ar, b, ld, true),
        Node::Bin { a, b, .. } => scaled_load(ar, a, ld, scaled) || scaled_load(ar, b, ld, scaled),
        Node::Conv { a, .. } => scaled_load(ar, a, ld, scaled),
        _ => false,
    }
}

pub fn classify(ar: &Arena, e: Id) -> Shape {
    if ar.const_val(e).is_some() {
        return Shape::Const;
    }
    let lds = table_loads(ar, e);
    if lds.is_empty() {
        return if has_load_leaf(ar, e) {
            Shape::ConstLoad
        } else {
            Shape::Reg
        };
    }
    if lds.len() > 1 {
        return Shape::MultiLoad;
    }
    let (lw, addr, _) = load_parts(ar, lds[0]);
    if has_scaled(ar, addr) {
        return Shape::Table;
    }
    // a word loaded from a field and then scaled is an index, not a target
    if lw > 16 && scaled_load(ar, e, lds[0], false) {
        return Shape::Computed;
    }
    if has_load_leaf(ar, addr) {
        Shape::FieldOfLoad
    } else {
        Shape::Field
    }
}

/// `Zext/Sext(Ld8/16(addr))`, possibly scaled: the outer table's index comes from an index table.
fn inner_index_load(ar: &Arena, e: Id) -> Option<Id> {
    match ar.get(e) {
        Node::Bin {
            op: BinOp::Shl | BinOp::Mul,
            a,
            b,
            ..
        } if ar.const_val(b).is_some() => inner_index_load(ar, a),
        Node::Conv {
            k: ConvKind::Zext | ConvKind::Sext,
            a,
            ..
        } => inner_index_load(ar, a),
        Node::Ld { w, addr, .. } if w <= 16 && ar.const_val(addr).is_none() => Some(e),
        _ => None,
    }
}

/// A register (or opaque) addend outside the scaled index, also inside index-table loads: the CVM may know it.
fn unscaled_reg(ar: &Arena, e: Id) -> bool {
    match ar.get(e) {
        Node::R { .. } | Node::U { .. } | Node::Ite { .. } => true,
        Node::Ld { addr, .. } => unscaled_reg(ar, addr),
        Node::Conv { a, .. } => unscaled_reg(ar, a),
        Node::Bin {
            op: BinOp::Add,
            a,
            b,
            ..
        } => [a, b].iter().any(|&x| {
            matches!(
                ar.get(x),
                Node::R { .. } | Node::U { .. } | Node::Ite { .. }
            ) || (ar.const_val(x).is_none() && unscaled_reg(ar, x))
        }),
        Node::Bin {
            op: BinOp::Shl | BinOp::Mul,
            a,
            ..
        } => match ar.get(a) {
            Node::Ld { .. }
            | Node::Conv {
                k: ConvKind::Zext | ConvKind::Sext,
                ..
            } => unscaled_reg(ar, a),
            _ => false,
        },
        _ => false,
    }
}

/// `has_niche_decoded_index`: `idx = (x <s 0) ? x ^ SIGN_BIT : C` (rustc's niche-encoded enum discriminants).
pub fn has_niche_decoded_index(ir: &VexIrsb) -> bool {
    let mut defs: FxHashMap<u32, ExprId> = FxHashMap::default();
    for s in &ir.stmts {
        if let Stmt::WrTmp { tmp, data } = s {
            defs.insert(*tmp, *data);
        }
    }
    let resolve = |mut e: ExprId| {
        while let Some(Expr::RdTmp(t)) = ir.expr(e) {
            match defs.get(t) {
                Some(&d) => e = d,
                None => break,
            }
        }
        e
    };
    let base = |mut e: ExprId| {
        while let Some(Expr::RdTmp(t)) = ir.expr(e) {
            match defs.get(t) {
                Some(&d) if matches!(ir.expr(d), Some(Expr::RdTmp(_))) => e = d,
                _ => break,
            }
        }
        e
    };
    let same_tmp = |a: ExprId, b: ExprId| match (ir.expr(base(a)), ir.expr(base(b))) {
        (Some(Expr::RdTmp(x)), Some(Expr::RdTmp(y))) => x == y,
        _ => false,
    };
    let int_const = |e: ExprId| match ir.expr(e) {
        Some(Expr::Const(c)) => c.int_value(),
        _ => None,
    };
    let sign_test_operand = |cond: ExprId| -> Option<ExprId> {
        let cond = resolve(cond);
        match ir.expr(cond) {
            Some(Expr::Unop { op, arg }) if op_name(*op).ends_with("to1") => {
                let inner = resolve(*arg);
                if let Some(Expr::Binop { op, args }) = ir.expr(inner)
                    && let Some(bits) = op_name(*op).strip_prefix("Iop_Shr")
                    && let Ok(bits) = bits.parse::<u64>()
                    && int_const(args[1]) == Some(bits - 1)
                {
                    return Some(args[0]);
                }
                None
            }
            Some(Expr::Binop { op, args })
                if op_name(*op).starts_with("Iop_CmpLT")
                    && op_name(*op).ends_with('S')
                    && int_const(args[1]) == Some(0) =>
            {
                Some(args[0])
            }
            _ => None,
        }
    };
    for s in &ir.stmts {
        let Stmt::WrTmp { data, .. } = s else {
            continue;
        };
        let Some(Expr::Ite {
            cond,
            iftrue,
            iffalse,
        }) = ir.expr(*data)
        else {
            continue;
        };
        if !matches!(ir.expr(*iffalse), Some(Expr::Const(_))) {
            continue;
        }
        let Some(x) = sign_test_operand(*cond) else {
            continue;
        };
        if let Some(Expr::Binop { op, args }) = ir.expr(resolve(*iftrue))
            && op_name(*op).starts_with("Iop_Xor")
            && args.iter().any(|&a| same_tmp(x, a))
        {
            return true;
        }
    }
    false
}

// --- the resolver ------------------------------------------------------------------------------------------------

pub struct JumpTableResolver {
    pub resolve_calls: bool,
    pub is_arm: bool,
    pub is_mips: bool,
    /// Resolve tables on this architecture (otherwise only the skip classes are answered in Rust).
    pub enabled_arch: bool,
    /// Answer the not-a-jump-table classes (`CFGFast._rust_jt_skip`).
    pub skip: bool,
    /// Also answer tables with an unbounded index (`CFGFast._rust_jt_skip_unbounded`).
    pub skip_unbounded: bool,
    pub instruction_alignment: u64,
    pub target_limit: u64,
    sym: Option<Rc<SymArch>>,
    /// `_is_jumptarget_legal` per target.
    legal: FxHashMap<u64, bool>,
    /// i386 PIC: per function, (block after the thunk call, GOT) when ebx holds the GOT everywhere else.
    pic: FxHashMap<u64, Option<(u64, u64)>>,
    /// `__x86.get_pc_thunk.bx` functions seen so far (and functions known not to be one).
    thunks: Rc<FxHashSet<u64>>,
    not_thunks: FxHashSet<u64>,
    /// The last call's verdict (shadow records).
    pub last: Option<Verdict>,
}

/// Results of one path.
struct PathOut {
    target: Id,
    guards: Vec<(Id, bool)>,
    sp: Option<Id>,
}

struct Job<'a> {
    py: Python<'a>,
    cfg: &'a Bound<'a, PyAny>,
    snap: std::sync::Arc<Snapshot>,
    sym: Rc<SymArch>,
    ar: Arena,
    func_addr: u64,
    jump_addr: u64,
    /// The CVM table: None not computed yet, Some(None) unavailable.
    cvm: Option<Option<Rc<FcpTable>>>,
    gp: Option<(i32, u64)>,
    /// i386 PIC: (ebx offset, block after the thunk call, GOT, function), and the thunks.
    pic: Option<(i32, u64, u64, u64)>,
    thunks: Rc<FxHashSet<u64>>,
}

impl JumpTableResolver {
    pub fn new(
        resolve_calls: bool,
        arch_name: &str,
        enabled_arch: bool,
        skip: bool,
        skip_unbounded: bool,
        instruction_alignment: u64,
        target_limit: u64,
    ) -> Self {
        JumpTableResolver {
            resolve_calls,
            is_arm: arch_name.starts_with("ARM"),
            is_mips: arch_name.starts_with("MIPS"),
            enabled_arch,
            skip,
            skip_unbounded,
            instruction_alignment,
            target_limit,
            sym: None,
            legal: FxHashMap::default(),
            pic: FxHashMap::default(),
            thunks: Rc::new(FxHashSet::default()),
            not_thunks: FxHashSet::default(),
            last: None,
        }
    }

    fn sym_arch(&mut self, cx: &ResolveCx) -> Rc<SymArch> {
        if let Some(s) = &self.sym {
            return s.clone();
        }
        let a = &cx.arch;
        let full_regs: FxHashSet<i32> = a
            .registers
            .values()
            .filter(|(_, size)| size * 8 == a.bits)
            .map(|(off, _)| *off)
            .collect();
        let caller_saved = a
            .default_clobbers
            .as_ref()
            .map(|v| v.iter().map(|(off, _)| *off).collect::<FxHashSet<i32>>());
        let s = Rc::new(SymArch {
            bits: a.bits,
            bytes: a.bytes,
            sp: a.sp_offset,
            bp: a.bp_offset,
            call_pushes_ret: a.call_pushes_ret,
            full_regs,
            caller_saved,
            amd64: cx.snap.arch.name == "AMD64",
        });
        self.sym = Some(s.clone());
        s
    }

    /// `_is_jumptarget_legal`: the block at `target` decodes. None when unknown (the lift needs Python).
    fn is_legal(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        target: u64,
    ) -> PyResult<Option<bool>> {
        if let Some(&v) = self.legal.get(&target) {
            return Ok(Some(v));
        }
        use crate::vexlift::Fallback;
        let v = match cx.lift_nostmt(
            py,
            target,
            VEX_IRSB_MAX_SIZE as i64,
            cx.default_opt_level,
            true,
        )? {
            Ok(s) => s.jumpkind != IJK_NODECODE && s.size != 0,
            Err(
                Fallback::NoBacker
                | Fallback::EmptyWindow
                | Fallback::LiftFailed
                | Fallback::NoInstructions
                | Fallback::PartialNoDecode,
            ) => false,
            Err(_) => return Ok(None),
        };
        self.legal.insert(target, v);
        Ok(Some(v))
    }

    fn graph_node(py: Python<'_>, cx: &ResolveCx, addr: u64) -> PyResult<Option<PNode>> {
        let g = cx.graph.bind(py).borrow();
        let Some(id) = g.first_node_at_addr(addr)? else {
            return Ok(None);
        };
        let (a, size) = g.node_key(id)?;
        Ok(Some(PNode {
            id,
            addr: a,
            size: size.max(0) as u32,
        }))
    }

    /// The blocks that end with the jump: the jump block, and blocks that run into it from a different start (before
    /// normalization a block entered at an earlier address is not a predecessor of the jump block).
    fn entries(py: Python<'_>, cx: &ResolveCx, n: PNode) -> PyResult<Vec<PNode>> {
        let end = n.addr + n.size as u64;
        let mut out = vec![n];
        let g = cx.graph.bind(py).borrow();
        for a in end.saturating_sub(ENTRY_LOOKBACK)..end {
            if a == n.addr {
                continue;
            }
            for id in g.nodes_at_addr(a)? {
                let (addr, size) = g.node_key(id)?;
                if size > 0 && addr + size as u64 == end && !cx.is_hooked(py, addr)? {
                    out.push(PNode {
                        id,
                        addr,
                        size: size as u32,
                    });
                }
            }
        }
        Ok(out)
    }

    /// Whether `addr` is a `__x86.get_pc_thunk.bx` (the CFG marks them with info["get_pc"] = "ebx").
    fn is_thunk(
        &mut self,
        py: Python<'_>,
        store: &Py<crate::recovery_functions::RecoveryFunctions>,
        addr: u64,
    ) -> PyResult<bool> {
        if self.thunks.contains(&addr) {
            return Ok(true);
        }
        if self.not_thunks.contains(&addr) {
            return Ok(false);
        }
        let st = store.bind(py).borrow();
        let is = st.contains(addr)
            && match st.info_get(py, addr, "get_pc")? {
                Some(v) => v.bind(py).extract::<String>().is_ok_and(|s| s == "ebx"),
                None => false,
            };
        drop(st);
        if is {
            Rc::make_mut(&mut self.thunks).insert(addr);
        } else {
            self.not_thunks.insert(addr);
        }
        Ok(is)
    }

    /// i386 PIC: `(block after the thunk call, GOT)` when the function's entry block calls the get_pc thunk, the
    /// next block adds the constant that makes ebx the object's `.got.plt`, and no other block except returns writes
    /// ebx. Cached per function.
    fn pic_info(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        store: &Py<crate::recovery_functions::RecoveryFunctions>,
        func: u64,
    ) -> PyResult<Option<(u64, u64)>> {
        if let Some(r) = self.pic.get(&func) {
            return Ok(*r);
        }
        let r = self.pic_info_uncached(py, cx, store, func)?;
        self.pic.insert(func, r);
        Ok(r)
    }

    fn pic_info_uncached(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        store: &Py<crate::recovery_functions::RecoveryFunctions>,
        func: u64,
    ) -> PyResult<Option<(u64, u64)>> {
        let Some(&(ebx, _)) = cx.arch.registers.get("ebx") else {
            return Ok(None);
        };
        let blocks: Vec<(u64, u32)> = {
            let st = store.bind(py).borrow();
            let Ok(rec) = st.rec(func) else {
                return Ok(None);
            };
            let g = rec.graph.bind(py).borrow();
            g.local_addrs()
                .into_iter()
                .filter_map(|a| g.block_size(a).map(|s| (a, s)))
                .collect()
        };
        let lift = |cx: &mut ResolveCx, addr: u64, size: u32| -> PyResult<Option<Rc<VexIrsb>>> {
            let spec = IrSpec {
                addr,
                max_size: size as i64,
                opt_level: 1,
                cross_insn_opt: true,
                extra_stops: false,
            };
            Ok(cx.ir(py, &spec)?.ok())
        };
        let Some(&(_, entry_size)) = blocks.iter().find(|(a, _)| *a == func) else {
            return Ok(None);
        };
        let Some(entry) = lift(cx, func, entry_size)? else {
            return Ok(None);
        };
        let Some(callee) = entry.next_const() else {
            return Ok(None);
        };
        if jumpkind_name(entry.jumpkind) != "Ijk_Call" || !self.is_thunk(py, store, callee)? {
            return Ok(None);
        }
        let add_block = func + entry_size as u64;
        let Some(&(_, add_size)) = blocks.iter().find(|(a, _)| *a == add_block) else {
            return Ok(None);
        };
        let Some(add_ir) = lift(cx, add_block, add_size)? else {
            return Ok(None);
        };
        // ebx after the block, from its value at block start
        let sym = self.sym_arch(cx);
        let snap = cx.snap.clone();
        let mut ar = Arena::default();
        let mut st = PathState::new(&mut ar, &sym, &snap, None);
        if st.run_block(&add_ir, None).is_none() {
            return Ok(None);
        }
        let Some(v) = st.reg_value(ebx) else {
            return Ok(None);
        };
        drop(st);
        let Node::Bin {
            op: BinOp::Add,
            a,
            b,
            ..
        } = ar.get(v)
        else {
            return Ok(None);
        };
        let (Node::R { off, .. }, Some(imm)) = (ar.get(a), ar.const_val(b)) else {
            return Ok(None);
        };
        if off != ebx {
            return Ok(None);
        }
        let got = add_block.wrapping_add(imm) & 0xffff_ffff;
        let Some(oi) = snap.find_object_containing(func, false) else {
            return Ok(None);
        };
        if !snap.objects[oi]
            .sections
            .iter()
            .any(|s| s.name.as_deref() == Some(".got.plt") && s.vaddr == got)
        {
            return Ok(None);
        }
        for &(addr, size) in &blocks {
            if addr == add_block {
                continue;
            }
            let Some(ir) = lift(cx, addr, size)? else {
                return Ok(None);
            };
            let writes = ir
                .stmts
                .iter()
                .any(|s| matches!(s, Stmt::Put { offset, .. } if (ebx..ebx + 4).contains(offset)));
            if writes && jumpkind_name(ir.jumpkind) != "Ijk_Ret" {
                return Ok(None);
            }
        }
        Ok(Some((add_block, got)))
    }

    /// Predecessors over Boring and FakeRet in-edges; None when the node cannot be extended.
    fn preds(py: Python<'_>, cx: &ResolveCx, n: &PNode) -> PyResult<Option<Vec<PNode>>> {
        let g = cx.graph.bind(py).borrow();
        let recs = g.with_store(|s| {
            let mut out = Vec::new();
            for (src, rec) in s.in_edges_rec(n.id)? {
                let jk = rec
                    .jumpkind_code()
                    .and_then(|c| s.jumpkind_str(c))
                    .map(str::to_owned);
                let (addr, size) = s.node_key(src)?;
                out.push((src, addr, size, jk));
            }
            Ok(out)
        })?;
        drop(g);
        let mut out = Vec::with_capacity(recs.len());
        for (id, addr, size, jk) in recs {
            if !matches!(jk.as_deref(), Some("Ijk_Boring" | "Ijk_FakeRet"))
                || size <= 0
                || cx.is_hooked(py, addr)?
            {
                return Ok(None);
            }
            out.push(PNode {
                id,
                addr,
                size: size as u32,
            });
        }
        Ok(Some(out))
    }

    /// All backward paths of `depth` blocks ending at one of the entry blocks (shorter where a path cannot be
    /// extended), and whether every path was extended to `depth`; incomplete past `cap` paths.
    fn paths_at_depth(
        py: Python<'_>,
        cx: &ResolveCx,
        entries: &[PNode],
        depth: usize,
        cap: usize,
    ) -> PyResult<(Vec<Vec<PNode>>, bool)> {
        let mut res: Vec<Vec<PNode>> = entries.iter().map(|e| vec![*e]).collect();
        let mut complete = true;
        for _ in 1..depth {
            let mut nxt = Vec::new();
            for p in &res {
                let preds = Self::preds(py, cx, &p[0])?;
                match preds {
                    Some(preds)
                        if !preds.is_empty()
                            && !preds.iter().any(|q| p.iter().any(|x| x.id == q.id)) =>
                    {
                        for q in preds {
                            let mut np = Vec::with_capacity(p.len() + 1);
                            np.push(q);
                            np.extend_from_slice(p);
                            nxt.push(np);
                        }
                    }
                    _ => {
                        complete = false;
                        nxt.push(p.clone());
                    }
                }
            }
            if nxt.len() > cap {
                return Ok((res, false));
            }
            res = nxt;
        }
        Ok((res, complete))
    }
}

impl Job<'_> {
    fn snap(&self) -> &Snapshot {
        &self.snap
    }

    fn lift(&self, cx: &mut ResolveCx, n: &PNode) -> PyResult<Option<Rc<VexIrsb>>> {
        let spec = IrSpec {
            addr: n.addr,
            max_size: n.size as i64,
            opt_level: 1,
            cross_insn_opt: true,
            extra_stops: false,
        };
        Ok(match cx.ir(self.py, &spec)? {
            Ok(ir) if ir.size == n.size => Some(ir),
            _ => None,
        })
    }

    fn cvm(&mut self, cx: &mut ResolveCx) -> PyResult<Option<Rc<FcpTable>>> {
        if let Some(t) = &self.cvm {
            return Ok(t.clone());
        }
        let t = match cx.functions(self.py, self.cfg)? {
            Some(store) => match cvm_table(self.py, cx, &store, self.func_addr, self.jump_addr)? {
                Ok(t) => Some(Rc::new(t)),
                Err(_) => None,
            },
            None => None,
        };
        self.cvm = Some(t.clone());
        Ok(t)
    }

    /// Execute a path; None when it cannot be executed.
    fn run_path(
        &mut self,
        cx: &mut ResolveCx,
        path: &[PNode],
        cvm: Option<&FcpTable>,
    ) -> PyResult<Option<PathOut>> {
        let mut irs = Vec::with_capacity(path.len());
        for n in path {
            match self.lift(cx, n)? {
                Some(ir) => irs.push(ir),
                None => return Ok(None),
            }
        }
        let snap = self.snap.clone();
        let sym = self.sym.clone();
        // ebx at path start: unknown at the function entry (before the thunk call), the return address at the
        // block after it, the GOT anywhere else
        let pic = self.pic.map(|(ebx, add_block, got, func)| {
            let start = path[0].addr;
            let v = if start == func {
                None
            } else if start == add_block {
                Some(add_block)
            } else {
                Some(got)
            };
            (ebx, v)
        });
        let thunks = self.thunks.clone();
        let mut st = PathState::new(&mut self.ar, &sym, &snap, cvm)
            .with_gp(self.gp)
            .with_pic(pic.map(|(ebx, v)| (ebx, v, &*thunks)));
        for (i, ir) in irs.iter().enumerate() {
            let next = path.get(i + 1).map(|n| n.addr);
            match st.run_block(ir, next) {
                None => return Ok(None),
                Some(Step::Next(t)) => {
                    let sp = st.reg_value(sym.sp);
                    let guards = std::mem::take(&mut st.guards);
                    drop(st);
                    // conditional values (`ldrls pc, [...]`, `bsf`) under the path's own guards
                    let mut decided: FxHashMap<Id, bool> = FxHashMap::default();
                    for &(g, v) in &guards {
                        let (base, v) = self.ar.bool_base(g, v);
                        decided.insert(base, v);
                    }
                    let mut memo = FxHashMap::default();
                    let target = self.ar.decide_ites(t, &decided, &mut memo);
                    // and inside the guards (`bsf` is an ITE on its operand being zero)
                    let guards = guards
                        .into_iter()
                        .map(|(g, v)| (self.ar.decide_ites(g, &decided, &mut memo), v))
                        .collect();
                    return Ok(Some(PathOut { target, guards, sp }));
                }
                Some(Step::Continue) => {}
            }
        }
        Ok(None)
    }

    fn bounded_by(&self, e: Id, ranges: &Ranges) -> Option<Si> {
        SiEval::new(&self.ar, ranges, self.snap()).eval(e, 0)
    }

    fn try_paths(
        &mut self,
        cx: &mut ResolveCx,
        paths: &[Vec<PNode>],
        use_cvm: bool,
    ) -> PyResult<Try> {
        let cvm = if use_cvm { self.cvm(cx)? } else { None };
        let mut const_targets = Vec::new();
        let mut table: Option<(Id, Id, u32, bool)> = None; // (load, target, width, be)
        let mut per_path: Vec<(Id, Ranges)> = Vec::new();
        let mut union: Option<Si> = None;
        // non-table paths, and unbounded table paths (base_leaf on any, base non-constant on all)
        let mut non_table: Vec<Shape> = Vec::new();
        let mut unbounded: Option<(bool, bool)> = None;
        for p in paths {
            let Some(out) = self.run_path(cx, p, cvm.as_deref())? else {
                return Ok(Try::Fail {
                    why: "path",
                    stop: false,
                });
            };
            let tgt = out.target;
            let mut cls = classify(&self.ar, tgt);
            if cls == Shape::Const {
                const_targets.push(self.ar.const_val(tgt).unwrap());
                continue;
            }
            let lds = table_loads(&self.ar, tgt);
            if cls == Shape::FieldOfLoad && load_parts(&self.ar, lds[0]).0 <= 16 {
                cls = Shape::ByteIndex;
            }
            let ranges = path_ranges(&self.ar, &out.guards, self.sym.amd64, &self.snap);
            if tracing() {
                let guards: Vec<String> = out
                    .guards
                    .iter()
                    .map(|&(g, t)| format!("{}={t}", self.ar.render(g, 0)))
                    .collect();
                let rs: Vec<String> = ranges
                    .iter()
                    .map(|(&e, &(lo, hi))| format!("{}:[{lo:#x},{hi:#x}]", self.ar.render(e, 0)))
                    .collect();
                trace(format!(
                    "path {:x?} target {} guards {guards:?} ranges {rs:?}",
                    p.iter().map(|n| n.addr).collect::<Vec<_>>(),
                    self.ar.render(tgt, 0)
                ));
            }
            if cls == Shape::FieldOfLoad {
                if self
                    .bounded_by(load_parts(&self.ar, lds[0]).1, &ranges)
                    .is_some()
                {
                    return Ok(Try::Fail {
                        why: "vtable_bounded",
                        stop: true,
                    });
                }
                non_table.push(cls);
                continue;
            }
            if !matches!(cls, Shape::Table | Shape::Field | Shape::ByteIndex) {
                non_table.push(cls);
                continue;
            }
            let ld = lds[0];
            let (lw, laddr, lbe) = load_parts(&self.ar, ld);
            if matches!(cls, Shape::Field | Shape::ByteIndex) && lw > 16 {
                if self.bounded_by(laddr, &ranges).is_some() {
                    return Ok(Try::Fail {
                        why: "vtable_bounded",
                        stop: true,
                    });
                }
                non_table.push(Shape::Field);
                continue;
            }
            let Some(a) = self.bounded_by(laddr, &ranges) else {
                let base = match self.ar.get(laddr) {
                    Node::Bin {
                        op: BinOp::Add,
                        a,
                        b,
                        ..
                    } => {
                        let parts: Vec<Id> = [a, b]
                            .into_iter()
                            .filter(|&x| !has_scaled(&self.ar, x))
                            .collect();
                        !parts.is_empty() && parts.iter().all(|&x| self.ar.const_val(x).is_none())
                    }
                    _ => false,
                };
                let base_leaf = unscaled_reg(&self.ar, laddr);
                unbounded = Some(match unbounded {
                    None => (base_leaf, base),
                    Some((l, b)) => (l || base_leaf, b && base),
                });
                continue;
            };
            match table {
                None => table = Some((ld, tgt, lw, lbe)),
                Some((ld0, tgt0, w0, be0)) => {
                    // every path must use the same table shape
                    if lw != w0 || lbe != be0 {
                        return Ok(Try::Fail {
                            why: "paths_differ",
                            stop: true,
                        });
                    }
                    for v in [0u64, 1, 0x7F, 0xFFFF_FFF0] {
                        if self.ar.eval_with(tgt, ld, v) != self.ar.eval_with(tgt0, ld0, v) {
                            if tracing() {
                                trace(format!(
                                    "paths differ at {v:#x}: {} vs {}",
                                    self.ar.render(tgt, 0),
                                    self.ar.render(tgt0, 0)
                                ));
                            }
                            return Ok(Try::Fail {
                                why: "paths_differ",
                                stop: true,
                            });
                        }
                    }
                }
            }
            per_path.push((ld, ranges));
            union = Some(match union {
                None => a,
                Some(u) => {
                    let lo = u.lo.min(a.lo);
                    let hi = u.hi.max(a.hi);
                    let d = u.lo.abs_diff(a.lo);
                    Si {
                        lo,
                        hi,
                        st: gcd(gcd(u.st, a.st), d),
                    }
                }
            });
        }
        if let Some(&s0) = non_table.first() {
            // a skip class needs every path to agree on it
            if non_table.iter().any(|&s| s != s0) || unbounded.is_some() || table.is_some() {
                return Ok(Try::Fail {
                    why: "mixed_shapes",
                    stop: false,
                });
            }
            return Ok(Try::Shape(s0));
        }
        if let Some((base_leaf, base)) = unbounded {
            return Ok(Try::Unbounded {
                base_leaf,
                base: base && table.is_none(),
            });
        }
        let (Some((ld, tgt, lw, be)), Some(a)) = (table, union) else {
            return Ok(Try::Shape(Shape::Const));
        };
        let size = (lw / 8) as u128;
        if a.st == 0 {
            return Ok(Try::Fail {
                why: "single",
                stop: true,
            });
        }
        if a.st < size {
            return Ok(Try::Fail {
                why: "stride_lt_size",
                stop: true,
            });
        }
        let n = a.count();
        if n > MAX_ENTRIES {
            return Ok(Try::Fail {
                why: "too_many",
                stop: true,
            });
        }
        let mut targets = Vec::with_capacity(n as usize);
        for i in 0..n {
            let Ok(at) = u64::try_from(a.lo + i * a.st) else {
                return Ok(Try::Fail {
                    why: "unmapped",
                    stop: true,
                });
            };
            let Some(v) = self.snap().load_word_endian(at, size as usize, be) else {
                return Ok(Try::Fail {
                    why: "unmapped",
                    stop: true,
                });
            };
            let Some(t) = self.ar.eval_with(tgt, ld, v) else {
                return Ok(Try::Fail {
                    why: "transform",
                    stop: true,
                });
            };
            targets.push(t);
        }
        if const_targets.iter().any(|c| !targets.contains(c)) {
            return Ok(Try::Fail {
                why: "const_path_not_in_table",
                stop: true,
            });
        }
        if let Some(two) = self.two_level(ld, tgt, &per_path)? {
            return Ok(two);
        }
        let (_, laddr, _) = load_parts(&self.ar, ld);
        let base = match self.ar.get(laddr) {
            Node::Bin {
                op: BinOp::Add, b, ..
            } => self.ar.const_val(b),
            _ => None,
        };
        let index_at_zero = base.is_some_and(|c| c as u128 == a.lo);
        Ok(Try::Resolved(Answer {
            table: a.lo as u64,
            entry_size: size as u64,
            n: n as u64,
            targets,
            table2: None,
            unbounded: false,
            depth: 0,
            stride: a.st as u64,
            index_at_zero,
            base,
            raised: false,
        }))
    }

    /// `target = f(Ld(T2 + g(Ld8(T1 + idx))))`: the index table T1 is the primary table (one target per case), T2
    /// the secondary one with its raw entries.
    fn two_level(&mut self, ld: Id, tgt: Id, per_path: &[(Id, Ranges)]) -> PyResult<Option<Try>> {
        let (lw, a, be) = load_parts(&self.ar, ld);
        let Node::Bin {
            op: BinOp::Add,
            a: scaled,
            b: base2,
            ..
        } = self.ar.get(a)
        else {
            return Ok(None);
        };
        let Some(base2) = self.ar.const_val(base2) else {
            return Ok(None);
        };
        let Some(inner) = inner_index_load(&self.ar, scaled) else {
            return Ok(None);
        };
        let fail = |why| Ok(Some(Try::Fail { why, stop: true }));
        let mut lo: Option<u128> = None;
        let mut hi: Option<u128> = None;
        for (pld, ranges) in per_path {
            let (_, paddr, _) = load_parts(&self.ar, *pld);
            let inn = match self.ar.get(paddr) {
                Node::Bin {
                    op: BinOp::Add,
                    a: x,
                    ..
                } => inner_index_load(&self.ar, x),
                _ => None,
            };
            let Some(inn) = inn else {
                return Ok(None);
            };
            let (iw, iaddr, _) = load_parts(&self.ar, inn);
            let Some(s) = self.bounded_by(iaddr, ranges) else {
                return Ok(None);
            };
            if s.st != 0 && s.st != (iw / 8) as u128 {
                return Ok(None);
            }
            lo = Some(lo.map_or(s.lo, |l| l.min(s.lo)));
            hi = Some(hi.map_or(s.hi, |h| h.max(s.hi)));
        }
        let (Some(lo), Some(hi)) = (lo, hi) else {
            return Ok(None);
        };
        let (iw, _, ibe) = load_parts(&self.ar, inner);
        let isz = (iw / 8) as u128;
        let n1 = (hi - lo) / isz + 1;
        if n1 > MAX_ENTRIES {
            return Ok(None);
        }
        let osz = (lw / 8) as usize;
        let mut raw: FxHashMap<u64, u64> = FxHashMap::default();
        let mut targets = Vec::with_capacity(n1 as usize);
        for i in 0..n1 {
            let Ok(at) = u64::try_from(lo + i * isz) else {
                return fail("unmapped");
            };
            let Some(v) = self.snap().load_word_endian(at, isz as usize, ibe) else {
                return fail("unmapped");
            };
            let Some(oa) = self.ar.eval_with(a, inner, v) else {
                return Ok(None);
            };
            let rv = match raw.get(&oa) {
                Some(&r) => r,
                None => {
                    let Some(r) = self.snap().load_word_endian(oa, osz, be) else {
                        return fail("unmapped");
                    };
                    raw.insert(oa, r);
                    r
                }
            };
            let Some(t) = self.ar.eval_with(tgt, ld, rv) else {
                return Ok(None);
            };
            targets.push(t);
        }
        let max_oa = raw.keys().copied().max().unwrap_or(base2);
        if max_oa < base2 {
            return fail("table2_below_base");
        }
        let n2 = (max_oa - base2) / osz as u64 + 1;
        if n2 as u128 > MAX_ENTRIES {
            return fail("too_many");
        }
        let mut raw2 = Vec::with_capacity(n2 as usize);
        for i in 0..n2 {
            let Some(r) = self
                .snap()
                .load_word_endian(base2 + i * osz as u64, osz, be)
            else {
                return fail("unmapped");
            };
            raw2.push(r);
        }
        Ok(Some(Try::Resolved(Answer {
            table: lo as u64,
            entry_size: isz as u64,
            n: n1 as u64,
            targets,
            table2: Some((base2, n2 * osz as u64, osz as u64, raw2)),
            unbounded: false,
            depth: 0,
            stride: isz as u64,
            index_at_zero: false,
            base: None,
            raised: false,
        })))
    }
}

/// `kb.xrefs.get_next_xref_addr_by_dst(addr)`.
fn next_xref(cfg: &Bound<'_, PyAny>, addr: u64) -> PyResult<Option<u64>> {
    let py = cfg.py();
    cfg.getattr(intern!(py, "kb"))?
        .getattr(intern!(py, "xrefs"))?
        .call_method1(intern!(py, "get_next_xref_addr_by_dst"), (addr,))?
        .extract()
}

fn plausible_base(snap: &Snapshot, base: u64) -> bool {
    if base == 0 {
        return false;
    }
    match snap.find_section_containing(base) {
        Some((oi, si)) => !snap.objects[oi].sections[si].is_writable,
        None => match snap.find_segment_containing(base) {
            Some((oi, si)) => !snap.objects[oi].segments[si].is_writable,
            None => false,
        },
    }
}

impl JumpTableResolver {
    /// The first depth at which every path is bounded; tables still unbounded then get deeper, wider paths.
    fn bounded(
        &mut self,
        cx: &mut ResolveCx,
        job: &mut Job<'_>,
        entries: &[PNode],
    ) -> PyResult<Try> {
        let mut tried: Vec<Vec<Vec<PNode>>> = Vec::new();
        let first = self.bounded_within(cx, job, entries, MAX_DEPTH, MAX_PATHS, &mut tried)?;
        if !matches!(first, Try::Unbounded { .. }) {
            return Ok(first);
        }
        if tracing() {
            trace("unbounded: deeper and wider paths".to_string());
        }
        Ok(
            match self.bounded_within(
                cx,
                job,
                entries,
                MAX_DEPTH_UNBOUNDED,
                MAX_PATHS_UNBOUNDED,
                &mut tried,
            )? {
                r @ Try::Resolved(_) => r,
                _ => first,
            },
        )
    }

    /// `bounded` within `max_depth` blocks and `cap` paths; path sets in `tried` were tried already.
    fn bounded_within(
        &mut self,
        cx: &mut ResolveCx,
        job: &mut Job<'_>,
        entries: &[PNode],
        max_depth: usize,
        cap: usize,
        tried: &mut Vec<Vec<Vec<PNode>>>,
    ) -> PyResult<Try> {
        let mut best: Option<Try> = None;
        let mut prev_paths: Option<Vec<Vec<PNode>>> = None;
        for depth in 1..=max_depth {
            let (paths, _) = Self::paths_at_depth(job.py, cx, entries, depth, cap)?;
            if prev_paths.as_ref() == Some(&paths) {
                // nothing extended: the same paths give the same answer
                break;
            }
            if tried.contains(&paths) {
                prev_paths = Some(paths);
                continue;
            }
            if tracing() {
                trace(format!("depth {depth}: {} paths", paths.len()));
            }
            let mut out = job.try_paths(cx, &paths, false)?;
            if let Try::Unbounded {
                base_leaf: true, ..
            } = out
            {
                out = job.try_paths(cx, &paths, true)?;
            }
            if tracing() {
                trace(format!(
                    "depth {depth} -> {}",
                    match &out {
                        Try::Resolved(a) => format!("resolved {:#x}/{}", a.table, a.n),
                        Try::Fail { why, stop } => format!("fail {why} stop={stop}"),
                        Try::Unbounded { base_leaf, base } =>
                            format!("unbounded base_leaf={base_leaf} base={base}"),
                        Try::Shape(s) => format!("shape {}", s.name()),
                    }
                ));
            }
            match out {
                Try::Resolved(mut a) => {
                    a.depth = depth;
                    if a.index_at_zero && a.table2.is_none() {
                        a = self.raise_lower_bound(cx, job, entries, a)?;
                    }
                    return Ok(Try::Resolved(a));
                }
                Try::Fail { stop: true, .. } => return Ok(out),
                _ => best = Some(out),
            }
            tried.push(paths.clone());
            prev_paths = Some(paths);
        }
        Ok(best.unwrap_or(Try::Fail {
            why: "nopaths",
            stop: true,
        }))
    }

    /// The table was bounded with index 0 as its first entry; deeper paths may carry a lower bound (a signed
    /// `jle 1` above an unsigned `ja 22`). A deeper bound counts only when every path at that depth is complete and
    /// bounded by the same table with the same upper end; the table then starts at the first reachable entry.
    fn raise_lower_bound(
        &mut self,
        cx: &mut ResolveCx,
        job: &mut Job<'_>,
        entries: &[PNode],
        a: Answer,
    ) -> PyResult<Answer> {
        let hi = a.table + (a.n - 1) * a.stride;
        let mut prev: Option<Vec<Vec<PNode>>> = None;
        for depth in a.depth + 1..=MAX_DEPTH {
            let (paths, complete) = Self::paths_at_depth(job.py, cx, entries, depth, MAX_PATHS)?;
            if tracing() {
                trace(format!(
                    "raise lo: depth {depth} complete {complete} {} paths",
                    paths.len()
                ));
            }
            if !complete || prev.as_ref() == Some(&paths) {
                break;
            }
            let Try::Resolved(b) = job.try_paths(cx, &paths, false)? else {
                break;
            };
            if b.table2.is_some()
                || b.entry_size != a.entry_size
                || b.stride != a.stride
                || b.table + (b.n - 1) * b.stride != hi
            {
                break;
            }
            if b.table > a.table {
                if !(b.table - a.table).is_multiple_of(a.stride) {
                    break;
                }
                let drop = ((b.table - a.table) / a.stride) as usize;
                if b.targets[..] != a.targets[drop..] {
                    break;
                }
                return Ok(Answer {
                    table: b.table,
                    n: a.n - drop as u64,
                    targets: a.targets[drop..].to_vec(),
                    depth,
                    index_at_zero: false,
                    raised: true,
                    ..a
                });
            }
            prev = Some(paths);
        }
        Ok(a)
    }

    /// Python's final-pass rule for tables without a bounds check: min(next referenced data, legal-target scan).
    fn unbounded_size(
        &mut self,
        cx: &mut ResolveCx,
        job: &mut Job<'_>,
        node: PNode,
    ) -> PyResult<Result<Answer, &'static str>> {
        let Some(out) = job.run_path(cx, &[node], None)? else {
            return Ok(Err("unb_path"));
        };
        let tgt = out.target;
        let lds = table_loads(&job.ar, tgt);
        if lds.len() != 1 {
            return Ok(Err("unb_shape"));
        }
        let ld = lds[0];
        let (lw, a, be) = load_parts(&job.ar, ld);
        let Node::Bin {
            op: BinOp::Add,
            a: sc,
            b: base,
            ..
        } = job.ar.get(a)
        else {
            return Ok(Err("unb_base"));
        };
        let Some(base) = job.ar.const_val(base) else {
            return Ok(Err("unb_base"));
        };
        let stride = match job.ar.get(sc) {
            Node::Bin {
                op: BinOp::Shl, b, ..
            } => match job.ar.const_val(b) {
                Some(k) if k < 16 => 1u64 << k,
                _ => return Ok(Err("unb_stride")),
            },
            Node::Bin {
                op: BinOp::Mul, b, ..
            } => match job.ar.const_val(b) {
                Some(c) => c,
                None => return Ok(Err("unb_stride")),
            },
            _ => return Ok(Err("unb_stride")),
        };
        let size = (lw / 8) as u64;
        if stride != size {
            return Ok(Err("unb_stride"));
        }
        if !plausible_base(job.snap(), base) {
            return Ok(Err("unb_base_writable"));
        }
        let nxt = next_xref(job.cfg, base + 1)?;
        let nref = nxt.filter(|&x| x > base).map(|x| (x - base) / stride);
        let mut scan = 0u64;
        let mut entries = Vec::new();
        for i in 0..self.target_limit {
            let Some(v) = job
                .snap()
                .load_word_endian(base + i * stride, size as usize, be)
            else {
                break;
            };
            let Some(t) = job.ar.eval_with(tgt, ld, v) else {
                break;
            };
            match self.is_legal(job.py, cx, t)? {
                Some(true) => {}
                Some(false) => break,
                None => return Ok(Err("unb_legal_unknown")),
            }
            entries.push(t);
            scan += 1;
            if nref.is_some_and(|r| scan >= r) {
                break;
            }
        }
        let n = match nref {
            Some(r) => r.min(scan),
            None => scan,
        };
        if n < 2 {
            return Ok(Err("unb_fail"));
        }
        entries.truncate(n as usize);
        Ok(Ok(Answer {
            table: base,
            entry_size: size,
            n,
            targets: entries,
            table2: None,
            unbounded: true,
            depth: 1,
            stride,
            index_at_zero: false,
            base: Some(base),
            raised: false,
        }))
    }

    fn resolve_inner(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Verdict> {
        let decline = |s: &str| Ok(Verdict::Decline(s.to_owned()));
        let Some(store) = cx.functions(py, cfg)? else {
            return decline("no_store");
        };
        let (block_count, has_preds) = {
            let st = store.bind(py).borrow();
            let Ok(rec) = st.rec(j.func_addr) else {
                return decline("no_function");
            };
            let g = rec.graph.bind(py).borrow();
            let Some(fnode) = g.block_node_at(j.addr) else {
                return decline("no_fnode");
            };
            (g.local_count(), !g.predecessors(fnode)?.is_empty())
        };
        let Some(node) = Self::graph_node(py, cx, j.addr)? else {
            return decline("no_node");
        };
        let entries = Self::entries(py, cx, node)?;
        let gp = if self.is_mips {
            let st = store.bind(py).borrow();
            let value = st.info_get(py, j.func_addr, "gp")?;
            let Some(gp) = value.and_then(|v| v.bind(py).extract::<u64>().ok()) else {
                return decline("mips_no_gp");
            };
            match cx.arch.registers.get("gp") {
                Some(&(off, _)) => Some((off, gp)),
                None => return decline("mips_no_gp"),
            }
        } else {
            None
        };
        let pic = if cx.snap.arch.name == "X86" {
            self.pic_info(py, cx, &store, j.func_addr)?
                .and_then(|(add_block, got)| {
                    cx.arch
                        .registers
                        .get("ebx")
                        .map(|&(ebx, _)| (ebx, add_block, got, j.func_addr))
                })
        } else {
            None
        };
        let sym = self.sym_arch(cx);
        let mut job = Job {
            py,
            cfg,
            snap: cx.snap.clone(),
            sym,
            ar: Arena::default(),
            func_addr: j.func_addr,
            jump_addr: j.addr,
            cvm: None,
            gp,
            pic,
            thunks: self.thunks.clone(),
        };
        let Some(r0) = job.run_path(cx, &[node], None)? else {
            return decline("lift");
        };
        let shape0 = classify(&job.ar, r0.target);
        let sp_up = match r0.sp.map(|e| job.ar.get(e)) {
            Some(Node::Bin {
                op: BinOp::Add,
                a,
                b,
                ..
            }) => {
                matches!(job.ar.get(a), Node::R { off, .. } if off == job.sym.sp)
                    && job
                        .ar
                        .const_val(b)
                        .is_some_and(|c| c > 0 && c < (1u64 << (job.sym.bits - 1)))
            }
            _ => false,
        };
        let is_call = jumpkind_name(j.jumpkind) == "Ijk_Call";
        let pct = is_call || sp_up || block_count <= 5;
        let blade_spec = IrSpec {
            addr: j.addr,
            max_size: VEX_IRSB_MAX_SIZE as i64,
            opt_level: cx.default_opt_level,
            cross_insn_opt: true,
            extra_stops: false,
        };
        let niche = match cx.ir(py, &blade_spec)? {
            Ok(ir) => has_niche_decoded_index(&ir),
            Err(_) => return decline("niche_lift"),
        };
        let unbounded = !self.is_arm && (!has_preds || niche);
        let final_pass: bool = cfg
            .getattr(intern!(py, "_unbounded_jumptable_final_pass"))?
            .is_truthy()?;
        let defer: bool = cfg
            .getattr(intern!(py, "_defer_unbounded_jumptables"))?
            .is_truthy()?;
        if tracing() {
            trace(format!(
                "shape0 {} pct {pct} has_preds {has_preds} niche {niche} unbounded {unbounded} final {final_pass} entries {:x?}",
                shape0.name(),
                entries.iter().map(|e| e.addr).collect::<Vec<_>>()
            ));
        }
        let bounded = self.bounded(cx, &mut job, &entries)?;
        // Python defers a load-shaped jump without function-graph predecessors before the final pass
        let py_defers = unbounded && defer && !final_pass;
        if unbounded && shape0 == Shape::Table {
            if defer && !final_pass {
                // Python defers; its potential-call-table pass may still resolve (or guess) a table first
                if pct {
                    return Ok(match bounded {
                        Try::Resolved(a) => Verdict::Resolved(a),
                        _ => Verdict::Decline("pct_guess".into()),
                    });
                }
                return Ok(Verdict::Deferred);
            }
            let u = self.unbounded_size(cx, &mut job, node)?;
            return Ok(match (u, bounded) {
                (Ok(u), Try::Resolved(b)) => {
                    if b.n < u.n && b.table == u.table {
                        Verdict::Resolved(b)
                    } else {
                        Verdict::Resolved(u)
                    }
                }
                (Ok(u), _) => Verdict::Resolved(u),
                (Err(_), Try::Resolved(b)) if pct => Verdict::Resolved(b),
                (Err(why), _) => Verdict::Decline(why.into()),
            });
        }
        Ok(match bounded {
            Try::Resolved(a) => Verdict::Resolved(a),
            Try::Fail { why, .. } => Verdict::Decline(why.into()),
            // where Python would defer, whether it does depends on its slice; let it decide
            Try::Unbounded { base: true, .. } | Try::Shape(Shape::Field | Shape::FieldOfLoad)
                if self.skip && py_defers =>
            {
                Verdict::Decline("skip_class_deferred".into())
            }
            Try::Unbounded { base: true, .. } if self.skip && shape0 == Shape::Table => {
                Verdict::Skip {
                    class: "table_base",
                }
            }
            Try::Unbounded { base: false, .. }
                if self.skip_unbounded && shape0 == Shape::Table && !py_defers =>
            {
                Verdict::Skip {
                    class: "unbounded_table",
                }
            }
            Try::Unbounded { base_leaf, .. } => Verdict::Decline(format!(
                "unbounded:{}{}",
                shape0.name(),
                if base_leaf { ":base" } else { "" }
            )),
            // `add pc, pc, r` computed jumps on ARM look like `reg`
            Try::Shape(Shape::Reg) if self.skip && !self.is_arm => Verdict::Skip { class: "reg" },
            Try::Shape(s @ (Shape::Field | Shape::FieldOfLoad)) if self.skip => {
                Verdict::Skip { class: s.name() }
            }
            Try::Shape(s) => Verdict::Decline(format!("shape:{}", s.name())),
        })
    }

    /// The acceptance checks: every target executable (or hooked) and decoding, and the table ending before the next
    /// referenced data.
    fn accept(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        a: &Answer,
    ) -> PyResult<Result<(), &'static str>> {
        let mut uniq: Vec<u64> = a.targets.clone();
        uniq.sort_unstable();
        uniq.dedup();
        for &t in &uniq {
            if !cx.is_target_valid(py, t)? {
                return Ok(Err("invalid_target"));
            }
        }
        for &t in &uniq {
            match self.is_legal(py, cx, t)? {
                Some(true) => {}
                Some(false) => return Ok(Err("illegal_target")),
                None => return Ok(Err("legal_unknown")),
            }
        }
        if !a.unbounded
            && let Some(nx) = next_xref(cfg, a.table + 1)?
            && a.table + a.n * a.entry_size > nx
        {
            return Ok(Err("overlaps_next_ref"));
        }
        Ok(Ok(()))
    }

    /// The return value: targets filtered by instruction alignment, like Python's `all_targets`.
    fn aligned(&self, jump_addr: u64, targets: &[u64]) -> Vec<u64> {
        if self.is_arm {
            return if jump_addr & 1 == 1 {
                targets
                    .iter()
                    .copied()
                    .filter(|t| (t.wrapping_sub(1)) % 2 == 0)
                    .collect()
            } else {
                targets.iter().copied().filter(|t| t % 4 == 0).collect()
            };
        }
        let al = self.instruction_alignment;
        if al <= 1 {
            return targets.to_vec();
        }
        targets.iter().copied().filter(|t| t % al == 0).collect()
    }
}

/// A JSON object for shadow records.
pub fn verdict_json(v: &Option<Verdict>) -> String {
    match v {
        None => "{\"cls\": \"none\"}".into(),
        Some(Verdict::Deferred) => "{\"cls\": \"deferred\"}".into(),
        Some(Verdict::Decline(w)) => format!("{{\"cls\": \"decline\", \"why\": \"{w}\"}}"),
        Some(Verdict::Skip { class }) => format!("{{\"cls\": \"skip\", \"why\": \"{class}\"}}"),
        Some(Verdict::Resolved(a)) => {
            let t2 = match &a.table2 {
                Some((b, s, es, raw)) => format!("[{b}, {s}, {es}, {}]", raw.len()),
                None => "null".into(),
            };
            format!(
                "{{\"cls\": \"resolved\", \"table\": {}, \"n\": {}, \"entry_size\": {}, \"stride\": {}, \"depth\": {}, \"unbounded\": {}, \"base\": {}, \"raised\": {}, \"table2\": {t2}, \"targets\": {:?}}}",
                a.table,
                a.n,
                a.entry_size,
                a.stride,
                a.depth,
                a.unbounded,
                a.base.map_or("null".to_string(), |b| b.to_string()),
                a.raised,
                a.targets
            )
        }
    }
}

impl Resolver for JumpTableResolver {
    fn kind(&self) -> &'static str {
        "JumpTableResolver"
    }

    fn timeless(&self) -> bool {
        false
    }

    fn filter(
        &mut self,
        _py: Python<'_>,
        _cx: &mut ResolveCx,
        _cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
    ) -> PyResult<Decision<bool>> {
        Ok(Decision::Done(
            j.jumpkind == IJK_BORING
                || (self.resolve_calls && jumpkind_name(j.jumpkind) == "Ijk_Call"),
        ))
    }

    fn resolve(
        &mut self,
        py: Python<'_>,
        cx: &mut ResolveCx,
        cfg: &Bound<'_, PyAny>,
        j: &JumpSite,
        fx: &mut Effects,
    ) -> PyResult<Decision<Outcome>> {
        self.last = None;
        if !self.enabled_arch && !self.skip {
            return Ok(Decision::Python("arch"));
        }
        // fix for angr issue #3768: the function must exist
        let contains = cfg
            .getattr(intern!(py, "kb"))?
            .getattr(intern!(py, "functions"))?
            .call_method1(intern!(py, "contains_addr"), (j.func_addr,))?
            .is_truthy()?;
        if !contains {
            return Ok(Decision::Done(Outcome::Unresolved));
        }
        let traced = TRACE_ADDRS.with(|t| t.borrow().contains(&j.addr));
        if traced {
            set_trace(true);
            trace(format!(
                "jump {:#x} final {}",
                j.addr,
                cfg.getattr(intern!(py, "_unbounded_jumptable_final_pass"))?
                    .is_truthy()?
            ));
        }
        let mut v = self.resolve_inner(py, cx, cfg, j)?;
        if !self.enabled_arch && !matches!(v, Verdict::Skip { .. }) {
            // only the skip classes are answered in Rust on this architecture
            v = Verdict::Decline("arch".into());
        }
        if self.is_arm
            && j.addr & 1 == 1
            && let Verdict::Resolved(a) = &mut v
        {
            // a THUMB jump block jumps to THUMB code
            for t in a.targets.iter_mut() {
                *t |= 1;
            }
        }
        if let Verdict::Resolved(a) = &v
            && let Err(why) = self.accept(py, cx, cfg, a)?
        {
            v = Verdict::Decline(why.into());
        }
        let out = match &v {
            Verdict::Resolved(a) => {
                cx.count("JumpTableResolver:cls:resolved");
                let mut tables = Vec::new();
                if a.targets.len() > 1 {
                    tables.push(JtInfo {
                        addr: a.table,
                        size: a.n * a.entry_size,
                        entry_size: a.entry_size,
                        entries: a.targets.clone(),
                        primary: true,
                    });
                }
                if let Some((b, s, es, raw)) = &a.table2 {
                    tables.push(JtInfo {
                        addr: *b,
                        size: *s,
                        entry_size: *es,
                        entries: raw.clone(),
                        primary: false,
                    });
                }
                fx.push(Effect::IjJumptable {
                    addr: j.addr,
                    jumptable: a.targets.len() > 1,
                    resolved_targets: a.targets.clone(),
                    tables,
                });
                Decision::Done(Outcome::Resolved(self.aligned(j.addr, &a.targets)))
            }
            Verdict::Deferred => {
                cx.count("JumpTableResolver:cls:deferred");
                Decision::Done(Outcome::Deferred)
            }
            Verdict::Skip { class } => {
                cx.count(&format!("JumpTableResolver:cls:skip:{class}"));
                Decision::Done(Outcome::Unresolved)
            }
            Verdict::Decline(why) => {
                let key = format!("JumpTableResolver:cls:{why}");
                cx.count(&key);
                Decision::Python("declined")
            }
        };
        if traced {
            let mut lines = set_trace(false);
            lines.push(format!("verdict {}", verdict_json(&Some(v.clone()))));
            TRACE_OUT.with(|t| t.borrow_mut().extend(lines));
        }
        self.last = Some(v);
        Ok(out)
    }

    fn shadow_detail(&self) -> Option<String> {
        Some(verdict_json(&self.last))
    }
}

/// Python-side view of a jump's records, for shadow classification.
pub fn py_jumptables<'py>(cfg: &Bound<'py, PyAny>, addr: u64) -> PyResult<Bound<'py, PyAny>> {
    let py = cfg.py();
    let ij = cfg
        .getattr(intern!(py, "indirect_jumps"))?
        .call_method1(intern!(py, "get"), (addr,))?;
    let out = pyo3::types::PyList::empty(py);
    if ij.is_none() {
        return Ok(out.into_any());
    }
    for ji in ij.getattr(intern!(py, "jumptables"))?.try_iter()? {
        let ji = ji?;
        let d = PyDict::new(py);
        for k in ["addr", "size", "entry_size", "entries_guessed"] {
            d.set_item(k, ji.getattr(k)?)?;
        }
        d.set_item("n", ji.getattr("entries")?.len()?)?;
        out.append(d)?;
    }
    Ok(out.into_any())
}
