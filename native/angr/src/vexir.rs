//! An owned, statement-level view of a VEX IRSB (`angr.rustylib.vexir`).
//!
//! [`LifterCore::lift_ir`] lifts like `VEXLifter.lift_vex` with statements and copies the C IRSB into a [`VexIrsb`]
//! right after `vex_lift`: statements 1:1 with `pyvex.IRSB.statements` (same indices, same tmps), an expression
//! arena, the type environment, `next`, the jumpkind and the instruction addresses. Indirect-jump resolvers read
//! VEX coordinates (statement indices, tmps, IMarks), so the view keeps every one of them.

use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::sync::{Mutex, OnceLock};

use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};

use crate::ailment::vex_ffi::{self, IRConst, IRExpr, IRSB, IRStmt};
use crate::ailment::vexop_names::{IOP_BASE, IROP_NAMES};
use crate::vexlift::{
    Fallback, IJK_NODECODE, LiftOptions, LifterCore, VEXLiftResult, jumpkind_name,
};

pub type ExprId = u32;
/// No expression (a NULL `IRExpr*`).
pub const NO_EXPR: ExprId = u32::MAX;

/// An `IRConst`: the tag and the raw payload bits (ints zero-extended, floats as their IEEE bits, vector masks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrConst {
    pub tag: u32,
    pub raw: u64,
}

impl IrConst {
    unsafe fn from_c(c: *const IRConst) -> Self {
        use vex_ffi::*;
        let tag = unsafe { (*c).tag };
        let ico = unsafe { &(*c).ico };
        let raw = unsafe {
            match tag {
                ICO_U1 => ico.u1 as u64,
                ICO_U8 => ico.u8_ as u64,
                ICO_U16 => ico.u16_ as u64,
                ICO_U32 => ico.u32_ as u64,
                ICO_U64 => ico.u64_,
                ICO_U128 => ico.u128 as u64,
                ICO_F32 => ico.f32_.to_bits() as u64,
                ICO_F32I => ico.f32i as u64,
                ICO_F64 => ico.f64_.to_bits(),
                ICO_F64I => ico.f64i,
                ICO_V128 => ico.v128 as u64,
                ICO_V256 => ico.v256 as u64,
                ICO_V512 => ico.v512,
                _ => 0,
            }
        };
        IrConst { tag, raw }
    }

    /// The value of an integer constant (U1..U64), as pyvex's `con.value`.
    pub fn int_value(&self) -> Option<u64> {
        use vex_ffi::*;
        match self.tag {
            ICO_U1 | ICO_U8 | ICO_U16 | ICO_U32 | ICO_U64 => Some(self.raw),
            _ => None,
        }
    }

    /// The `Ity_*` of the constant (`con.type`).
    pub fn ty(&self) -> u32 {
        use vex_ffi::*;
        match self.tag {
            ICO_U1 => ITY_I1,
            ICO_U8 => ITY_I8,
            ICO_U16 => ITY_I16,
            ICO_U32 => ITY_I32,
            ICO_U64 => ITY_I64,
            ICO_U128 => ITY_I128,
            ICO_F32 | ICO_F32I => ITY_F32,
            ICO_F64 | ICO_F64I => ITY_F64,
            ICO_V128 => ITY_V128,
            ICO_V256 => ITY_V256,
            ICO_V512 => ITY_V512,
            _ => ITY_INVALID,
        }
    }

    /// `con.size` in bits.
    pub fn bits(&self) -> u32 {
        vex_ffi::type_size_bits(self.ty())
    }
}

/// `IRRegArray`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegArray {
    pub base: i32,
    pub elem_ty: u32,
    pub n_elems: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Binder(i32),
    Get {
        offset: i32,
        ty: u32,
    },
    GetI {
        descr: RegArray,
        ix: ExprId,
        bias: i32,
    },
    RdTmp(u32),
    Qop {
        op: u32,
        args: [ExprId; 4],
    },
    Triop {
        op: u32,
        args: [ExprId; 3],
    },
    Binop {
        op: u32,
        args: [ExprId; 2],
    },
    Unop {
        op: u32,
        arg: ExprId,
    },
    Load {
        end: u32,
        ty: u32,
        addr: ExprId,
    },
    Const(IrConst),
    Ite {
        cond: ExprId,
        iftrue: ExprId,
        iffalse: ExprId,
    },
    /// `args` is a range into [`VexIrsb::args`].
    CCall {
        callee: &'static str,
        retty: u32,
        args: (u32, u32),
    },
    VecRet,
    GsPtr,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Stmt {
    NoOp,
    IMark {
        addr: u64,
        len: u32,
        delta: u8,
    },
    AbiHint {
        base: ExprId,
        len: i32,
        nia: ExprId,
    },
    Put {
        offset: i32,
        data: ExprId,
    },
    PutI {
        descr: RegArray,
        ix: ExprId,
        data: ExprId,
        bias: i32,
    },
    WrTmp {
        tmp: u32,
        data: ExprId,
    },
    Store {
        end: u32,
        addr: ExprId,
        data: ExprId,
    },
    LoadG {
        end: u32,
        cvt: u32,
        dst: u32,
        addr: ExprId,
        alt: ExprId,
        guard: ExprId,
    },
    StoreG {
        end: u32,
        addr: ExprId,
        data: ExprId,
        guard: ExprId,
    },
    Cas {
        addr: ExprId,
        data_lo: ExprId,
        data_hi: ExprId,
        expd_lo: ExprId,
        expd_hi: ExprId,
        old_lo: u32,
        old_hi: u32,
        end: u32,
    },
    Llsc {
        end: u32,
        result: u32,
        addr: ExprId,
        storedata: ExprId,
    },
    Dirty {
        callee: &'static str,
        guard: ExprId,
        args: (u32, u32),
        tmp: u32,
        mfx: u32,
        maddr: ExprId,
        msize: i32,
        nfx_state: i32,
    },
    Mbe {
        event: u32,
    },
    Exit {
        guard: ExprId,
        dst: IrConst,
        jk: u32,
        offs_ip: i32,
    },
}

/// The statement-level IRSB. Indices into `stmts` are pyvex statement indices.
#[derive(Clone, Debug)]
pub struct VexIrsb {
    /// The lifted address (THUMB bit included), `irsb.addr`.
    pub addr: u64,
    pub size: u32,
    pub jumpkind: u32,
    pub next: ExprId,
    pub tyenv: Vec<u32>,
    pub stmts: Vec<Stmt>,
    pub exprs: Vec<Expr>,
    pub args: Vec<ExprId>,
    pub instructions: u32,
    pub instruction_addresses: Vec<u64>,
    /// `irsb.const_vals` as (tmp, value): lift-time constant propagation results (`const_prop=True` lifts).
    pub const_vals: Vec<(i32, u64)>,
}

fn intern_callee(p: *const c_char) -> &'static str {
    static NAMES: OnceLock<Mutex<HashMap<usize, &'static str>>> = OnceLock::new();
    if p.is_null() {
        return "";
    }
    let mut names = NAMES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    // libVEX helper names are string literals, so the pointer identifies the name
    names.entry(p as usize).or_insert_with(|| {
        Box::leak(
            unsafe { CStr::from_ptr(p) }
                .to_string_lossy()
                .into_owned()
                .into_boxed_str(),
        )
    })
}

struct Copier<'a> {
    irsb: &'a IRSB,
    exprs: Vec<Expr>,
    args: Vec<ExprId>,
}

impl Copier<'_> {
    unsafe fn expr(&mut self, e: *mut IRExpr) -> Result<ExprId, Fallback> {
        use vex_ffi::*;
        if e.is_null() {
            return Ok(NO_EXPR);
        }
        let tag = unsafe { (*e).tag };
        let iex = unsafe { &(*e).iex };
        let out = unsafe {
            match tag {
                IEX_BINDER => Expr::Binder(iex.binder.binder),
                IEX_GET => Expr::Get {
                    offset: iex.get.offset,
                    ty: iex.get.ty,
                },
                IEX_GETI => {
                    let d = &*iex.geti.descr;
                    let ix = self.expr(iex.geti.ix)?;
                    Expr::GetI {
                        descr: RegArray {
                            base: d.base,
                            elem_ty: d.elem_ty,
                            n_elems: d.n_elems,
                        },
                        ix,
                        bias: iex.geti.bias,
                    }
                }
                IEX_RDTMP => Expr::RdTmp(iex.rdtmp.tmp),
                IEX_QOP => {
                    let d = &*iex.qop.details;
                    Expr::Qop {
                        op: d.op,
                        args: [
                            self.expr(d.arg1)?,
                            self.expr(d.arg2)?,
                            self.expr(d.arg3)?,
                            self.expr(d.arg4)?,
                        ],
                    }
                }
                IEX_TRIOP => {
                    let d = &*iex.triop.details;
                    Expr::Triop {
                        op: d.op,
                        args: [self.expr(d.arg1)?, self.expr(d.arg2)?, self.expr(d.arg3)?],
                    }
                }
                IEX_BINOP => Expr::Binop {
                    op: iex.binop.op,
                    args: [self.expr(iex.binop.arg1)?, self.expr(iex.binop.arg2)?],
                },
                IEX_UNOP => Expr::Unop {
                    op: iex.unop.op,
                    arg: self.expr(iex.unop.arg)?,
                },
                IEX_LOAD => Expr::Load {
                    end: iex.load.end,
                    ty: iex.load.ty,
                    addr: self.expr(iex.load.addr)?,
                },
                IEX_CONST => Expr::Const(IrConst::from_c(iex.con.con)),
                IEX_ITE => Expr::Ite {
                    cond: self.expr(iex.ite.cond)?,
                    iftrue: self.expr(iex.ite.iftrue)?,
                    iffalse: self.expr(iex.ite.iffalse)?,
                },
                IEX_CCALL => {
                    let callee = intern_callee((*iex.ccall.cee).name);
                    let args = self.arg_list(iex.ccall.args, usize::MAX)?;
                    Expr::CCall {
                        callee,
                        retty: iex.ccall.retty,
                        args,
                    }
                }
                IEX_VECRET => Expr::VecRet,
                IEX_GSPTR => Expr::GsPtr,
                _ => return Err(Fallback::LiftFailed),
            }
        };
        self.exprs.push(out);
        Ok((self.exprs.len() - 1) as ExprId)
    }

    unsafe fn arg_list(
        &mut self,
        mut p: *mut *mut IRExpr,
        limit: usize,
    ) -> Result<(u32, u32), Fallback> {
        let mut ids = Vec::new();
        while !p.is_null() && !unsafe { *p }.is_null() && ids.len() < limit {
            ids.push(unsafe { self.expr(*p) }?);
            p = unsafe { p.add(1) };
        }
        let start = self.args.len() as u32;
        self.args.extend(ids);
        Ok((start, self.args.len() as u32))
    }

    unsafe fn stmt(&mut self, s: *mut IRStmt) -> Result<Stmt, Fallback> {
        use vex_ffi::*;
        let tag = unsafe { (*s).tag };
        let ist = unsafe { &(*s).ist };
        Ok(unsafe {
            match tag {
                IST_NOOP => Stmt::NoOp,
                IST_IMARK => Stmt::IMark {
                    addr: ist.imark.addr,
                    len: ist.imark.len,
                    delta: ist.imark.delta,
                },
                IST_ABIHINT => Stmt::AbiHint {
                    base: self.expr(ist.abi_hint.base)?,
                    len: ist.abi_hint.len,
                    nia: self.expr(ist.abi_hint.nia)?,
                },
                IST_PUT => Stmt::Put {
                    offset: ist.put.offset,
                    data: self.expr(ist.put.data)?,
                },
                IST_PUTI => {
                    let d = &*ist.puti.details;
                    let descr = &*d.descr;
                    Stmt::PutI {
                        descr: RegArray {
                            base: descr.base,
                            elem_ty: descr.elem_ty,
                            n_elems: descr.n_elems,
                        },
                        ix: self.expr(d.ix)?,
                        data: self.expr(d.data)?,
                        bias: d.bias,
                    }
                }
                IST_WRTMP => Stmt::WrTmp {
                    tmp: ist.wrtmp.tmp,
                    data: self.expr(ist.wrtmp.data)?,
                },
                IST_STORE => Stmt::Store {
                    end: ist.store.end,
                    addr: self.expr(ist.store.addr)?,
                    data: self.expr(ist.store.data)?,
                },
                IST_LOADG => {
                    let d = &*ist.loadg.details;
                    Stmt::LoadG {
                        end: d.end,
                        cvt: d.cvt,
                        dst: d.dst,
                        addr: self.expr(d.addr)?,
                        alt: self.expr(d.alt)?,
                        guard: self.expr(d.guard)?,
                    }
                }
                IST_STOREG => {
                    let d = &*ist.storeg.details;
                    Stmt::StoreG {
                        end: d.end,
                        addr: self.expr(d.addr)?,
                        data: self.expr(d.data)?,
                        guard: self.expr(d.guard)?,
                    }
                }
                IST_CAS => {
                    let d = &*ist.cas.details;
                    Stmt::Cas {
                        addr: self.expr(d.addr)?,
                        data_lo: self.expr(d.data_lo)?,
                        data_hi: self.expr(d.data_hi)?,
                        expd_lo: self.expr(d.expd_lo)?,
                        expd_hi: self.expr(d.expd_hi)?,
                        old_lo: d.old_lo,
                        old_hi: d.old_hi,
                        end: d.end,
                    }
                }
                IST_LLSC => Stmt::Llsc {
                    end: ist.llsc.end,
                    result: ist.llsc.result,
                    addr: self.expr(ist.llsc.addr)?,
                    storedata: self.expr(ist.llsc.storedata)?,
                },
                IST_DIRTY => {
                    let d = &*ist.dirty.details;
                    let callee = intern_callee((*d.cee).name);
                    let guard = self.expr(d.guard)?;
                    // pyvex reads at most 20 arguments
                    let args = self.arg_list(d.args, 20)?;
                    Stmt::Dirty {
                        callee,
                        guard,
                        args,
                        tmp: d.tmp,
                        mfx: d.m_fx,
                        maddr: self.expr(d.m_addr)?,
                        msize: d.m_size,
                        nfx_state: d.n_fx_state,
                    }
                }
                IST_MBE => Stmt::Mbe {
                    event: ist.mbe.event,
                },
                IST_EXIT => Stmt::Exit {
                    guard: self.expr(ist.exit.guard)?,
                    dst: IrConst::from_c(ist.exit.dst),
                    jk: ist.exit.jk,
                    offs_ip: ist.exit.offs_ip,
                },
                _ => return Err(Fallback::LiftFailed),
            }
        })
    }
}

/// Copy the live lift result into a [`VexIrsb`], applying `pyvex.lift`'s acceptance rules (anything pyvex would
/// re-lift, merge or hand to another lifter is a [`Fallback`]).
///
/// # Safety
/// `r` must be the live `_lift_r` of a successful lift.
pub(crate) unsafe fn copy_ir(r: *const VEXLiftResult, addr: u64) -> Result<VexIrsb, Fallback> {
    let r = unsafe { &*r };
    if r.irsb.is_null() || r.size <= 0 {
        return Err(Fallback::NoInstructions);
    }
    let irsb = unsafe { &*r.irsb };
    let size = r.size as u32;
    if irsb.jumpkind == IJK_NODECODE {
        // pyvex.lift keeps only an intentional NoDecode (a constant next other than the fall-through)
        let next = irsb.next;
        let intentional = !next.is_null()
            && unsafe { (*next).tag } == vex_ffi::IEX_CONST
            && unsafe { IrConst::from_c((*next).iex.con.con) }
                .int_value()
                .is_some_and(|v| v != addr.wrapping_add(size as u64));
        if !intentional {
            return Err(Fallback::PartialNoDecode);
        }
    }
    let mut c = Copier {
        irsb,
        exprs: Vec::with_capacity(irsb.stmts_used.max(0) as usize * 2),
        args: Vec::new(),
    };
    let n = irsb.stmts_used.max(0) as usize;
    let mut stmts = Vec::with_capacity(n);
    for i in 0..n {
        let s = unsafe { *irsb.stmts.add(i) };
        if s.is_null() {
            return Err(Fallback::LiftFailed);
        }
        stmts.push(unsafe { c.stmt(s) }?);
    }
    let next = unsafe { c.expr(irsb.next) }?;
    let tyenv = unsafe {
        let te = &*c.irsb.tyenv;
        (0..te.types_used.max(0) as usize)
            .map(|i| *te.types.add(i))
            .collect()
    };
    let insts = r.insts.max(0) as usize;
    Ok(VexIrsb {
        addr,
        size,
        jumpkind: irsb.jumpkind,
        next,
        tyenv,
        stmts,
        exprs: c.exprs,
        args: c.args,
        instructions: r.insts.max(0) as u32,
        instruction_addresses: r.inst_addrs[..insts.min(r.inst_addrs.len())].to_vec(),
        const_vals: r.const_vals[..(r.const_val_count.max(0) as usize).min(r.const_vals.len())]
            .iter()
            .map(|c| (c.tmp, c.value))
            .collect(),
    })
}

impl VexIrsb {
    pub fn expr(&self, id: ExprId) -> Option<&Expr> {
        self.exprs.get(id as usize)
    }

    pub fn arg_ids(&self, range: (u32, u32)) -> &[ExprId] {
        &self.args[range.0 as usize..range.1 as usize]
    }

    pub fn tmp_type(&self, tmp: u32) -> u32 {
        self.tyenv
            .get(tmp as usize)
            .copied()
            .unwrap_or(vex_ffi::ITY_INVALID)
    }

    /// pyvex `expr.result_type(tyenv)`.
    pub fn result_type(&self, id: ExprId) -> u32 {
        use vex_ffi::*;
        match self.expr(id) {
            Some(Expr::Get { ty, .. }) | Some(Expr::Load { ty, .. }) => *ty,
            Some(Expr::GetI { descr, .. }) => descr.elem_ty,
            Some(Expr::RdTmp(t)) => self.tmp_type(*t),
            Some(Expr::Const(c)) => c.ty(),
            Some(Expr::CCall { retty, .. }) => *retty,
            Some(Expr::Unop { op, .. }) | Some(Expr::Binop { op, .. }) => {
                vex_ffi::op_result_type(*op)
            }
            Some(Expr::Triop { op, .. }) | Some(Expr::Qop { op, .. }) => {
                vex_ffi::op_result_type(*op)
            }
            Some(Expr::Ite { iftrue, .. }) => self.result_type(*iftrue),
            _ => ITY_INVALID,
        }
    }

    /// pyvex `expr.result_size(tyenv)` in bits.
    pub fn result_bits(&self, id: ExprId) -> u32 {
        vex_ffi::type_size_bits(self.result_type(id))
    }

    /// The tmp `next` reads, if it is an `RdTmp`.
    pub fn next_tmp(&self) -> Option<u32> {
        match self.expr(self.next) {
            Some(Expr::RdTmp(t)) => Some(*t),
            _ => None,
        }
    }

    /// The integer constant `next` holds, if it is a `Const`.
    pub fn next_const(&self) -> Option<u64> {
        match self.expr(self.next) {
            Some(Expr::Const(c)) => c.int_value(),
            _ => None,
        }
    }

    /// `_find_tmp_write_stmt_and_ins` of MemoryLoadResolver/ConstantResolver: the last statement writing `tmp` and
    /// the address of the IMark before it.
    pub fn find_tmp_write_stmt_and_ins(&self, tmp: u32) -> Option<(usize, u64)> {
        let mut stmt_idx = None;
        for (idx, stmt) in self.stmts.iter().enumerate().rev() {
            match stmt {
                Stmt::IMark { addr, delta, .. } if stmt_idx.is_some() => {
                    return stmt_idx.map(|s| (s, addr + *delta as u64));
                }
                Stmt::WrTmp { tmp: t, .. } if *t == tmp => stmt_idx = Some(idx),
                _ => {}
            }
        }
        None
    }

    /// `angr.utils.vex.get_tmp_def_stmt`: the index of the statement that defines `tmp`.
    pub fn tmp_def_stmt(&self, tmp: u32) -> Option<usize> {
        self.stmts
            .iter()
            .position(|s| matches!(s, Stmt::WrTmp { tmp: t, .. } if *t == tmp))
    }
}

pub fn op_name(op: u32) -> &'static str {
    op.checked_sub(IOP_BASE)
        .and_then(|i| IROP_NAMES.get(i as usize).copied())
        .unwrap_or("Iop_INVALID")
}

/// `VEXLifter._first_stoppoint`: the first IMark after the first one that sits at a stop point.
pub fn first_stoppoint(ir: &VexIrsb, is_stop: &mut dyn FnMut(u64) -> bool) -> Option<u64> {
    let mut first_imark = true;
    for stmt in &ir.stmts {
        if let Stmt::IMark { addr, delta, .. } = stmt {
            let a = addr + *delta as u64;
            if !first_imark {
                if is_stop(a) {
                    return Some(a);
                }
                if *delta != 0 && is_stop(*addr) {
                    return Some(a);
                }
            }
            first_imark = false;
        }
    }
    None
}

impl LifterCore {
    /// Lift with statements the way `VEXLifter.lift_vex` does (cache aside): the first lift, then a re-lift cut at
    /// the first stop point after the first instruction. The caller holds the GIL and `_libvex_lock`.
    pub fn lift_ir(
        &self,
        addr: u64,
        max_size: i64,
        initial_regs: &[(u32, u32, u64)],
        opts: &LiftOptions,
        is_stop: &mut dyn FnMut(u64) -> bool,
    ) -> Result<VexIrsb, Fallback> {
        let (r, insn_addr) = self.raw_lift(addr, max_size, initial_regs, opts)?;
        let ir = unsafe { copy_ir(r, insn_addr) }?;
        let Some(stop) = first_stoppoint(&ir, is_stop) else {
            return Ok(ir);
        };
        let real_addr = if self.is_arm { addr & !1 } else { addr };
        let size = stop as i64 - real_addr as i64;
        let (r, insn_addr) = self.raw_lift(addr, size, initial_regs, opts)?;
        unsafe { copy_ir(r, insn_addr) }
    }
}

// ---------------------------------------------------------------------------
// Python view (for the IR-vs-pyvex tests and debugging)
// ---------------------------------------------------------------------------

fn type_name(ty: u32) -> &'static str {
    use vex_ffi::*;
    match ty {
        ITY_INVALID => "Ity_INVALID",
        ITY_I1 => "Ity_I1",
        ITY_I8 => "Ity_I8",
        ITY_I16 => "Ity_I16",
        ITY_I32 => "Ity_I32",
        ITY_I64 => "Ity_I64",
        ITY_I128 => "Ity_I128",
        ITY_F16 => "Ity_F16",
        ITY_F32 => "Ity_F32",
        ITY_F64 => "Ity_F64",
        ITY_D32 => "Ity_D32",
        ITY_D64 => "Ity_D64",
        ITY_D128 => "Ity_D128",
        ITY_F128 => "Ity_F128",
        ITY_V128 => "Ity_V128",
        ITY_V256 => "Ity_V256",
        ITY_V512 => "Ity_V512",
        _ => "Ity_?",
    }
}

fn const_tag_name(tag: u32) -> &'static str {
    use vex_ffi::*;
    match tag {
        ICO_U1 => "Ico_U1",
        ICO_U8 => "Ico_U8",
        ICO_U16 => "Ico_U16",
        ICO_U32 => "Ico_U32",
        ICO_U64 => "Ico_U64",
        ICO_U128 => "Ico_U128",
        ICO_F32 => "Ico_F32",
        ICO_F32I => "Ico_F32i",
        ICO_F64 => "Ico_F64",
        ICO_F64I => "Ico_F64i",
        ICO_V128 => "Ico_V128",
        ICO_V256 => "Ico_V256",
        ICO_V512 => "Ico_V512",
        _ => "Ico_?",
    }
}

fn mbe_name(e: u32) -> &'static str {
    match e {
        0x1C00 => "Imbe_Fence",
        0x1C01 => "Imbe_CancelReservation",
        _ => "Imbe_?",
    }
}

fn effect_name(fx: u32) -> &'static str {
    match fx {
        0x1B00 => "Ifx_None",
        0x1B01 => "Ifx_Read",
        0x1B02 => "Ifx_Write",
        0x1B03 => "Ifx_Modify",
        _ => "Ifx_?",
    }
}

impl VexIrsb {
    /// pyvex's `con.value`, except that floats are given as their IEEE bits (NaN-safe comparisons).
    fn py_const<'py>(py: Python<'py>, c: &IrConst) -> PyResult<Bound<'py, PyTuple>> {
        use vex_ffi::*;
        let name = const_tag_name(c.tag);
        let value: Bound<'py, PyAny> = match c.tag {
            ICO_V128 | ICO_V256 | ICO_V512 => {
                // each set bit i becomes a 0xff byte i (pyvex V128/V256 `_from_c`)
                let nbytes = c.bits() as usize / 8;
                let bytes: Vec<u8> = (0..nbytes)
                    .map(|i| if (c.raw >> i) & 1 == 1 { 0xff } else { 0 })
                    .collect();
                py.get_type::<pyo3::types::PyInt>().call_method1(
                    "from_bytes",
                    (pyo3::types::PyBytes::new(py, &bytes), "little"),
                )?
            }
            _ => c.raw.into_pyobject(py)?.into_any(),
        };
        PyTuple::new(py, [name.into_pyobject(py)?.into_any(), value])
    }

    fn py_expr<'py>(&self, py: Python<'py>, id: ExprId) -> PyResult<Bound<'py, PyAny>> {
        let Some(e) = self.expr(id) else {
            return Ok(py.None().into_bound(py));
        };
        let t: Bound<'py, PyTuple> = match e {
            Expr::Binder(b) => ("Binder", *b).into_pyobject(py)?,
            Expr::Get { offset, ty } => ("Get", *offset, type_name(*ty)).into_pyobject(py)?,
            Expr::GetI { descr, ix, bias } => (
                "GetI",
                (descr.base, type_name(descr.elem_ty), descr.n_elems),
                self.py_expr(py, *ix)?,
                *bias,
            )
                .into_pyobject(py)?,
            Expr::RdTmp(t) => ("RdTmp", *t).into_pyobject(py)?,
            Expr::Qop { op, args } => {
                ("Qop", op_name(*op), self.py_list(py, args)?).into_pyobject(py)?
            }
            Expr::Triop { op, args } => {
                ("Triop", op_name(*op), self.py_list(py, args)?).into_pyobject(py)?
            }
            Expr::Binop { op, args } => {
                ("Binop", op_name(*op), self.py_list(py, args)?).into_pyobject(py)?
            }
            Expr::Unop { op, arg } => {
                ("Unop", op_name(*op), self.py_list(py, &[*arg])?).into_pyobject(py)?
            }
            Expr::Load { end, ty, addr } => (
                "Load",
                vex_ffi::endness_str(*end),
                type_name(*ty),
                self.py_expr(py, *addr)?,
            )
                .into_pyobject(py)?,
            Expr::Const(c) => ("Const", Self::py_const(py, c)?).into_pyobject(py)?,
            Expr::Ite {
                cond,
                iftrue,
                iffalse,
            } => (
                "ITE",
                self.py_expr(py, *cond)?,
                self.py_expr(py, *iftrue)?,
                self.py_expr(py, *iffalse)?,
            )
                .into_pyobject(py)?,
            Expr::CCall {
                callee,
                retty,
                args,
            } => (
                "CCall",
                type_name(*retty),
                *callee,
                self.py_list(py, self.arg_ids(*args))?,
            )
                .into_pyobject(py)?,
            Expr::VecRet => ("VECRET",).into_pyobject(py)?,
            Expr::GsPtr => ("GSPTR",).into_pyobject(py)?,
        };
        Ok(t.into_any())
    }

    fn py_list<'py>(&self, py: Python<'py>, ids: &[ExprId]) -> PyResult<Bound<'py, PyTuple>> {
        let items = ids
            .iter()
            .map(|&i| self.py_expr(py, i))
            .collect::<PyResult<Vec<_>>>()?;
        PyTuple::new(py, items)
    }

    fn py_stmt<'py>(&self, py: Python<'py>, s: &Stmt) -> PyResult<Bound<'py, PyAny>> {
        let e = |id: ExprId| self.py_expr(py, id);
        let t: Bound<'py, PyTuple> = match s {
            Stmt::NoOp => ("NoOp",).into_pyobject(py)?,
            Stmt::IMark { addr, len, delta } => ("IMark", *addr, *len, *delta).into_pyobject(py)?,
            Stmt::AbiHint { base, len, nia } => {
                ("AbiHint", e(*base)?, *len, e(*nia)?).into_pyobject(py)?
            }
            Stmt::Put { offset, data } => ("Put", *offset, e(*data)?).into_pyobject(py)?,
            Stmt::PutI {
                descr,
                ix,
                data,
                bias,
            } => (
                "PutI",
                (descr.base, type_name(descr.elem_ty), descr.n_elems),
                e(*ix)?,
                *bias,
                e(*data)?,
            )
                .into_pyobject(py)?,
            Stmt::WrTmp { tmp, data } => ("WrTmp", *tmp, e(*data)?).into_pyobject(py)?,
            Stmt::Store { end, addr, data } => {
                ("Store", vex_ffi::endness_str(*end), e(*addr)?, e(*data)?).into_pyobject(py)?
            }
            Stmt::LoadG {
                end,
                cvt,
                dst,
                addr,
                alt,
                guard,
            } => (
                "LoadG",
                vex_ffi::endness_str(*end),
                *cvt,
                *dst,
                e(*addr)?,
                e(*alt)?,
                e(*guard)?,
            )
                .into_pyobject(py)?,
            Stmt::StoreG {
                end,
                addr,
                data,
                guard,
            } => (
                "StoreG",
                vex_ffi::endness_str(*end),
                e(*addr)?,
                e(*data)?,
                e(*guard)?,
            )
                .into_pyobject(py)?,
            Stmt::Cas {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_hi,
                end,
            } => (
                "CAS",
                e(*addr)?,
                e(*data_lo)?,
                e(*data_hi)?,
                e(*expd_lo)?,
                e(*expd_hi)?,
                *old_lo,
                *old_hi,
                vex_ffi::endness_str(*end),
            )
                .into_pyobject(py)?,
            Stmt::Llsc {
                end,
                result,
                addr,
                storedata,
            } => (
                "LLSC",
                vex_ffi::endness_str(*end),
                *result,
                e(*addr)?,
                e(*storedata)?,
            )
                .into_pyobject(py)?,
            Stmt::Dirty {
                callee,
                guard,
                args,
                tmp,
                mfx,
                maddr,
                msize,
                nfx_state,
            } => (
                "Dirty",
                *callee,
                e(*guard)?,
                self.py_list(py, self.arg_ids(*args))?,
                *tmp,
                effect_name(*mfx),
                e(*maddr)?,
                *msize,
                *nfx_state,
            )
                .into_pyobject(py)?,
            Stmt::Mbe { event } => ("MBE", mbe_name(*event)).into_pyobject(py)?,
            Stmt::Exit {
                guard,
                dst,
                jk,
                offs_ip,
            } => (
                "Exit",
                e(*guard)?,
                Self::py_const(py, dst)?,
                jumpkind_name(*jk),
                *offs_ip,
            )
                .into_pyobject(py)?,
        };
        Ok(t.into_any())
    }
}

/// A lifted [`VexIrsb`], exposed for tests.
#[pyclass(name = "IrBlock", module = "angr.rustylib.vexir", frozen)]
pub struct PyIrBlock {
    pub inner: VexIrsb,
}

#[pymethods]
impl PyIrBlock {
    #[getter]
    fn addr(&self) -> u64 {
        self.inner.addr
    }

    #[getter]
    fn size(&self) -> u32 {
        self.inner.size
    }

    #[getter]
    fn jumpkind(&self) -> &'static str {
        jumpkind_name(self.inner.jumpkind)
    }

    #[getter]
    fn instructions(&self) -> u32 {
        self.inner.instructions
    }

    #[getter]
    fn instruction_addresses(&self) -> Vec<u64> {
        self.inner.instruction_addresses.clone()
    }

    /// `(statements, next, tyenv)` as nested tuples (see tests/analyses/cfg/test_vexir.py for the format).
    fn to_tuple<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        let ir = &self.inner;
        let stmts = PyList::empty(py);
        for s in &ir.stmts {
            stmts.append(ir.py_stmt(py, s)?)?;
        }
        let tyenv: Vec<&str> = ir.tyenv.iter().map(|&t| type_name(t)).collect();
        (stmts, ir.py_expr(py, ir.next)?, tyenv).into_pyobject(py)
    }
}

pub fn vexir(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyIrBlock>()?;
    Ok(())
}
