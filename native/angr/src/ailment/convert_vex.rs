//! Rust port of `angr.ailment.converter_vex` (the VEX -> AIL converter).
//!
//! Two entry points on [`VEXIRSBConverter`]:
//!   * `convert_from_lift(arch, addr, data, manager, ...)` -- the default fast
//!     path. Lifts directly into libVEX via FFI and walks the C `IRSB`,
//!     building AIL objects natively. No pyvex Python `IRSB` is materialized.
//!   * `convert(irsb, manager)` -- fallback that walks a cached pyvex Python
//!     `IRSB` object via PyO3 attribute access.
//!
//! Both share one conversion core ([`Conv`]) over the [`IrReader`] trait;
//! only the IR-reading layer differs.

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::ailment::CachedHash;
use crate::ailment::ail_expr::{
    AilExpression, CFGTarget, ExprHeader, ExprInner, RoundingModeOrExpr,
};
use crate::ailment::ail_stmt::{AilStatement, Statement, StmtHeader, StmtInner};
use crate::ailment::block::Block;
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::{ConvertType, RoundingMode};
use crate::ailment::manager::Manager;
use crate::ailment::tags::{TagExtra, TagKey, Tags};
use crate::ailment::vex_ffi::{self, IRExpr, IRSB};
use crate::ailment::vexop;

const DEFAULT_STATEMENT: i64 = -2;
const IRTEMP_INVALID: u32 = 0xFFFF_FFFF;

/// Error type for the op converters. `Unsupported` mirrors the Python
/// converter's `UnsupportedIROpError` (caught -> `DirtyExpression`); `Py`
/// carries a genuine Python error that must propagate.
enum ConvErr {
    Unsupported,
    Py(PyErr),
}

impl From<PyErr> for ConvErr {
    fn from(e: PyErr) -> Self {
        ConvErr::Py(e)
    }
}

// ===========================================================================
// IR node descriptions produced by a reader and consumed by the core.
// ===========================================================================

/// A converted constant value + its width.
struct ConstVal {
    value: ConstValue,
    bits: u32,
}

/// How a reader identifies a VEX op. The C reader has the libVEX integer; the
/// Python-IRSB reader has the op *name* (plus the pyvex-reported result size),
/// which is the only way to classify ops libVEX emits but pyvex does not expose
/// as an integer constant -- e.g. `Iop_DivU8` / `Iop_Mod8`, which pyvex's Python
/// lifter synthesizes for AAM/AAD.
enum OpRef {
    Int(u32),
    Named { name: String, result_bits: u32 },
}

impl OpRef {
    fn simop(&self) -> Result<vexop::SimOpInfo, ()> {
        match self {
            OpRef::Int(i) => vexop::vexop_to_simop(*i),
            // Prefer the exact integer path for ops pyvex *does* expose (so the
            // output size still comes from libVEX `typeOfPrimop`); fall back to
            // name-only classification for the ones it doesn't.
            OpRef::Named { name, result_bits } => match vexop::op_int_from_name(name) {
                Some(i) => vexop::vexop_to_simop(i),
                None => vexop::vexop_to_simop_by_name(name, *result_bits),
            },
        }
    }

    /// Op name, for the `Not1` special-case and unsupported-op DirtyExpression
    /// labels.
    fn label(&self) -> String {
        match self {
            OpRef::Int(i) => op_label(*i),
            OpRef::Named { name, .. } => name.clone(),
        }
    }
}

enum ExprKind<E> {
    RdTmp {
        tmp: u32,
        bits: u32,
    },
    Get {
        offset: i64,
        bits: u32,
    },
    Load {
        end: String,
        bits: u32,
        addr: E,
    },
    Unop {
        op: OpRef,
        arg: E,
    },
    Binop {
        op: OpRef,
        arg1: E,
        arg2: E,
    },
    Triop {
        op: OpRef,
        args: Vec<E>,
    },
    Const {
        value: ConstValue,
        bits: u32,
    },
    Ite {
        cond: E,
        iftrue: E,
        iffalse: E,
    },
    CCall {
        callee: String,
        args: Vec<E>,
        bits: u32,
    },
    /// Anything unsupported -> DirtyExpression(label, bits).
    Unsupported {
        label: String,
        bits: u32,
    },
}

enum StmtKind<E> {
    IMark {
        addr: i64,
        delta: i64,
    },
    AbiHint,
    NoOp,
    WrTmp {
        tmp: u32,
        data: E,
        data_bits: u32,
    },
    Put {
        offset: i64,
        data: E,
    },
    Store {
        addr: E,
        data: E,
        size_bytes: i32,
        endness: String,
    },
    Exit {
        guard: E,
        dst: E,
        jk: String,
    },
    LoadG {
        dst: u32,
        dst_bits: u32,
        cvt: String,
        addr: E,
        alt: E,
        guard: E,
        end: String,
    },
    StoreG {
        addr: E,
        data: E,
        size_bytes: i32,
        endness: String,
        guard: E,
    },
    Cas {
        addr: E,
        data_lo: E,
        data_hi: Option<E>,
        expd_lo: E,
        expd_hi: Option<E>,
        old_lo: u32,
        old_lo_bits: u32,
        old_hi: Option<u32>,
        old_hi_bits: u32,
        endness: String,
    },
    Dirty {
        callee: String,
        args: Vec<E>,
        guard: Option<E>,
        mfx: Option<String>,
        maddr: Option<E>,
        msize: Option<i64>,
        tmp: Option<u32>,
        tmp_bits: u32,
    },
    /// Unknown statement -> DirtyStatement(DirtyExpression(str(stmt))).
    Other {
        label: String,
    },
}

// ===========================================================================
// IrReader: abstracts "read a VEX IRSB" over the C and Python representations.
// ===========================================================================

trait IrReader {
    type E: Clone;

    fn block_addr(&self) -> i64;
    fn block_size(&self) -> Option<i64>;
    fn jumpkind(&self) -> String;
    fn next_expr(&self) -> Self::E;

    fn num_stmts(&self) -> usize;
    fn stmt_kind(&self, py: Python<'_>, i: usize) -> PyResult<StmtKind<Self::E>>;

    fn expr_kind(&self, py: Python<'_>, e: &Self::E) -> PyResult<ExprKind<Self::E>>;
    /// VEX `result_size` (in bits) of an expression; 0 if undeterminable.
    fn result_bits(&self, e: &Self::E) -> u32;
}

// ===========================================================================
// Arch helpers (cached).
// ===========================================================================

struct ArchCtx<'py> {
    arch: Bound<'py, PyAny>,
    byte_width: u32,
    bits: u32,
    reg_name_memo: HashMap<(i64, u32), Option<String>>,
}

impl<'py> ArchCtx<'py> {
    fn new(arch: Bound<'py, PyAny>) -> PyResult<Self> {
        let byte_width: u32 = arch.getattr("byte_width")?.extract()?;
        let bits: u32 = arch.getattr("bits")?.extract()?;
        Ok(Self {
            arch,
            byte_width,
            bits,
            reg_name_memo: HashMap::new(),
        })
    }

    fn reg_name(&mut self, offset: i64, size: u32) -> PyResult<Option<String>> {
        if let Some(v) = self.reg_name_memo.get(&(offset, size)) {
            return Ok(v.clone());
        }
        let res = self
            .arch
            .call_method1("translate_register_name", (offset, size))?;
        let name: Option<String> = if res.is_none() {
            None
        } else {
            Some(res.extract()?)
        };
        self.reg_name_memo.insert((offset, size), name.clone());
        Ok(name)
    }
}

// ===========================================================================
// Conversion core.
//
// Builds `AilExpression` / `AilStatement` values natively -- no Python
// constructor calls; each statement is wrapped into a `Statement` pyclass
// object exactly once, when the final `Block` is assembled.
//
// Field defaults (depth, bits, tags) mirror the `_new_*` factories in
// `ail_expr.rs` / `ail_stmt.rs` exactly, and atom idx allocation follows the
// deleted Python converter's left-to-right argument evaluation order, so the
// output stays idx-identical to the factory-calling implementation.
// ===========================================================================

struct Conv<'py, 'r, R: IrReader> {
    py: Python<'py>,
    reader: &'r R,
    arch: ArchCtx<'py>,
    // Atom allocation: a local counter seeded from the Manager's `atom_ctr`
    // and committed back only when the conversion succeeds -- a failing fast
    // path leaves the Manager untouched, so the fallback stays idx-identical.
    // The Manager is always the Rust pyclass (the typed `run()` signature
    // enforces it), so no per-atom Python `next_atom()` round-trip is needed.
    atom: i64,
    ins_addr: Option<i64>,
    block_addr: i64,
    vex_stmt_idx: i64,
}

impl<'py, 'r, R: IrReader> Conv<'py, 'r, R> {
    fn next_atom(&mut self) -> i64 {
        let v = self.atom;
        self.atom += 1;
        v
    }

    /// Standard tags (ins_addr / vex_block_addr / vex_stmt_idx).
    fn tags(&self) -> Tags {
        Tags {
            ins_addr: self.ins_addr,
            vex_block_addr: Some(self.block_addr),
            vex_stmt_idx: Some(self.vex_stmt_idx as i32),
            block_idx: None,
            extras: HashMap::new(),
        }
    }

    // ---- expression conversion ----------------------------------------

    fn convert_expr(&mut self, e: &R::E) -> PyResult<AilExpression> {
        let kind = self.reader.expr_kind(self.py, e)?;
        match kind {
            ExprKind::RdTmp { tmp, bits } => self.make_tmp(tmp as i64, bits),
            ExprKind::Get { offset, bits } => self.make_register(offset, bits),
            ExprKind::Load { end, bits, addr } => {
                // Python arg eval order: Load(next_atom(), convert(addr), ...).
                let idx = self.next_atom();
                let addr_e = self.convert_expr(&addr)?;
                let size = (bits / 8) as i32;
                let depth = addr_e.header.depth + 1;
                Ok(AilExpression {
                    header: ExprHeader::new(idx, depth, size.wrapping_mul(8) as u32, self.tags()),
                    inner: ExprInner::Load {
                        addr: Arc::new(addr_e),
                        size,
                        endness: end,
                        guard: None,
                        alt: None,
                    },
                })
            }
            ExprKind::Const { value, bits } => self.make_const(value, bits),
            ExprKind::Ite {
                cond,
                iftrue,
                iffalse,
            } => {
                let c = self.convert_expr(&cond)?;
                let f = self.convert_expr(&iffalse)?;
                let t = self.convert_expr(&iftrue)?;
                let idx = self.next_atom();
                let depth = c.header.depth.max(f.header.depth).max(t.header.depth) + 1;
                let bits = t.header.bits;
                Ok(AilExpression {
                    header: ExprHeader::new(idx, depth, bits, self.tags()),
                    inner: ExprInner::ITE {
                        cond: Arc::new(c),
                        iffalse: Arc::new(f),
                        iftrue: Arc::new(t),
                    },
                })
            }
            ExprKind::CCall { callee, args, bits } => {
                let mut ops = Vec::with_capacity(args.len());
                for a in &args {
                    ops.push(self.convert_expr(a)?);
                }
                let idx = self.next_atom();
                // The VEXCCallExpression factory's depth is the max over the
                // operands, with no +1.
                let depth = ops.iter().map(|o| o.header.depth).max().unwrap_or(0);
                Ok(AilExpression {
                    header: ExprHeader::new(idx, depth, bits, self.tags()),
                    inner: ExprInner::VEXCCallExpression {
                        callee,
                        operands: ops,
                    },
                })
            }
            ExprKind::Unop { op, arg } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_unop(&op, &arg, bits);
                self.finish_op(r, op.label(), bits)
            }
            ExprKind::Binop { op, arg1, arg2 } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_binop(&op, &arg1, &arg2);
                self.finish_op(r, op.label(), bits)
            }
            ExprKind::Triop { op, args } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_triop(&op, &args);
                self.finish_op(r, op.label(), bits)
            }
            ExprKind::Unsupported { label, bits } => self.unsupported_expr(label, bits),
        }
    }

    fn convert_list(&mut self, args: &[R::E]) -> PyResult<Vec<AilExpression>> {
        let mut out = Vec::with_capacity(args.len());
        for a in args {
            out.push(self.convert_expr(a)?);
        }
        Ok(out)
    }

    fn make_tmp(&mut self, tmp_idx: i64, bits: u32) -> PyResult<AilExpression> {
        let idx = self.next_atom();
        Ok(AilExpression {
            header: ExprHeader::new(idx, 0, bits, self.tags()),
            inner: ExprInner::Tmp { tmp_idx },
        })
    }

    fn make_register(&mut self, offset: i64, bits: u32) -> PyResult<AilExpression> {
        let reg_size = bits / self.arch.byte_width;
        let reg_name = self.arch.reg_name(offset, reg_size)?;
        let idx = self.next_atom();
        let mut tags = self.tags();
        if let Some(n) = reg_name {
            tags.extras.insert(TagKey::RegName, TagExtra::Str(n));
        }
        Ok(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Register { reg_offset: offset },
        })
    }

    fn make_const(&mut self, value: ConstValue, bits: u32) -> PyResult<AilExpression> {
        let idx = self.next_atom();
        Ok(AilExpression {
            header: ExprHeader::new(idx, 0, bits, self.tags()),
            inner: ExprInner::Const { value },
        })
    }

    fn unsupported_expr(&mut self, label: String, bits: u32) -> PyResult<AilExpression> {
        let idx = self.next_atom();
        Ok(new_dirty_expr(
            idx,
            format!("unsupported_{label}"),
            bits,
            self.tags(),
        ))
    }

    // ---- Unop ----------------------------------------------------------

    /// Returns Err(ConvErr::Unsupported) -> caller emits DirtyExpression
    /// (matches the Python `try/except UnsupportedIROpError`).
    ///
    /// `bits` is the VEX result size of the whole unop expression (the
    /// Python converter's `expr.result_size(manager.tyenv)`).
    fn convert_unop(
        &mut self,
        op: &OpRef,
        arg: &R::E,
        bits: u32,
    ) -> Result<AilExpression, ConvErr> {
        let simop = op.simop().map_err(|_| ConvErr::Unsupported)?;
        let op_name = simop.generic_name.clone();

        if op_name.as_deref() == Some("Reinterp") {
            // Python arg eval order: Reinterpret(next_atom(), ..., convert(arg)).
            let idx = self.next_atom();
            let operand = self.convert_expr(arg)?;
            let to_bits = simop.to_size.unwrap_or(0);
            let depth = operand.header.depth + 1;
            return Ok(AilExpression {
                header: ExprHeader::new(idx, depth, to_bits, self.tags()),
                inner: ExprInner::Reinterpret {
                    operand: Arc::new(operand),
                    from_bits: simop.from_size.unwrap_or(0),
                    from_type: simop.from_type.clone().unwrap_or_default(),
                    to_bits,
                    to_type: simop.to_type.clone().unwrap_or_default(),
                },
            });
        }

        if op_name.is_none() {
            if !simop.is_conversion() {
                // Python raises NotImplementedError; treat as unsupported.
                return Err(ConvErr::Unsupported);
            }
            let from_size = simop.from_size.unwrap_or(0);
            let to_size = simop.to_size.unwrap_or(0);
            let signed = simop.is_signed();
            if simop.from_side.as_deref() == Some("HI") {
                // Python arg eval order: inner first, then the BinaryOp's
                // atom, then the shift-amount Const's atom.
                let inner = self.convert_expr(arg)?;
                let shifted = {
                    let idx = self.next_atom();
                    let shift_const = self.make_const(ConstValue::Int(to_size as i128), 8)?;
                    new_binop(
                        idx,
                        "Shr".to_string(),
                        inner,
                        shift_const,
                        false,
                        false,
                        None,
                        None,
                        None,
                        None,
                        self.tags(),
                    )
                };
                let idx = self.next_atom();
                return Ok(new_convert(
                    idx,
                    from_size,
                    to_size,
                    signed,
                    shifted,
                    ConvertType::TypeInt,
                    ConvertType::TypeInt,
                    None,
                    self.tags(),
                ));
            }
            // Python arg eval order: Convert(next_atom(), ..., convert(arg)).
            let idx = self.next_atom();
            let operand = self.convert_expr(arg)?;
            return Ok(new_convert(
                idx,
                from_size,
                to_size,
                signed,
                operand,
                ConvertType::TypeInt,
                ConvertType::TypeInt,
                None,
                self.tags(),
            ));
        }

        let mut name = op_name.unwrap();
        if name == "Not" && op.label() != "Iop_Not1" {
            name = "BitwiseNeg".to_string();
        }
        // Python arg eval order: UnaryOp(next_atom(), name, convert(arg), bits=...).
        let idx = self.next_atom();
        let operand = self.convert_expr(arg)?;
        let depth = operand.header.depth + 1;
        Ok(AilExpression {
            header: ExprHeader::new(idx, depth, bits, self.tags()),
            inner: ExprInner::UnaryOp {
                op: name,
                operand: Arc::new(operand),
            },
        })
    }

    // ---- Binop ---------------------------------------------------------

    fn convert_binop(
        &mut self,
        op: &OpRef,
        a1: &R::E,
        a2: &R::E,
    ) -> Result<AilExpression, ConvErr> {
        let simop = op.simop().map_err(|_| ConvErr::Unsupported)?;
        let mut op_name = simop.generic_name.clone();
        let mut operands = vec![self.convert_expr(a1)?, self.convert_expr(a2)?];

        // Add + negative Const -> Sub
        if op_name.as_deref() == Some("Add") {
            let negated = match &operands[1].inner {
                ExprInner::Const { value }
                    if const_value_sign_bit(value, operands[1].header.bits) =>
                {
                    Some(const_value_negated(value, operands[1].header.bits))
                }
                _ => None,
            };
            if let Some(new_val) = negated {
                op_name = Some("Sub".to_string());
                // Const(operands[1].idx, new_val, bits) with NO tags --
                // matches the Python rewrite.
                operands[1] = AilExpression {
                    header: ExprHeader::new(
                        operands[1].header.idx,
                        0,
                        operands[1].header.bits,
                        Tags::default(),
                    ),
                    inner: ExprInner::Const { value: new_val },
                };
            }
        }

        let mut signed = false;
        let mut vector_count: Option<i64> = None;
        let mut vector_size: Option<i64> = None;
        if simop.vector_count.is_some() && simop.vector_size.is_some() {
            op_name = Some(format!("{}V", op_name.unwrap_or_default()));
            signed = simop.is_signed();
            vector_count = simop.vector_count.map(|v| v as i64);
            vector_size = simop.vector_size.map(|v| v as i64);
        } else if matches!(
            op_name.as_deref(),
            Some("CmpLE")
                | Some("CmpLT")
                | Some("CmpGE")
                | Some("CmpGT")
                | Some("Div")
                | Some("DivMod")
                | Some("Mod")
                | Some("Mul")
                | Some("Mull")
        ) && simop.is_signed()
        {
            signed = true;
        }

        if op_name.as_deref() == Some("Cmp") && simop.float {
            op_name = Some("CmpF".to_string());
        }

        if op_name.is_none() && simop.is_conversion() {
            let from_size = simop.from_size.unwrap_or(0);
            let to_size = simop.to_size.unwrap_or(0);
            if simop.from_type.as_deref() == Some("I") && simop.to_type.as_deref() == Some("F") {
                let rm = vex_rm_value(&operands[0]);
                let operand = operands.pop().unwrap();
                let idx = self.next_atom();
                return Ok(new_convert(
                    idx,
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeInt,
                    ConvertType::TypeFp,
                    Some(rm),
                    self.tags(),
                ));
            }
            if simop.from_side.as_deref() == Some("HL") {
                op_name = Some("Concat".to_string());
            } else if simop.from_type.as_deref() == Some("F")
                && simop.to_type.as_deref() == Some("F")
            {
                let rm = vex_rm_value(&operands[0]);
                let operand = operands.pop().unwrap();
                let idx = self.next_atom();
                return Ok(new_convert(
                    idx,
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeFp,
                    ConvertType::TypeFp,
                    Some(rm),
                    self.tags(),
                ));
            } else if simop.from_type.as_deref() == Some("F")
                && simop.to_type.as_deref() == Some("I")
            {
                let rm = vex_rm_value(&operands[0]);
                let operand = operands.pop().unwrap();
                let idx = self.next_atom();
                return Ok(new_convert(
                    idx,
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeFp,
                    ConvertType::TypeInt,
                    Some(rm),
                    self.tags(),
                ));
            }
        }

        let bits = simop.output_size_bits;

        if op_name.as_deref() == Some("DivMod") {
            let op1_size = simop.from_size.unwrap_or(operands[0].header.bits);
            let op2_size = simop.to_size.unwrap_or(operands[1].header.bits);
            if op2_size < op1_size {
                // Python arg eval order: Convert(next_atom(), ..., operands[1]).
                let signed_cvt = simop.from_signed.as_deref() != Some("U");
                let idx = self.next_atom();
                let o = operands.pop().unwrap();
                operands.push(new_convert(
                    idx,
                    op2_size,
                    op1_size,
                    signed_cvt,
                    o,
                    ConvertType::TypeInt,
                    ConvertType::TypeInt,
                    None,
                    self.tags(),
                ));
            }
            let chunk_bits = bits / 2;
            let div = {
                let idx = self.next_atom();
                new_binop(
                    idx,
                    "Div".to_string(),
                    operands[0].clone(),
                    operands[1].clone(),
                    signed,
                    false,
                    None,
                    Some(op1_size),
                    None,
                    None,
                    self.tags(),
                )
            };
            let truncated_div = {
                let idx = self.next_atom();
                new_convert(
                    idx,
                    op1_size,
                    chunk_bits,
                    signed,
                    div,
                    ConvertType::TypeInt,
                    ConvertType::TypeInt,
                    None,
                    self.tags(),
                )
            };
            let modd = {
                let idx = self.next_atom();
                new_binop(
                    idx,
                    "Mod".to_string(),
                    operands[0].clone(),
                    operands[1].clone(),
                    signed,
                    false,
                    None,
                    Some(op1_size),
                    None,
                    None,
                    self.tags(),
                )
            };
            let truncated_mod = {
                let idx = self.next_atom();
                new_convert(
                    idx,
                    op1_size,
                    chunk_bits,
                    signed,
                    modd,
                    ConvertType::TypeInt,
                    ConvertType::TypeInt,
                    None,
                    self.tags(),
                )
            };
            let idx = self.next_atom();
            return Ok(new_binop(
                idx,
                "Concat".to_string(),
                truncated_mod,
                truncated_div,
                false,
                false,
                None,
                Some(bits),
                None,
                None,
                self.tags(),
            ));
        }

        let idx = self.next_atom();
        let rhs = operands.pop().unwrap();
        let lhs = operands.pop().unwrap();
        Ok(new_binop(
            idx,
            op_name.unwrap_or_default(),
            lhs,
            rhs,
            signed,
            false,
            None,
            Some(bits),
            vector_count,
            vector_size,
            self.tags(),
        ))
    }

    fn convert_triop(&mut self, op: &OpRef, args: &[R::E]) -> Result<AilExpression, ConvErr> {
        let simop = op.simop().map_err(|_| ConvErr::Unsupported)?;
        let op_name = simop.generic_name.clone().unwrap_or_default();
        let mut operands = self.convert_list(args)?;
        let bits = simop.output_size_bits;
        if simop.float {
            // first operand is the rounding mode -> BinaryOp over the rest
            if operands.len() != 3 {
                // The BinaryOp factory would reject this; mirror its error.
                return Err(ConvErr::Py(PyTypeError::new_err(format!(
                    "BinaryOp requires exactly 2 operands, got {}",
                    operands.len().saturating_sub(1)
                ))));
            }
            let rm = vex_rm_value(&operands[0]);
            let rhs = operands.pop().unwrap();
            let lhs = operands.pop().unwrap();
            let idx = self.next_atom();
            return Ok(new_binop(
                idx,
                op_name,
                lhs,
                rhs,
                true, // all floating-point operations are signed
                true,
                Some(rm),
                Some(bits),
                None,
                None,
                self.tags(),
            ));
        }
        // Non-fp triop: Python raises TypeError (unsupported in practice).
        Err(ConvErr::Unsupported)
    }

    fn finish_op(
        &mut self,
        r: Result<AilExpression, ConvErr>,
        op_label: String,
        bits: u32,
    ) -> PyResult<AilExpression> {
        match r {
            Ok(o) => Ok(o),
            Err(ConvErr::Unsupported) => self.unsupported_expr(op_label, bits),
            Err(ConvErr::Py(e)) => Err(e),
        }
    }

    // ---- statement conversion -----------------------------------------

    /// Returns the converted statement objects (usually one) appended to
    /// `out`, and whether it was a ConditionalJump (for false-target backpatch).
    ///
    /// Statement idx values come from `next_atom()` (like every expression),
    /// allocated at the exact point the Python converter's arg-eval order
    /// reaches the statement constructor's `manager.next_atom()` call.
    fn convert_stmt(
        &mut self,
        kind: StmtKind<R::E>,
        out: &mut Vec<AilStatement>,
    ) -> PyResult<bool> {
        match kind {
            StmtKind::WrTmp {
                tmp,
                data,
                data_bits,
            } => {
                let var = self.make_tmp(tmp as i64, data_bits)?;
                let val = self.convert_expr(&data)?;
                let idx = self.next_atom();
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Assignment {
                        dst: Arc::new(var),
                        src: Arc::new(val),
                    },
                ));
                Ok(false)
            }
            StmtKind::Put { offset, data } => {
                let val = self.convert_expr(&data)?;
                let bits = val.header.bits;
                let reg = self.make_register(offset, bits)?;
                let idx = self.next_atom();
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Assignment {
                        dst: Arc::new(reg),
                        src: Arc::new(val),
                    },
                ));
                Ok(false)
            }
            StmtKind::Store {
                addr,
                data,
                size_bytes,
                endness,
            } => {
                // Python arg eval order: Store(next_atom(), convert(addr), convert(data), ...).
                let idx = self.next_atom();
                let a = self.convert_expr(&addr)?;
                let d = self.convert_expr(&data)?;
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Store {
                        addr: Arc::new(a),
                        data: Arc::new(d),
                        size: size_bytes,
                        endness,
                        guard: None,
                    },
                ));
                Ok(false)
            }
            StmtKind::Exit { guard, dst, jk } => {
                if EXIT_SKIP_JK.contains(&jk.as_str()) {
                    return Ok(false); // SkipConversionNotice
                }
                // Python arg eval order: ConditionalJump(next_atom(), convert(guard), convert(dst), None).
                let idx = self.next_atom();
                let g = self.convert_expr(&guard)?;
                let d = self.convert_expr(&dst)?;
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::ConditionalJump {
                        condition: Arc::new(g),
                        true_target: Some(CFGTarget::Expr(Arc::new(d))),
                        false_target: None, // filled in right afterwards
                        true_target_idx: None,
                        false_target_idx: None,
                    },
                ));
                Ok(true)
            }
            StmtKind::LoadG {
                dst,
                dst_bits,
                cvt,
                addr,
                alt,
                guard,
                end,
            } => {
                let (load_bits, convert_bits, signed) = loadg_sizes(&cvt)?;
                let dst_var = self.make_tmp(dst as i64, dst_bits)?;
                // Python arg eval order: Load(next_atom(), convert(addr), ...,
                // guard=convert(guard), alt=convert(alt)).
                let lidx = self.next_atom();
                let a = self.convert_expr(&addr)?;
                let g = self.convert_expr(&guard)?;
                let al = self.convert_expr(&alt)?;
                // Load has NO tags in the Python converter for LoadG.
                let size = (load_bits / 8) as i32;
                let load = AilExpression {
                    header: ExprHeader::new(
                        lidx,
                        a.header.depth + 1,
                        size.wrapping_mul(8) as u32,
                        Tags::default(),
                    ),
                    inner: ExprInner::Load {
                        addr: Arc::new(a),
                        size,
                        endness: end,
                        guard: Some(Arc::new(g)),
                        alt: Some(Arc::new(al)),
                    },
                };
                let src = if convert_bits != load_bits {
                    // ... and neither has this Convert.
                    let cidx = self.next_atom();
                    new_convert(
                        cidx,
                        load_bits,
                        convert_bits,
                        signed,
                        load,
                        ConvertType::TypeInt,
                        ConvertType::TypeInt,
                        None,
                        Tags::default(),
                    )
                } else {
                    load
                };
                let idx = self.next_atom();
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Assignment {
                        dst: Arc::new(dst_var),
                        src: Arc::new(src),
                    },
                ));
                Ok(false)
            }
            StmtKind::StoreG {
                addr,
                data,
                size_bytes,
                endness,
                guard,
            } => {
                // Python arg eval order: Store(next_atom(), convert(addr),
                // convert(data), ..., guard=convert(guard)).
                let idx = self.next_atom();
                let a = self.convert_expr(&addr)?;
                let d = self.convert_expr(&data)?;
                let g = self.convert_expr(&guard)?;
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Store {
                        addr: Arc::new(a),
                        data: Arc::new(d),
                        size: size_bytes,
                        endness,
                        guard: Some(Arc::new(g)),
                    },
                ));
                Ok(false)
            }
            StmtKind::Cas {
                addr,
                data_lo,
                data_hi,
                expd_lo,
                expd_hi,
                old_lo,
                old_lo_bits,
                old_hi,
                old_hi_bits,
                endness,
            } => {
                let a = self.convert_expr(&addr)?;
                let dl = self.convert_expr(&data_lo)?;
                let dh = match data_hi {
                    Some(e) => Some(self.convert_expr(&e)?),
                    None => None,
                };
                let el = self.convert_expr(&expd_lo)?;
                let eh = match expd_hi {
                    Some(e) => Some(self.convert_expr(&e)?),
                    None => None,
                };
                let ol = self.make_tmp(old_lo as i64, old_lo_bits)?;
                let oh = match old_hi {
                    Some(t) => Some(self.make_tmp(t as i64, old_hi_bits)?),
                    None => None,
                };
                let idx = self.next_atom();
                // CAS only sets ins_addr (matches Python).
                let tags = Tags {
                    ins_addr: self.ins_addr,
                    ..Default::default()
                };
                out.push(new_stmt(
                    idx,
                    tags,
                    StmtInner::CAS {
                        addr: Arc::new(a),
                        data_lo: Arc::new(dl),
                        data_hi: dh.map(Arc::new),
                        expd_lo: Arc::new(el),
                        expd_hi: eh.map(Arc::new),
                        old_lo: Arc::new(ol),
                        old_hi: oh.map(Arc::new),
                        endness,
                    },
                ));
                Ok(false)
            }
            StmtKind::Dirty {
                callee,
                args,
                guard,
                mfx,
                maddr,
                msize,
                tmp,
                tmp_bits,
            } => {
                let ops = self.convert_list(&args)?;
                let g = match guard {
                    Some(e) => Some(self.convert_expr(&e)?),
                    None => None,
                };
                let ma = match maddr {
                    Some(e) => Some(self.convert_expr(&e)?),
                    None => None,
                };
                let didx = self.next_atom();
                // The DirtyExpression factory's depth is a constant 1.
                let dirty_expr = AilExpression {
                    header: ExprHeader::new(didx, 1, tmp_bits, self.tags()),
                    inner: ExprInner::DirtyExpression {
                        callee,
                        operands: ops,
                        guard: g.map(Arc::new),
                        mfx,
                        maddr: ma.map(Arc::new),
                        msize,
                    },
                };
                match tmp {
                    None => {
                        let idx = self.next_atom();
                        out.push(new_stmt(
                            idx,
                            self.tags(),
                            StmtInner::DirtyStatement {
                                dirty: Arc::new(dirty_expr),
                            },
                        ));
                    }
                    Some(t) => {
                        let tmp_var = self.make_tmp(t as i64, tmp_bits)?;
                        let idx = self.next_atom();
                        out.push(new_stmt(
                            idx,
                            self.tags(),
                            StmtInner::Assignment {
                                dst: Arc::new(tmp_var),
                                src: Arc::new(dirty_expr),
                            },
                        ));
                    }
                }
                Ok(false)
            }
            StmtKind::Other { label } => {
                let didx = self.next_atom();
                let dirty_expr = new_dirty_expr(didx, label, 0, self.tags());
                let idx = self.next_atom();
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::DirtyStatement {
                        dirty: Arc::new(dirty_expr),
                    },
                ));
                Ok(false)
            }
            StmtKind::IMark { .. } | StmtKind::AbiHint | StmtKind::NoOp => Ok(false),
        }
    }

    // ---- whole IRSB ----------------------------------------------------

    fn convert_block(&mut self) -> PyResult<Py<PyAny>> {
        let mut statements: Vec<AilStatement> = Vec::new();
        let mut addr = self.block_addr;
        // Guarantee every emitted statement carries an ``ins_addr``: seed it
        // with the block address so a statement produced before the first
        // IMark -- or the terminator of a block that decodes no instructions
        // at all (pure NoDecode / invalid bytes, hence no IMark) -- still gets
        // a source address instead of ``None``. Each IMark overrides it with
        // the real instruction address below.
        self.ins_addr = Some(addr);
        let mut first_imark = true;
        let mut cond_jump_positions: Vec<usize> = Vec::new();

        let n = self.reader.num_stmts();
        for vex_idx in 0..n {
            let kind = self.reader.stmt_kind(self.py, vex_idx)?;
            match &kind {
                StmtKind::IMark { addr: a, delta } => {
                    if first_imark {
                        addr = a + delta;
                        first_imark = false;
                    }
                    self.ins_addr = Some(a + delta);
                    continue;
                }
                StmtKind::AbiHint | StmtKind::NoOp => continue,
                _ => {}
            }
            self.vex_stmt_idx = vex_idx as i64;
            let is_cond = self.convert_stmt(kind, &mut statements)?;
            if is_cond {
                cond_jump_positions.push(statements.len() - 1);
            }
        }

        self.vex_stmt_idx = DEFAULT_STATEMENT;
        let jk = self.reader.jumpkind();
        if jk == "Ijk_Call" || jk.starts_with("Ijk_Sys") {
            self.emit_call_tail(&jk, &mut statements)?;
        } else if jk == "Ijk_Boring" {
            if let Some(&pos) = cond_jump_positions.last() {
                let next = self.reader.next_expr();
                let false_target = self.convert_expr(&next)?;
                match &mut statements[pos].inner {
                    StmtInner::ConditionalJump {
                        false_target: ft, ..
                    } => *ft = Some(CFGTarget::Expr(Arc::new(false_target))),
                    _ => unreachable!("cond_jump_positions points at a non-ConditionalJump"),
                }
            } else {
                // Match the original's arg eval order: the Jump's idx
                // (next_atom) is allocated *before* the target is converted.
                let jidx = self.next_atom();
                let next = self.reader.next_expr();
                let target = self.convert_expr(&next)?;
                statements.push(new_stmt(
                    jidx,
                    self.tags(),
                    StmtInner::Jump {
                        target: CFGTarget::Expr(Arc::new(target)),
                        target_idx: None,
                    },
                ));
            }
        } else if jk == "Ijk_Ret" {
            let ridx = self.next_atom();
            statements.push(new_stmt(
                ridx,
                self.tags(),
                StmtInner::Return {
                    ret_exprs: Vec::new(),
                },
            ));
        } else if jk == "Ijk_SigTRAP" {
            // int3 -> MSVC __debugbreak() intrinsic: a side-effecting call to
            // an opaque (dirty) intrinsic, mirroring the syscall path.
            let target = {
                let didx = self.next_atom();
                new_dirty_expr(
                    didx,
                    "__debugbreak".to_string(),
                    self.arch.bits,
                    Tags::default(),
                )
            };
            let call_expr = {
                let cidx = self.next_atom();
                // Call(..., args=[], bits=None): empty args vec; the factory's
                // bits default (bits.unwrap_or(0)) puts 0 in the header.
                let depth = target.header.depth + 1;
                AilExpression {
                    header: ExprHeader::new(cidx, depth, 0, self.tags()),
                    inner: ExprInner::Call {
                        target: CFGTarget::Expr(Arc::new(target)),
                        args: Some(Vec::new()),
                        arg_vvars: None,
                    },
                }
            };
            let seidx = self.next_atom();
            statements.push(new_stmt(
                seidx,
                self.tags(),
                StmtInner::SideEffectStatement {
                    expr: Arc::new(call_expr),
                    ret_expr: None,
                    fp_ret_expr: None,
                },
            ));
        } else {
            // Unknown/unsupported jumpkind: an opaque dirty placeholder whose
            // callee is a clean C identifier (never an internal diagnostic
            // string, which must not leak into the AIL/C output).
            let dirty_expr = {
                let didx = self.next_atom();
                new_dirty_expr(
                    didx,
                    format!("__unsupported_jumpkind_{jk}"),
                    0,
                    Tags::default(),
                )
            };
            let sidx = self.next_atom();
            statements.push(new_stmt(
                sidx,
                self.tags(),
                StmtInner::DirtyStatement {
                    dirty: Arc::new(dirty_expr),
                },
            ));
        }

        // Wrap each statement into its pyclass exactly once and assemble the
        // Block.
        let py_stmts = PyList::empty(self.py);
        for st in statements {
            py_stmts.append(Bound::new(self.py, Statement::wrap(st))?)?;
        }
        let block = Block {
            addr,
            original_size: self.reader.block_size(),
            statements: py_stmts.unbind(),
            idx: None,
            cached_hash: CachedHash::new(),
        };
        Ok(Bound::new(self.py, block)?.into_any().unbind())
    }

    fn emit_call_tail(&mut self, jk: &str, statements: &mut Vec<AilStatement>) -> PyResult<()> {
        let ret_offset: i64 = self.arch.arch.getattr("ret_offset")?.extract()?;
        let bits = self.arch.bits;
        let ret_name = self.arch.reg_name(ret_offset, bits)?;
        let ret_expr = {
            let aidx = self.next_atom();
            let mut tags = self.tags();
            if let Some(n) = ret_name {
                tags.extras.insert(TagKey::RegName, TagExtra::Str(n));
            }
            AilExpression {
                header: ExprHeader::new(aidx, 0, bits, tags),
                inner: ExprInner::Register {
                    reg_offset: ret_offset,
                },
            }
        };

        let fp_ret_obj = self.arch.arch.getattr("fp_ret_offset")?;
        let fp_ret_expr: Option<AilExpression> = if fp_ret_obj.is_none() {
            None
        } else {
            let fp_ret_offset: i64 = fp_ret_obj.extract()?;
            if fp_ret_offset == ret_offset {
                None
            } else {
                let fp_name = self.arch.reg_name(fp_ret_offset, bits)?;
                let aidx = self.next_atom();
                let mut tags = self.tags();
                if let Some(n) = fp_name {
                    tags.extras.insert(TagKey::RegName, TagExtra::Str(n));
                }
                Some(AilExpression {
                    header: ExprHeader::new(aidx, 0, bits, tags),
                    inner: ExprInner::Register {
                        reg_offset: fp_ret_offset,
                    },
                })
            }
        };

        let target = if jk == "Ijk_Call" {
            let next = self.reader.next_expr();
            self.convert_expr(&next)?
        } else {
            // Ijk_Sys*: hack -- DirtyExpression("syscall")
            let didx = self.next_atom();
            new_dirty_expr(didx, "syscall".to_string(), bits, Tags::default())
        };

        let ret_bits = ret_expr.header.bits;
        let call_expr = {
            let cidx = self.next_atom();
            let depth = target.header.depth + 1;
            AilExpression {
                header: ExprHeader::new(cidx, depth, ret_bits, self.tags()),
                inner: ExprInner::Call {
                    target: CFGTarget::Expr(Arc::new(target)),
                    args: None,
                    arg_vvars: None,
                },
            }
        };

        let seidx = self.next_atom();
        statements.push(new_stmt(
            seidx,
            self.tags(),
            StmtInner::SideEffectStatement {
                expr: Arc::new(call_expr),
                ret_expr: Some(Arc::new(ret_expr)),
                fp_ret_expr: fp_ret_expr.map(Arc::new),
            },
        ));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Native node constructors -- mirror the `_new_*` factory defaults exactly.
// ---------------------------------------------------------------------------

fn new_stmt(idx: i64, tags: Tags, inner: StmtInner) -> AilStatement {
    AilStatement {
        header: StmtHeader::new(idx, tags),
        inner,
    }
}

/// `_new_binary_op`: depth = max(lhs, rhs) + 1; bits defaults to lhs bits.
#[allow(clippy::too_many_arguments)]
fn new_binop(
    idx: i64,
    op: String,
    lhs: AilExpression,
    rhs: AilExpression,
    signed: bool,
    floating_point: bool,
    rounding_mode: Option<RoundingModeOrExpr>,
    bits: Option<u32>,
    vector_count: Option<i64>,
    vector_size: Option<i64>,
    tags: Tags,
) -> AilExpression {
    let depth = lhs.header.depth.max(rhs.header.depth) + 1;
    let final_bits = bits.unwrap_or(lhs.header.bits);
    AilExpression {
        header: ExprHeader::new(idx, depth, final_bits, tags),
        inner: ExprInner::BinaryOp {
            op,
            operands: [Arc::new(lhs), Arc::new(rhs)],
            signed,
            floating_point,
            rounding_mode,
            vector_count,
            vector_size,
        },
    }
}

/// `_new_convert`: depth = operand + 1; header bits = to_bits.
#[allow(clippy::too_many_arguments)]
fn new_convert(
    idx: i64,
    from_bits: u32,
    to_bits: u32,
    is_signed: bool,
    operand: AilExpression,
    from_type: ConvertType,
    to_type: ConvertType,
    rounding_mode: Option<RoundingModeOrExpr>,
    tags: Tags,
) -> AilExpression {
    let depth = operand.header.depth + 1;
    AilExpression {
        header: ExprHeader::new(idx, depth, to_bits, tags),
        inner: ExprInner::Convert {
            operand: Arc::new(operand),
            from_bits,
            to_bits,
            is_signed,
            from_type,
            to_type,
            rounding_mode,
        },
    }
}

/// `_new_dirty_expression` with no operands: depth is a constant 1.
fn new_dirty_expr(idx: i64, callee: String, bits: u32, tags: Tags) -> AilExpression {
    AilExpression {
        header: ExprHeader::new(idx, 1, bits, tags),
        inner: ExprInner::DirtyExpression {
            callee,
            operands: Vec::new(),
            guard: None,
            mfx: None,
            maddr: None,
            msize: None,
        },
    }
}

const EXIT_SKIP_JK: &[&str] = &[
    "Ijk_EmWarn",
    "Ijk_NoDecode",
    "Ijk_MapFail",
    "Ijk_NoRedir",
    "Ijk_SigTRAP",
    "Ijk_SigSEGV",
    "Ijk_ClientReq",
    "Ijk_SigFPE_IntDiv",
];

fn loadg_sizes(cvt: &str) -> PyResult<(u32, u32, bool)> {
    Ok(match cvt {
        "ILGop_Ident32" => (32, 32, false),
        "ILGop_Ident64" => (64, 64, false),
        "ILGop_IdentV128" => (128, 128, false),
        "ILGop_8Uto32" => (8, 32, false),
        "ILGop_8Sto32" => (8, 32, true),
        "ILGop_16Uto32" => (16, 32, false),
        "ILGop_16Sto32" => (16, 32, true),
        other => return Err(PyValueError::new_err(format!("unknown LoadG cvt {other}"))),
    })
}

fn op_label(op: u32) -> String {
    vexop::op_name(op).unwrap_or("Iop_INVALID").to_string()
}

/// Higher-ranked `Bound -> Py` helper (avoids closures pinning a lifetime).
fn unbind_any(o: Bound<'_, PyAny>) -> Py<PyAny> {
    o.unbind()
}

// ---------------------------------------------------------------------------
// Const-value helpers for the Add->Sub rewrite and the rounding-mode
// extraction. These mirror the Python-side `Const.sign_bit` semantics.
// ---------------------------------------------------------------------------

/// Bit `bits - 1` of the value's raw pattern (the Python `Const.sign_bit`);
/// `false` for float constants and zero-width values.
fn const_value_sign_bit(v: &ConstValue, bits: u32) -> bool {
    if bits == 0 {
        return false;
    }
    let top = (bits - 1) as u64;
    match v {
        ConstValue::Int(v) if bits <= 128 => (*v >> top) & 1 != 0,
        ConstValue::Int(v) => num_bigint::BigInt::from(*v).bit(top),
        ConstValue::BigInt(b) => b.bit(top),
        ConstValue::Float(_) => false,
    }
}

/// The Python converter's `(1 << bits) - value`. Only called on int consts
/// (`const_value_sign_bit` returned true).
fn const_value_negated(v: &ConstValue, bits: u32) -> ConstValue {
    let big = match v {
        ConstValue::Int(v) if bits < 127 => return ConstValue::Int((1i128 << bits) - v),
        ConstValue::Int(v) => (num_bigint::BigInt::from(1) << bits) - num_bigint::BigInt::from(*v),
        ConstValue::BigInt(b) => (num_bigint::BigInt::from(1) << bits) - b,
        ConstValue::Float(_) => unreachable!("negating a float const"),
    };
    match i128::try_from(&big) {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::BigInt(big),
    }
}

/// The rounding-mode operand of a float op: a Const int operand maps to the
/// typed `RoundingMode(value & 0b11)` enum; any other expression (e.g. a tmp
/// -- VEX sometimes carries the rounding mode in a tmp that only becomes a
/// constant later in the decompilation pipeline) is passed through as-is.
fn vex_rm_value(rm: &AilExpression) -> RoundingModeOrExpr {
    if let ExprInner::Const { value } = &rm.inner {
        let low2 = match value {
            ConstValue::Int(v) => Some((v & 3) as i64),
            ConstValue::BigInt(b) => i64::try_from(b & num_bigint::BigInt::from(3)).ok(),
            ConstValue::Float(_) => None,
        };
        if let Some(m) = low2.and_then(RoundingMode::from_int) {
            return RoundingModeOrExpr::Mode(m);
        }
    }
    RoundingModeOrExpr::Expr(Arc::new(rm.clone()))
}

// ===========================================================================
// C reader: walks a raw libVEX IRSB.
// ===========================================================================

struct CReader {
    irsb: *mut IRSB,
    size: i64,
    /// Synthetic `Iex_Const` wrappers for `Exit.dst` (an `IRConst*`, not an
    /// `IRExpr*`). Owned here so they outlive conversion and are freed when
    /// the reader drops -- no leak. The `Box` is required: `const_to_expr`
    /// hands out raw pointers into these allocations, which must stay stable
    /// when the `Vec` reallocates.
    #[allow(clippy::vec_box)]
    dst_exprs: std::cell::RefCell<Vec<Box<IRExpr>>>,
}

impl CReader {
    unsafe fn tyenv_lookup(&self, t: u32) -> u32 {
        unsafe { (*(*self.irsb).tyenv).lookup(t) }
    }

    /// Wrap an `IRConst*` as an `Iex_Const` `IRExpr` so the core can convert
    /// `Exit.dst` uniformly.
    fn const_to_expr(&self, con: *mut vex_ffi::IRConst) -> *mut IRExpr {
        let boxed = Box::new(IRExpr {
            tag: vex_ffi::IEX_CONST,
            iex: vex_ffi::IexUnion {
                con: vex_ffi::ExprConst { con },
            },
        });
        let ptr = Box::as_ref(&boxed) as *const IRExpr as *mut IRExpr;
        self.dst_exprs.borrow_mut().push(boxed);
        ptr
    }
}

unsafe fn const_value(c: *const vex_ffi::IRConst) -> ConstVal {
    use vex_ffi::*;
    let tag = unsafe { (*c).tag };
    let ico = unsafe { &(*c).ico };
    let (value, bits): (ConstValue, u32) = unsafe {
        match tag {
            ICO_U1 => (ConstValue::Int(ico.u1 as i128), 1),
            ICO_U8 => (ConstValue::Int(ico.u8_ as i128), 8),
            ICO_U16 => (ConstValue::Int(ico.u16_ as i128), 16),
            ICO_U32 => (ConstValue::Int(ico.u32_ as i128), 32),
            ICO_U64 => (ConstValue::Int(ico.u64_ as i128), 64),
            ICO_F32 | ICO_F32I => (ConstValue::Float(ico.f32_ as f64), 32),
            ICO_F64 | ICO_F64I => (ConstValue::Float(ico.f64_), 64),
            ICO_V128 => (expand_vector(ico.v128 as u64, 16), 128),
            ICO_V256 => (expand_vector(ico.v256 as u64, 32), 256),
            _ => (ConstValue::Int(0), 0),
        }
    };
    ConstVal { value, bits }
}

/// Mirror of pyvex V128/V256 `_from_c`: each set bit `i` in `base` becomes a
/// 0xFF byte at position `i`, read back as a little-endian unsigned int.
fn expand_vector(base: u64, nbytes: usize) -> ConstValue {
    let mut bytes = vec![0u8; nbytes];
    for (i, b) in bytes.iter_mut().enumerate() {
        if (base >> i) & 1 == 1 {
            *b = 0xFF;
        }
    }
    let big = num_bigint::BigInt::from_bytes_le(num_bigint::Sign::Plus, &bytes);
    match i128::try_from(&big) {
        Ok(v) => ConstValue::Int(v),
        Err(_) => ConstValue::BigInt(big),
    }
}

fn jk_name(jk: u32) -> String {
    let s = match jk {
        0x1A01 => "Ijk_Boring",
        0x1A02 => "Ijk_Call",
        0x1A03 => "Ijk_Ret",
        0x1A04 => "Ijk_ClientReq",
        0x1A05 => "Ijk_Yield",
        0x1A06 => "Ijk_EmWarn",
        0x1A07 => "Ijk_EmFail",
        0x1A08 => "Ijk_NoDecode",
        0x1A09 => "Ijk_MapFail",
        0x1A0A => "Ijk_InvalICache",
        0x1A0B => "Ijk_FlushDCache",
        0x1A0C => "Ijk_NoRedir",
        0x1A0D => "Ijk_SigILL",
        0x1A0E => "Ijk_SigTRAP",
        0x1A0F => "Ijk_SigSEGV",
        0x1A10 => "Ijk_SigBUS",
        0x1A11 => "Ijk_SigFPE",
        0x1A12 => "Ijk_SigFPE_IntDiv",
        0x1A13 => "Ijk_SigFPE_IntOvf",
        0x1A14 => "Ijk_Privileged",
        0x1A15 => "Ijk_Sys_syscall",
        0x1A16 => "Ijk_Sys_int",
        0x1A17 => "Ijk_Sys_int32",
        0x1A18 => "Ijk_Sys_int128",
        0x1A19 => "Ijk_Sys_int129",
        0x1A1A => "Ijk_Sys_int130",
        0x1A1B => "Ijk_Sys_int145",
        0x1A1C => "Ijk_Sys_int210",
        0x1A1D => "Ijk_Sys_sysenter",
        _ => "Ijk_INVALID",
    };
    s.to_string()
}

fn effect_name(fx: u32) -> String {
    match fx {
        0x1B01 => "Ifx_Read",
        0x1B02 => "Ifx_Write",
        0x1B03 => "Ifx_Modify",
        _ => "Ifx_None",
    }
    .to_string()
}

fn loadg_cvt_name(cvt: u32) -> String {
    match cvt {
        0x1D01 => "ILGop_IdentV128",
        0x1D02 => "ILGop_Ident64",
        0x1D03 => "ILGop_Ident32",
        0x1D04 => "ILGop_16Uto32",
        0x1D05 => "ILGop_16Sto32",
        0x1D06 => "ILGop_8Uto32",
        0x1D07 => "ILGop_8Sto32",
        _ => "ILGop_INVALID",
    }
    .to_string()
}

impl IrReader for CReader {
    type E = *mut IRExpr;

    fn block_addr(&self) -> i64 {
        // VEX IRSB has no addr field; the caller supplies it via first IMark.
        // We seed from the lift address stored separately.
        unsafe { (*self.irsb).offs_ip as i64 } // placeholder; overwritten below
    }

    fn block_size(&self) -> Option<i64> {
        Some(self.size)
    }

    fn jumpkind(&self) -> String {
        jk_name(unsafe { (*self.irsb).jumpkind })
    }

    fn next_expr(&self) -> Self::E {
        unsafe { (*self.irsb).next }
    }

    fn num_stmts(&self) -> usize {
        unsafe { (*self.irsb).stmts_used as usize }
    }

    fn stmt_kind(&self, py: Python<'_>, i: usize) -> PyResult<StmtKind<Self::E>> {
        use vex_ffi::*;
        let stmt: *mut IRStmt = unsafe { *(*self.irsb).stmts.add(i) };
        let tag = unsafe { (*stmt).tag };
        let ist = unsafe { &(*stmt).ist };
        Ok(unsafe {
            match tag {
                IST_IMARK => StmtKind::IMark {
                    addr: ist.imark.addr as i64,
                    delta: ist.imark.delta as i64,
                },
                IST_ABIHINT => StmtKind::AbiHint,
                IST_NOOP => StmtKind::NoOp,
                IST_WRTMP => {
                    let data = ist.wrtmp.data;
                    StmtKind::WrTmp {
                        tmp: ist.wrtmp.tmp,
                        data,
                        data_bits: self.result_bits(&data),
                    }
                }
                IST_PUT => StmtKind::Put {
                    offset: ist.put.offset as i64,
                    data: ist.put.data,
                },
                IST_STORE => {
                    let data = ist.store.data;
                    StmtKind::Store {
                        addr: ist.store.addr,
                        data,
                        size_bytes: (self.result_bits(&data) / 8) as i32,
                        endness: endness_str(ist.store.end).to_string(),
                    }
                }
                IST_EXIT => StmtKind::Exit {
                    guard: ist.exit.guard,
                    dst: self.const_to_expr(ist.exit.dst),
                    jk: jk_name(ist.exit.jk),
                },
                IST_STOREG => {
                    let d = &*ist.storeg.details;
                    StmtKind::StoreG {
                        addr: d.addr,
                        data: d.data,
                        size_bytes: (self.result_bits(&d.data) / 8) as i32,
                        endness: endness_str(d.end).to_string(),
                        guard: d.guard,
                    }
                }
                IST_LOADG => {
                    let d = &*ist.loadg.details;
                    StmtKind::LoadG {
                        dst: d.dst,
                        dst_bits: type_size_bits(self.tyenv_lookup(d.dst)),
                        cvt: loadg_cvt_name(d.cvt),
                        addr: d.addr,
                        alt: d.alt,
                        guard: d.guard,
                        end: endness_str(d.end).to_string(),
                    }
                }
                IST_CAS => {
                    let d = &*ist.cas.details;
                    let data_hi = if d.data_hi.is_null() {
                        None
                    } else {
                        Some(d.data_hi)
                    };
                    let expd_hi = if d.expd_hi.is_null() {
                        None
                    } else {
                        Some(d.expd_hi)
                    };
                    let old_hi = if d.old_hi != IRTEMP_INVALID {
                        Some(d.old_hi)
                    } else {
                        None
                    };
                    StmtKind::Cas {
                        addr: d.addr,
                        data_lo: d.data_lo,
                        data_hi,
                        expd_lo: d.expd_lo,
                        expd_hi,
                        old_lo: d.old_lo,
                        old_lo_bits: type_size_bits(self.tyenv_lookup(d.old_lo)),
                        old_hi,
                        old_hi_bits: old_hi
                            .map(|t| type_size_bits(self.tyenv_lookup(t)))
                            .unwrap_or(0),
                        endness: endness_str(d.end).to_string(),
                    }
                }
                IST_DIRTY => {
                    let d = &*ist.dirty.details;
                    let callee = cstr((*d.cee).name);
                    let mut args = Vec::new();
                    let mut p = d.args;
                    while !(*p).is_null() {
                        args.push(*p);
                        p = p.add(1);
                    }
                    let guard = if d.guard.is_null() {
                        None
                    } else {
                        Some(d.guard)
                    };
                    let maddr = if d.m_addr.is_null() {
                        None
                    } else {
                        Some(d.m_addr)
                    };
                    let (tmp, tmp_bits) = if d.tmp != IRTEMP_INVALID {
                        (Some(d.tmp), type_size_bits(self.tyenv_lookup(d.tmp)))
                    } else {
                        (None, 0)
                    };
                    StmtKind::Dirty {
                        callee,
                        args,
                        guard,
                        mfx: Some(effect_name(d.m_fx)),
                        maddr,
                        msize: Some(d.m_size as i64),
                        tmp,
                        tmp_bits,
                    }
                }
                _ => {
                    // MBE / LLSC / PutI etc.: the Python converter labels these
                    // with ``str(stmt)`` (e.g. "MBusEvent-Imbe_Fence"), which we
                    // can't faithfully reproduce from the C struct. Error out so
                    // the caller falls back to the Python-IRSB path. (run() only
                    // writes the atom counter on success, so this is clean.)
                    let _ = py;
                    return Err(PyRuntimeError::new_err(
                        "fast path: unsupported VEX statement; use the Python-IRSB path",
                    ));
                }
            }
        })
    }

    fn expr_kind(&self, _py: Python<'_>, e: &Self::E) -> PyResult<ExprKind<Self::E>> {
        use vex_ffi::*;
        let e = *e;
        let tag = unsafe { (*e).tag };
        let iex = unsafe { &(*e).iex };
        Ok(unsafe {
            match tag {
                IEX_RDTMP => ExprKind::RdTmp {
                    tmp: iex.rdtmp.tmp,
                    bits: type_size_bits(self.tyenv_lookup(iex.rdtmp.tmp)),
                },
                IEX_GET => ExprKind::Get {
                    offset: iex.get.offset as i64,
                    bits: type_size_bits(iex.get.ty),
                },
                IEX_LOAD => ExprKind::Load {
                    end: endness_str(iex.load.end).to_string(),
                    bits: type_size_bits(iex.load.ty),
                    addr: iex.load.addr,
                },
                IEX_UNOP => ExprKind::Unop {
                    op: OpRef::Int(iex.unop.op),
                    arg: iex.unop.arg,
                },
                IEX_BINOP => ExprKind::Binop {
                    op: OpRef::Int(iex.binop.op),
                    arg1: iex.binop.arg1,
                    arg2: iex.binop.arg2,
                },
                IEX_TRIOP => {
                    let d = &*iex.triop.details;
                    ExprKind::Triop {
                        op: OpRef::Int(d.op),
                        args: vec![d.arg1, d.arg2, d.arg3],
                    }
                }
                IEX_CONST => {
                    let cv = const_value(iex.con.con);
                    ExprKind::Const {
                        value: cv.value,
                        bits: cv.bits,
                    }
                }
                IEX_ITE => ExprKind::Ite {
                    cond: iex.ite.cond,
                    iftrue: iex.ite.iftrue,
                    iffalse: iex.ite.iffalse,
                },
                IEX_CCALL => {
                    let callee = cstr((*iex.ccall.cee).name);
                    let mut args = Vec::new();
                    let mut p = iex.ccall.args;
                    while !(*p).is_null() {
                        args.push(*p);
                        p = p.add(1);
                    }
                    ExprKind::CCall {
                        callee,
                        args,
                        bits: type_size_bits(iex.ccall.retty),
                    }
                }
                _ => {
                    // GetI / Qop / VECRET / GSPTR / Binder: the Python converter
                    // labels these with ``str(type(expr))``, which we can't
                    // reproduce here. Error out so the caller falls back to the
                    // Python-IRSB path.
                    return Err(PyRuntimeError::new_err(
                        "fast path: unsupported VEX expression; use the Python-IRSB path",
                    ));
                }
            }
        })
    }

    fn result_bits(&self, e: &Self::E) -> u32 {
        unsafe { result_bits_c(self.irsb, *e) }
    }
}

/// VEX `result_size` (bits) for a C expression.
unsafe fn result_bits_c(irsb: *mut IRSB, e: *mut IRExpr) -> u32 {
    use vex_ffi::*;
    if e.is_null() {
        return 0;
    }
    let tag = unsafe { (*e).tag };
    let iex = unsafe { &(*e).iex };
    unsafe {
        match tag {
            IEX_RDTMP => type_size_bits((*(*irsb).tyenv).lookup(iex.rdtmp.tmp)),
            IEX_GET => type_size_bits(iex.get.ty),
            IEX_LOAD => type_size_bits(iex.load.ty),
            IEX_CONST => const_bits((*iex.con.con).tag),
            IEX_CCALL => type_size_bits(iex.ccall.retty),
            IEX_UNOP => type_size_bits(vex_ffi::op_result_type(iex.unop.op)),
            IEX_BINOP => type_size_bits(vex_ffi::op_result_type(iex.binop.op)),
            IEX_TRIOP => type_size_bits(vex_ffi::op_result_type((*iex.triop.details).op)),
            IEX_ITE => result_bits_c(irsb, iex.ite.iftrue),
            _ => 0,
        }
    }
}

fn const_bits(tag: u32) -> u32 {
    use vex_ffi::*;
    match tag {
        ICO_U1 => 1,
        ICO_U8 => 8,
        ICO_U16 => 16,
        ICO_U32 | ICO_F32 | ICO_F32I => 32,
        ICO_U64 | ICO_F64 | ICO_F64I => 64,
        ICO_V128 => 128,
        ICO_V256 => 256,
        _ => 0,
    }
}

// ===========================================================================
// VexArch / VexArchInfo construction for the FFI lift.
// ===========================================================================

fn vex_arch_int(name: &str) -> Option<u32> {
    Some(match name {
        "VexArchX86" => 0x401,
        "VexArchAMD64" => 0x402,
        "VexArchARM" => 0x403,
        "VexArchARM64" => 0x404,
        "VexArchPPC32" => 0x405,
        "VexArchPPC64" => 0x406,
        "VexArchS390X" => 0x407,
        "VexArchMIPS32" => 0x408,
        "VexArchMIPS64" => 0x409,
        "VexArchTILEGX" => 0x40A,
        "VexArchRISCV64" => 0x40B,
        _ => return None,
    })
}

fn build_archinfo(arch: &Bound<'_, PyAny>) -> PyResult<vex_ffi::VexArchInfo> {
    let vai = arch.getattr("vex_archinfo")?;
    let geti = |k: &str| -> PyResult<i64> {
        let v = vai.get_item(k)?;
        if v.is_none() { Ok(0) } else { v.extract() }
    };
    Ok(vex_ffi::VexArchInfo {
        hwcaps: geti("hwcaps")? as u32,
        endness: geti("endness")? as std::ffi::c_int,
        hwcache_info: vex_ffi::VexCacheInfo {
            num_levels: 0,
            num_caches: 0,
            caches: std::ptr::null_mut(),
            icaches_maintain_coherence: 1,
        },
        ppc_icache_line_sz_b: geti("ppc_icache_line_szB").unwrap_or(0) as std::ffi::c_int,
        ppc_dcbz_sz_b: geti("ppc_dcbz_szB").unwrap_or(0) as u32,
        ppc_dcbzl_sz_b: geti("ppc_dcbzl_szB").unwrap_or(0) as u32,
        arm64_d_min_line_lg2_sz_b: geti("arm64_dMinLine_lg2_szB").unwrap_or(0) as u32,
        arm64_i_min_line_lg2_sz_b: geti("arm64_iMinLine_lg2_szB").unwrap_or(0) as u32,
        x86_cr0: geti("x86_cr0").unwrap_or(0) as u32,
    })
}

// ===========================================================================
// VEXIRSBConverter (PyO3).
// ===========================================================================

#[pyclass(name = "VEXIRSBConverter", module = "angr.rustylib.ailment")]
pub struct VEXIRSBConverter;

impl VEXIRSBConverter {
    fn run<R: IrReader>(
        py: Python<'_>,
        reader: &R,
        block_addr_override: Option<i64>,
        manager: &Bound<'_, Manager>,
        arch: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        // The Manager is touched exactly twice: seed the local atom counter
        // here, and commit it back below -- only on success, so a failing
        // fast path leaves the Manager untouched (idx-identical fallback).
        let start_atom = manager.borrow().atom_ctr;
        let block_addr = block_addr_override.unwrap_or_else(|| reader.block_addr());

        let mut conv = Conv {
            py,
            reader,
            arch: ArchCtx::new(arch)?,
            atom: start_atom,
            ins_addr: None,
            block_addr,
            vex_stmt_idx: DEFAULT_STATEMENT,
        };
        let block = conv.convert_block()?;
        manager.borrow_mut().atom_ctr = conv.atom;
        Ok(block)
    }
}

#[pymethods]
impl VEXIRSBConverter {
    /// Default fast path: lift `data` at `addr` directly into libVEX and
    /// convert the resulting C IRSB to an AIL block without materializing a
    /// pyvex Python IRSB.
    #[staticmethod]
    #[pyo3(signature = (
        arch, addr, data, manager, *,
        opt_level=1, traceflags=0, strict_block_end=false, collect_data_refs=false,
        load_from_ro_regions=false, const_prop=false, cross_insn_opt=true,
        max_inst=99, max_bytes=None, bytes_offset=0
    ))]
    #[allow(clippy::too_many_arguments)]
    fn convert_from_lift(
        py: Python<'_>,
        arch: Bound<'_, PyAny>,
        addr: u64,
        data: Bound<'_, PyAny>,
        manager: Bound<'_, Manager>,
        opt_level: i32,
        traceflags: i32,
        strict_block_end: bool,
        collect_data_refs: bool,
        load_from_ro_regions: bool,
        const_prop: bool,
        cross_insn_opt: bool,
        max_inst: u32,
        max_bytes: Option<u32>,
        bytes_offset: u32,
    ) -> PyResult<Py<PyAny>> {
        vex_ffi::init_symbols(py);
        let lift = vex_ffi::vex_lift_fn().ok_or_else(|| {
            PyRuntimeError::new_err("libpyvex `vex_lift` symbol not found (is pyvex imported?)")
        })?;

        let vex_arch_name: String = arch.getattr("vex_arch")?.extract()?;
        let guest = vex_arch_int(&vex_arch_name)
            .ok_or_else(|| PyValueError::new_err(format!("unsupported VexArch {vex_arch_name}")))?;
        let archinfo = build_archinfo(&arch)?;

        // Borrow ``data`` zero-copy via the buffer protocol (accepts bytes,
        // bytearray, memoryview -- cle backers are bytearrays). The buffer must
        // outlive the lift, so `buf` is held until the end of this function.
        let buf = pyo3::buffer::PyBuffer::<u8>::get(&data)?;
        if !buf.is_c_contiguous() {
            return Err(PyValueError::new_err(
                "data must be a contiguous bytes-like buffer",
            ));
        }
        let data_ptr = buf.buf_ptr() as *const u8;
        let data_len = buf.item_count();
        if data_ptr.is_null() || data_len == 0 {
            return Err(PyValueError::new_err("empty data buffer"));
        }

        // Mirror pyvex.lift defaults.
        let mut opt_level = opt_level;
        let mut allow_arch_optimizations = true;
        if opt_level < 0 {
            allow_arch_optimizations = false;
            opt_level = 0;
        }
        let data_len_u32 = data_len.min(u32::MAX as usize) as u32;
        let mut mb = max_bytes.unwrap_or(data_len_u32).min(data_len_u32);
        if mb > 5000 {
            mb = 5000;
        }
        let max_inst = max_inst.min(99);
        let px_control: u32 = if cross_insn_opt { 0x702 } else { 0x705 };

        if (bytes_offset as usize) >= data_len {
            return Err(PyValueError::new_err("bytes_offset past end of data"));
        }
        let insn_start = unsafe { data_ptr.add(bytes_offset as usize) };

        // SAFETY: GIL is held for the whole call; we read the result before any
        // other lift can run. libVEX's `_lift_r`/arena stay valid until then.
        let lift_r = unsafe {
            lift(
                guest,
                archinfo,
                insn_start,
                addr,
                max_inst,
                mb,
                opt_level,
                traceflags,
                if allow_arch_optimizations { 1 } else { 0 },
                if strict_block_end { 1 } else { 0 },
                if collect_data_refs { 1 } else { 0 },
                if load_from_ro_regions { 1 } else { 0 },
                if const_prop { 1 } else { 0 },
                px_control,
                bytes_offset,
            )
        };
        if lift_r.is_null() {
            return Err(PyRuntimeError::new_err("libvex: vex_lift returned NULL"));
        }
        let (irsb, size) = unsafe { ((*lift_r).irsb, (*lift_r).size as i64) };
        if irsb.is_null() || size == 0 {
            return Err(PyRuntimeError::new_err(
                "libvex: could not decode any instructions",
            ));
        }

        let reader = CReader {
            irsb,
            size,
            dst_exprs: std::cell::RefCell::new(Vec::new()),
        };
        // The C IRSB has no addr; the AIL block addr is the lift address
        // (matches pyvex IRSB.addr / the first IMark).
        VEXIRSBConverter::run(py, &reader, Some(addr as i64), &manager, arch)
    }

    /// Fallback: convert a cached pyvex Python `IRSB` object.
    #[staticmethod]
    fn convert(
        py: Python<'_>,
        irsb: Bound<'_, PyAny>,
        manager: Bound<'_, Manager>,
    ) -> PyResult<Py<PyAny>> {
        vex_ffi::init_symbols(py);
        let arch = match &manager.borrow().arch {
            Some(a) => a.bind(py).clone(),
            None => {
                return Err(PyValueError::new_err(
                    "manager.arch must be set for VEX conversion",
                ));
            }
        };
        let tyenv = irsb.getattr("tyenv")?;
        let block_addr: i64 = irsb.getattr("addr")?.extract()?;
        // Keep manager state in sync with the legacy converter.
        {
            let mut m = manager.borrow_mut();
            m.tyenv = Some(tyenv.clone().unbind());
            m.block_addr = Some(block_addr);
        }
        let reader = PyReader {
            irsb: irsb.clone(),
            tyenv,
            statements: irsb.getattr("statements")?.cast_into::<PyList>()?,
        };
        VEXIRSBConverter::run(py, &reader, Some(block_addr), &manager, arch)
    }
}

// ===========================================================================
// Python-object reader: walks a pyvex Python IRSB.
// ===========================================================================

struct PyReader<'py> {
    irsb: Bound<'py, PyAny>,
    tyenv: Bound<'py, PyAny>,
    statements: Bound<'py, PyList>,
}

impl<'py> PyReader<'py> {
    fn result_size(&self, e: &Bound<'py, PyAny>) -> u32 {
        match e.call_method1("result_size", (&self.tyenv,)) {
            Ok(v) => v.extract().unwrap_or(0),
            Err(_) => 0,
        }
    }

    fn type_name(e: &Bound<'_, PyAny>) -> String {
        e.get_type()
            .name()
            .map(|n| n.to_string())
            .unwrap_or_default()
    }
}

impl<'py> IrReader for PyReader<'py> {
    type E = Py<PyAny>;

    fn block_addr(&self) -> i64 {
        self.irsb
            .getattr("addr")
            .and_then(|a| a.extract())
            .unwrap_or(0)
    }

    fn block_size(&self) -> Option<i64> {
        self.irsb
            .getattr("size")
            .ok()
            .and_then(|s| s.extract().ok())
    }

    fn jumpkind(&self) -> String {
        self.irsb
            .getattr("jumpkind")
            .and_then(|j| j.extract())
            .unwrap_or_default()
    }

    fn next_expr(&self) -> Self::E {
        self.irsb.getattr("next").unwrap().unbind()
    }

    fn num_stmts(&self) -> usize {
        self.statements.len()
    }

    fn stmt_kind(&self, py: Python<'_>, i: usize) -> PyResult<StmtKind<Self::E>> {
        let stmt = self.statements.get_item(i)?;
        let tn = Self::type_name(&stmt);
        Ok(match tn.as_str() {
            "IMark" => StmtKind::IMark {
                addr: stmt.getattr("addr")?.extract()?,
                delta: stmt.getattr("delta")?.extract()?,
            },
            "AbiHint" => StmtKind::AbiHint,
            "NoOp" => StmtKind::NoOp,
            "WrTmp" => {
                let data = stmt.getattr("data")?;
                let data_bits = self.result_size(&data);
                StmtKind::WrTmp {
                    tmp: stmt.getattr("tmp")?.extract()?,
                    data: unbind_any(data),
                    data_bits,
                }
            }
            "Put" => StmtKind::Put {
                offset: stmt.getattr("offset")?.extract()?,
                data: unbind_any(stmt.getattr("data")?),
            },
            "Store" => {
                let data = stmt.getattr("data")?;
                let size_bytes = (self.result_size(&data) / 8) as i32;
                StmtKind::Store {
                    addr: unbind_any(stmt.getattr("addr")?),
                    data: unbind_any(data),
                    size_bytes,
                    endness: stmt.getattr("endness")?.extract()?,
                }
            }
            "Exit" => StmtKind::Exit {
                guard: unbind_any(stmt.getattr("guard")?),
                dst: unbind_any(stmt.getattr("dst")?),
                jk: stmt.getattr("jumpkind")?.extract()?,
            },
            "LoadG" => {
                let dst: u32 = stmt.getattr("dst")?.extract()?;
                let dst_bits = self.tyenv.call_method1("sizeof", (dst,))?.extract()?;
                StmtKind::LoadG {
                    dst,
                    dst_bits,
                    cvt: stmt.getattr("cvt")?.extract()?,
                    addr: unbind_any(stmt.getattr("addr")?),
                    alt: unbind_any(stmt.getattr("alt")?),
                    guard: unbind_any(stmt.getattr("guard")?),
                    end: stmt.getattr("end")?.extract()?,
                }
            }
            "StoreG" => {
                let data = stmt.getattr("data")?;
                let size_bytes = (self.result_size(&data) / 8) as i32;
                StmtKind::StoreG {
                    addr: unbind_any(stmt.getattr("addr")?),
                    data: unbind_any(data),
                    size_bytes,
                    endness: stmt.getattr("endness")?.extract()?,
                    guard: unbind_any(stmt.getattr("guard")?),
                }
            }
            "CAS" => {
                let data_hi = stmt.getattr("dataHi")?;
                let expd_hi = stmt.getattr("expdHi")?;
                let old_lo: u32 = stmt.getattr("oldLo")?.extract()?;
                let old_hi_raw: u32 = stmt.getattr("oldHi")?.extract()?;
                let old_lo_bits = self.tyenv.call_method1("sizeof", (old_lo,))?.extract()?;
                let (old_hi, old_hi_bits) = if old_hi_raw != IRTEMP_INVALID {
                    (
                        Some(old_hi_raw),
                        self.tyenv
                            .call_method1("sizeof", (old_hi_raw,))?
                            .extract()?,
                    )
                } else {
                    (None, 0)
                };
                StmtKind::Cas {
                    addr: unbind_any(stmt.getattr("addr")?),
                    data_lo: unbind_any(stmt.getattr("dataLo")?),
                    data_hi: if data_hi.is_none() {
                        None
                    } else {
                        Some(unbind_any(data_hi))
                    },
                    expd_lo: unbind_any(stmt.getattr("expdLo")?),
                    expd_hi: if expd_hi.is_none() {
                        None
                    } else {
                        Some(unbind_any(expd_hi))
                    },
                    old_lo,
                    old_lo_bits,
                    old_hi,
                    old_hi_bits,
                    endness: stmt.getattr("endness")?.extract()?,
                }
            }
            "Dirty" => {
                let tmp_raw: u32 = stmt.getattr("tmp")?.extract()?;
                let (tmp, tmp_bits) = if tmp_raw != IRTEMP_INVALID {
                    (
                        Some(tmp_raw),
                        self.tyenv.call_method1("sizeof", (tmp_raw,))?.extract()?,
                    )
                } else {
                    (None, 0)
                };
                let guard = stmt.getattr("guard")?;
                let maddr = stmt.getattr("mAddr")?;
                let mut args = Vec::new();
                for a in stmt.getattr("args")?.try_iter()? {
                    args.push(a?.unbind());
                }
                StmtKind::Dirty {
                    callee: stmt.getattr("cee")?.getattr("name")?.extract()?,
                    args,
                    guard: if guard.is_none() {
                        None
                    } else {
                        Some(unbind_any(guard))
                    },
                    mfx: Some(stmt.getattr("mFx")?.extract()?),
                    maddr: if maddr.is_none() {
                        None
                    } else {
                        Some(unbind_any(maddr))
                    },
                    msize: Some(stmt.getattr("mSize")?.extract()?),
                    tmp,
                    tmp_bits,
                }
            }
            _ => {
                let _ = py;
                StmtKind::Other {
                    label: stmt.str()?.extract()?,
                }
            }
        })
    }

    fn expr_kind(&self, py: Python<'_>, e: &Self::E) -> PyResult<ExprKind<Self::E>> {
        let expr = e.bind(py);
        // pyvex.const.IRConst (e.g. Exit.dst) -> const_n in the original.
        let irconst_ty = py.import("pyvex")?.getattr("const")?.getattr("IRConst")?;
        if expr.is_instance(&irconst_ty)? {
            return Ok(ExprKind::Const {
                value: expr.getattr("value")?.extract()?,
                bits: expr.getattr("size")?.extract()?,
            });
        }
        let tn = Self::type_name(expr);
        Ok(match tn.as_str() {
            "RdTmp" => ExprKind::RdTmp {
                tmp: expr.getattr("tmp")?.extract()?,
                bits: self.result_size(expr),
            },
            "Get" => ExprKind::Get {
                offset: expr.getattr("offset")?.extract()?,
                bits: self.result_size(expr),
            },
            "Load" => ExprKind::Load {
                end: expr.getattr("end")?.extract()?,
                bits: self.result_size(expr),
                addr: unbind_any(expr.getattr("addr")?),
            },
            "Unop" => ExprKind::Unop {
                op: OpRef::Named {
                    name: expr.getattr("op")?.extract::<String>()?,
                    result_bits: self.result_size(expr),
                },
                arg: unbind_any(expr.getattr("args")?.get_item(0)?),
            },
            "Binop" => {
                let args = expr.getattr("args")?;
                ExprKind::Binop {
                    op: OpRef::Named {
                        name: expr.getattr("op")?.extract::<String>()?,
                        result_bits: self.result_size(expr),
                    },
                    arg1: unbind_any(args.get_item(0)?),
                    arg2: unbind_any(args.get_item(1)?),
                }
            }
            "Triop" => {
                let args = expr.getattr("args")?;
                let mut v = Vec::new();
                for a in args.try_iter()? {
                    v.push(a?.unbind());
                }
                ExprKind::Triop {
                    op: OpRef::Named {
                        name: expr.getattr("op")?.extract::<String>()?,
                        result_bits: self.result_size(expr),
                    },
                    args: v,
                }
            }
            "Const" => {
                let con = expr.getattr("con")?;
                ExprKind::Const {
                    value: con.getattr("value")?.extract()?,
                    bits: self.result_size(expr),
                }
            }
            "ITE" => ExprKind::Ite {
                cond: unbind_any(expr.getattr("cond")?),
                iftrue: unbind_any(expr.getattr("iftrue")?),
                iffalse: unbind_any(expr.getattr("iffalse")?),
            },
            "CCall" => {
                let mut args = Vec::new();
                for a in expr.getattr("args")?.try_iter()? {
                    args.push(a?.unbind());
                }
                ExprKind::CCall {
                    callee: expr.getattr("cee")?.getattr("name")?.extract()?,
                    args,
                    bits: self.result_size(expr),
                }
            }
            _ => {
                // Match the original converter's label: f"unsupported_{type(expr)!s}".
                // `unsupported_expr` prepends "unsupported_", so pass str(type(expr)).
                let label = expr.get_type().str()?.to_string();
                ExprKind::Unsupported {
                    label,
                    bits: self.result_size(expr),
                }
            }
        })
    }

    fn result_bits(&self, e: &Self::E) -> u32 {
        Python::attach(|py| self.result_size(e.bind(py)))
    }
}
