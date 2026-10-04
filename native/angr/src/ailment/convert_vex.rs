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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;

use crate::ailment::CachedHash;
use crate::ailment::ail_expr::{
    AilExpression, CFGTarget, DirtyExpr, ExprHeader, ExprInner, RoundingModeOrExpr,
};
use crate::ailment::ail_stmt::{AilStatement, StmtHeader, StmtInner};
use crate::ailment::block::Block;
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::{ConvertType, RoundingMode};
use crate::ailment::manager::Manager;
use crate::ailment::tags::{TagExtra, TagKey, Tags};
use crate::ailment::vex_ffi::{self, IRExpr, IRSB};
use crate::ailment::vexop::{self, SimOpInfo};

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
        /// The VEX access type is a floating-point type (``Ity_F*``).
        float: bool,
    },
    /// Indexed register-array read (x87 stack, etc.).
    GetI {
        ix: E,
        bits: u32,
        base: i64,
        bias: i64,
        n_elems: i64,
    },
    Load {
        end: String,
        bits: u32,
        addr: E,
        data_type: Option<String>,
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
    Qop {
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
    /// IRExpr_GSPTR: the guest-state pointer passed to dirty helpers. It has no
    /// program semantics, so dirty-call conversion drops it from the operands.
    GsPtr,
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
    /// Indexed register-array write.
    PutI {
        ix: E,
        data: E,
        base: i64,
        bias: i64,
        n_elems: i64,
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
    /// Whether the VEX result type of an expression is a floating-point type (``Ity_F*``).
    fn result_is_float(&self, e: &Self::E) -> bool;
}

// ===========================================================================
// Arch helpers (cached).
// ===========================================================================

struct ArchCtx<'py> {
    arch: Bound<'py, PyAny>,
    byte_width: u32,
    bits: u32,
    reg_name_memo: HashMap<(i64, u32), Option<String>>,
    /// Offsets of floating-point data registers and their sub-registers (scalar lanes).
    fp_data_reg_offsets: HashSet<i64>,
}

/// FP-flagged registers that VEX accesses as integers: the x87 register file (MMX aliases it with I64
/// accesses), the x87 status word and the AVX-512 mask registers.
const NON_DATA_FP_REGS: &[&str] = &[
    "fpreg", "fc3210", "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7",
];

impl<'py> ArchCtx<'py> {
    fn new(arch: Bound<'py, PyAny>) -> PyResult<Self> {
        let byte_width: u32 = arch.getattr("byte_width")?.extract()?;
        let bits: u32 = arch.getattr("bits")?.extract()?;
        let fp_data_reg_offsets = Self::collect_fp_data_reg_offsets(&arch)?;
        Ok(Self {
            arch,
            byte_width,
            bits,
            reg_name_memo: HashMap::new(),
            fp_data_reg_offsets,
        })
    }

    /// Registers that hold floating-point data: vector/FP registers of at least 8 bytes that are neither
    /// artificial nor control registers (control registers carry a default value).
    fn collect_fp_data_reg_offsets(arch: &Bound<'py, PyAny>) -> PyResult<HashSet<i64>> {
        let mut offsets = HashSet::new();
        let Ok(register_list) = arch.getattr("register_list") else {
            return Ok(offsets);
        };
        for reg in register_list.try_iter()? {
            let reg = reg?;
            let vector: bool = reg.getattr("vector")?.extract()?;
            let floating_point: bool = reg.getattr("floating_point")?.extract()?;
            let artificial: bool = reg.getattr("artificial")?.extract()?;
            let size: i64 = reg.getattr("size")?.extract()?;
            let name: String = reg.getattr("name")?.extract()?;
            if !(vector || floating_point)
                || artificial
                || size < 8
                || !reg.getattr("default_value")?.is_none()
                || NON_DATA_FP_REGS.contains(&name.as_str())
            {
                continue;
            }
            let offset: i64 = reg.getattr("vex_offset")?.extract()?;
            offsets.insert(offset);
            for sub in reg.getattr("subregisters")?.try_iter()? {
                let (_, sub_offset, sub_size): (String, i64, i64) = sub?.extract()?;
                if sub_size >= 4 {
                    offsets.insert(offset + sub_offset);
                }
            }
        }
        Ok(offsets)
    }

    /// An integer-typed VEX access of this width at this offset reads or writes the bit pattern of a scalar FP
    /// register.
    fn is_fp_scalar_slot(&self, offset: i64, bits: u32) -> bool {
        (bits == 32 || bits == 64) && self.fp_data_reg_offsets.contains(&offset)
    }

    fn reg_name(&mut self, offset: i64, size: u32) -> PyResult<Option<String>> {
        if let Some(v) = self.reg_name_memo.get(&(offset, size)) {
            return Ok(v.clone());
        }
        let res = self
            .arch
            .call_method1("translate_register_name", (offset, size))?;
        let name: Option<String> = res.extract()?;
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
    /// tmps holding a scalar zero-extended to vector width (``64UtoV128``): tmp -> (scalar, from_bits, to_bits)
    zext_tmps: HashMap<i64, (Arc<AilExpression>, u32, u32)>,
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
            extras: None,
        }
    }

    // ---- expression conversion ----------------------------------------

    fn convert_expr(&mut self, e: &R::E) -> PyResult<AilExpression> {
        let kind = self.reader.expr_kind(self.py, e)?;
        match kind {
            ExprKind::RdTmp { tmp, bits } => self.make_tmp(tmp as i64, bits),
            ExprKind::Get {
                offset,
                bits,
                float,
            } => {
                if !float && self.arch.is_fp_scalar_slot(offset, bits) {
                    // an integer read of an FP register (fmov x0, d0 / movq rax, xmm0) is a bit-pattern view
                    let idx = self.next_atom();
                    let reg = self.make_register(offset, bits)?;
                    return Ok(self.make_reinterpret(idx, reg, "F", "I", bits));
                }
                self.make_register(offset, bits)
            }
            ExprKind::GetI {
                ix,
                bits,
                base,
                bias,
                n_elems,
            } => self.make_iregister(&ix, bits, base, bias, n_elems),
            ExprKind::Load {
                end,
                bits,
                addr,
                data_type,
            } => {
                // Python arg eval order: Load(next_atom(), convert(addr), ...).
                let idx = self.next_atom();
                let addr_e = self.convert_expr(&addr)?;
                let size = (bits / 8) as i32;
                let depth = addr_e.header.depth + 1;
                let mut tags = self.tags();
                if let Some(dt) = data_type {
                    tags.insert_extra(TagKey::Custom("data_type".to_string()), TagExtra::Str(dt));
                }
                Ok(AilExpression {
                    header: ExprHeader::new(idx, depth, size.wrapping_mul(8) as u32, tags),
                    inner: ExprInner::Load {
                        addr: Arc::new(addr_e),
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
                self.finish_op(r, op.label(), bits, std::slice::from_ref(&arg))
            }
            ExprKind::Binop { op, arg1, arg2 } => {
                let bits = self.reader.result_bits(e);
                let args = [arg1, arg2];
                let r = self.convert_binop(&op, &args[0], &args[1], bits);
                self.finish_op(r, op.label(), bits, &args)
            }
            ExprKind::Triop { op, args } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_triop(&op, &args, bits);
                self.finish_op(r, op.label(), bits, &args)
            }
            ExprKind::Qop { op, args } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_qop(&op, &args, bits);
                self.finish_op(r, op.label(), bits, &args)
            }
            // Only reachable outside a dirty call's argument list (never emitted by libVEX).
            ExprKind::GsPtr => self.unsupported_expr("GSPTR".to_string(), 0),
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
            tags.insert_extra(TagKey::RegName, TagExtra::Str(n));
        }
        Ok(AilExpression {
            header: ExprHeader::new(idx, 0, bits, tags),
            inner: ExprInner::Register { reg_offset: offset },
        })
    }

    /// ``Reinterpret`` between an integer and a floating-point view of the same ``bits``.
    fn make_reinterpret(
        &self,
        idx: i64,
        operand: AilExpression,
        from_type: &str,
        to_type: &str,
        bits: u32,
    ) -> AilExpression {
        let depth = operand.header.depth + 1;
        AilExpression {
            header: ExprHeader::new(idx, depth, bits, self.tags()),
            inner: ExprInner::Reinterpret {
                operand: Arc::new(operand),
                from_bits: bits,
                from_type: from_type.to_string(),
                to_bits: bits,
                to_type: to_type.to_string(),
            },
        }
    }

    /// The integer scalar that the VEX expression ``data`` (converted to ``val``) zero-extends to vector width
    /// (``Iop_64UtoV128``, or a tmp holding one), as (scalar, from_bits, to_bits).
    fn vector_zext(
        &self,
        data: &R::E,
        val: &AilExpression,
    ) -> PyResult<Option<(Arc<AilExpression>, u32, u32)>> {
        match self.reader.expr_kind(self.py, data)? {
            ExprKind::RdTmp { tmp, .. } => Ok(self.zext_tmps.get(&(tmp as i64)).cloned()),
            ExprKind::Unop { op, .. } => {
                let Ok(simop) = op.simop() else {
                    return Ok(None);
                };
                if !matches!(simop.name.as_str(), "Iop_32UtoV128" | "Iop_64UtoV128") {
                    return Ok(None);
                }
                if let ExprInner::Convert {
                    operand,
                    from_bits,
                    to_bits,
                    ..
                } = &val.inner
                {
                    return Ok(Some((operand.clone(), *from_bits, *to_bits)));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// GetI/PutI target: ``IRegister`` over the converted index expression.
    fn make_iregister(
        &mut self,
        ix: &R::E,
        bits: u32,
        base: i64,
        bias: i64,
        n_elems: i64,
    ) -> PyResult<AilExpression> {
        let ix_e = self.convert_expr(ix)?;
        let idx = self.next_atom();
        let depth = ix_e.header.depth + 1;
        Ok(AilExpression {
            header: ExprHeader::new(idx, depth, bits, self.tags()),
            inner: ExprInner::IRegister {
                reg_offset: Arc::new(ix_e),
                array_base: base,
                array_bias: bias,
                array_n_elems: n_elems.max(1),
                array_shift: (bits / 8).max(1).trailing_zeros(),
            },
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
        if matches!(op.label().as_str(), "Iop_Sqrt32Fx8" | "Iop_Sqrt64Fx4") {
            // AVX vsqrtps/vsqrtpd ymm: unary, no rounding-mode operand
            let x = self.convert_expr(arg)?;
            return Ok(self.fp_unop("SqrtV", x, bits));
        }
        if op.label() == "Iop_TruncF64asF32" {
            // PPC stfs: the F64 narrowed to single precision, without a rounding-mode operand
            let idx = self.next_atom();
            let operand = self.convert_expr(arg)?;
            return Ok(new_convert(
                idx,
                64,
                32,
                false,
                operand,
                ConvertType::TypeFp,
                ConvertType::TypeFp,
                None,
                self.tags(),
            ));
        }
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
            if let Some(vector_count) = simop.vector_count {
                // lane-wise conversion, e.g. Iop_F16toF32x4 or Iop_F32toI32Sx4_RZ
                let idx = self.next_atom();
                let operand = self.convert_expr(arg)?;
                return Ok(self.vector_convert(&simop, idx, operand, vector_count, None));
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
            // Type the conversion by the op's operand types so FP widenings like
            // Iop_F32toF64 (a unary, rounding-free conversion) are tagged floating point.
            let from_ct = if simop.from_type.as_deref() == Some("F") {
                ConvertType::TypeFp
            } else {
                ConvertType::TypeInt
            };
            let to_ct = if simop.to_type.as_deref() == Some("F") {
                ConvertType::TypeFp
            } else {
                ConvertType::TypeInt
            };
            let idx = self.next_atom();
            let operand = self.convert_expr(arg)?;
            return Ok(new_convert(
                idx,
                from_size,
                to_size,
                signed,
                operand,
                from_ct,
                to_ct,
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
                floating_point: simop.float,
            },
        })
    }

    // ---- Binop ---------------------------------------------------------

    /// Build a lane-wise `Convert` for a vector conversion op. `from_bits`/`to_bits` are the
    /// total widths; the lane widths are `from_bits / vector_count` and `to_bits / vector_count`.
    fn vector_convert(
        &mut self,
        simop: &SimOpInfo,
        idx: i64,
        operand: AilExpression,
        vector_count: u32,
        rounding_mode: Option<RoundingModeOrExpr>,
    ) -> AilExpression {
        let from_type = convert_type_of(simop.from_type.as_deref());
        let to_type = convert_type_of(simop.to_type.as_deref());
        let is_signed = if from_type == ConvertType::TypeFp && to_type == ConvertType::TypeInt {
            simop.fp_to_int_signed()
        } else {
            simop.is_signed()
        };
        let rounding_mode = rounding_mode.or_else(|| suffix_rounding_mode(&simop.name));
        new_convert_v(
            idx,
            operand.header.bits,
            simop.output_size_bits,
            is_signed,
            operand,
            from_type,
            to_type,
            rounding_mode,
            Some(vector_count),
            self.tags(),
        )
    }

    fn convert_binop(
        &mut self,
        op: &OpRef,
        a1: &R::E,
        a2: &R::E,
        bits: u32,
    ) -> Result<AilExpression, ConvErr> {
        if let Some(e) = self.convert_math_binop(&op.label(), a1, a2, bits)? {
            return Ok(e);
        }
        let minmax_num = match op.label().as_str() {
            // AArch64 fmaxnm/fminnm: IEEE maxNum/minNum, i.e. C fmax/fmin
            "Iop_MaxNumF32" | "Iop_MaxNumF64" => Some("MaxF"),
            "Iop_MinNumF32" | "Iop_MinNumF64" => Some("MinF"),
            _ => None,
        };
        if let Some(ail_op) = minmax_num {
            let lhs = self.convert_expr(a1)?;
            let rhs = self.convert_expr(a2)?;
            return Ok(self.fp_binop(ail_op, lhs, rhs, bits));
        }
        let simop = op.simop().map_err(|_| ConvErr::Unsupported)?;
        let mut op_name = simop.generic_name.clone();
        if let (None, Some(vector_count)) = (op_name.as_deref(), simop.vector_count) {
            if !simop.is_conversion() {
                return Err(ConvErr::Unsupported);
            }
            // lane-wise conversion with a rounding-mode operand, e.g. Iop_F32toI32Sx4
            let rm = self.convert_expr(a1)?;
            let operand = self.convert_expr(a2)?;
            let idx = self.next_atom();
            let rm = Some(vex_rm_value(&rm));
            return Ok(self.vector_convert(&simop, idx, operand, vector_count, rm));
        }
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
        let mut floating_point = false;
        let mut vector_count: Option<i64> = None;
        let mut vector_size: Option<i64> = None;
        if simop.vector_zero
            && simop.float
            && let Some(scalar_op) = scalar_in_vector_op_name(op_name.as_deref())
            && let Some(scalar_bits) = simop.vector_size
        {
            let rhs = operands.pop().unwrap();
            let lhs = operands.pop().unwrap();
            return self.scalar_in_vector_op(scalar_op, lhs, rhs, scalar_bits, None);
        }
        if simop.vector_count.is_some() && simop.vector_size.is_some() {
            // a saturating narrow reads signed lanes either way (16Sto8S vs 16Sto8U); keep the result's signedness
            signed = if op_name.as_deref() == Some("QNarrowBin") {
                simop.vector_signed_is_s
            } else {
                simop.is_signed()
            };
            op_name = Some(format!("{}V", op_name.unwrap_or_default()));
            // lane-wise FP ops (CmpEQ64F0x2, CmpLT32Fx4, ...) keep their FP nature
            floating_point = simop.float;
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
                    simop.fp_to_int_signed(),
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

        // a conversion none of the branches above understood; never emit a nameless BinaryOp
        let Some(op_name) = op_name else {
            return Err(ConvErr::Unsupported);
        };
        let idx = self.next_atom();
        let rhs = operands.pop().unwrap();
        let lhs = operands.pop().unwrap();
        Ok(new_binop(
            idx,
            op_name,
            lhs,
            rhs,
            signed,
            floating_point,
            None,
            Some(bits),
            vector_count,
            vector_size,
            self.tags(),
        ))
    }

    /// Scalar-in-vector FP op (VEX "F0x" family, e.g. Add64F0x2): only the lowest lane participates.
    /// Emit Conv(N->128I, scalar_op) so Extract(Conv(N->128I, x), N@0) later recovers the scalar value.
    fn scalar_in_vector_op(
        &mut self,
        scalar_op: &str,
        lhs: AilExpression,
        rhs: AilExpression,
        scalar_bits: u32,
        rm: Option<RoundingModeOrExpr>,
    ) -> Result<AilExpression, ConvErr> {
        let lhs = self.unwrap_scalar_lane(lhs, scalar_bits)?;
        let rhs = self.unwrap_scalar_lane(rhs, scalar_bits)?;
        let binop_idx = self.next_atom();
        let conv_idx = self.next_atom();
        let binop = new_binop(
            binop_idx,
            scalar_op.to_string(),
            lhs,
            rhs,
            false,
            true,
            rm,
            Some(scalar_bits),
            None,
            None,
            self.tags(),
        );
        Ok(new_convert(
            conv_idx,
            scalar_bits,
            128,
            false,
            binop,
            ConvertType::TypeInt,
            ConvertType::TypeInt,
            None,
            self.tags(),
        ))
    }

    /// The N-bit scalar inside a 128-bit lane operand: unwrap a ``Conv(N->128I, x)`` widen, else extract the
    /// low N bits.
    fn unwrap_scalar_lane(
        &mut self,
        operand: AilExpression,
        n: u32,
    ) -> Result<AilExpression, ConvErr> {
        if let ExprInner::Convert {
            operand: inner,
            from_bits,
            to_bits,
            from_type: ConvertType::TypeInt,
            to_type: ConvertType::TypeInt,
            ..
        } = &operand.inner
            && *from_bits == n
            && *to_bits == 128
        {
            return Ok((**inner).clone());
        }
        let zero = self.make_const(ConstValue::Int(0), 64)?;
        let idx = self.next_atom();
        let depth = operand.header.depth.max(zero.header.depth) + 1;
        Ok(AilExpression {
            header: ExprHeader::new(idx, depth, n, self.tags()),
            inner: ExprInner::Extract {
                base: Arc::new(operand),
                offset: Arc::new(zero),
                endness: "Iend_LE".to_string(),
            },
        })
    }

    fn convert_triop(
        &mut self,
        op: &OpRef,
        args: &[R::E],
        bits: u32,
    ) -> Result<AilExpression, ConvErr> {
        if args.len() == 3 {
            if let Some(op_name) = f64r32_op_name(&op.label()) {
                // PPC fadds/fsubs/fmuls/fdivs: the F64 result rounded to single precision
                let rm_e = self.convert_expr(&args[0])?;
                let rm = vex_rm_value(&rm_e);
                let lhs = self.convert_expr(&args[1])?;
                let rhs = self.convert_expr(&args[2])?;
                let e = self.fp_binop_rm(op_name, lhs, rhs, bits, rm.clone());
                return Ok(self.round_f64_to_f32(e, rm));
            }
            if let Some(e) = self.convert_math_triop(&op.label(), &args[1], &args[2], bits)? {
                return Ok(e);
            }
        }
        let simop = op.simop().map_err(|_| ConvErr::Unsupported)?;
        let Some(op_name) = simop.generic_name.clone() else {
            return Err(ConvErr::Unsupported);
        };
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
            if simop.vector_zero
                && let Some(scalar_op) = scalar_in_vector_op_name(Some(op_name.as_str()))
                && let Some(scalar_bits) = simop.vector_size
            {
                return self.scalar_in_vector_op(scalar_op, lhs, rhs, scalar_bits, Some(rm));
            }
            // packed FP ops (Add64Fx2, Mul32Fx4, ...) are lane-wise: keep the "V" op name and the lane layout
            let (op_name, vector_count, vector_size) =
                if simop.vector_count.is_some() && simop.vector_size.is_some() {
                    (
                        format!("{op_name}V"),
                        simop.vector_count.map(|v| v as i64),
                        simop.vector_size.map(|v| v as i64),
                    )
                } else {
                    (op_name, None, None)
                };
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
                vector_count,
                vector_size,
                self.tags(),
            ));
        }
        // Non-fp triop: Python raises TypeError (unsupported in practice).
        Err(ConvErr::Unsupported)
    }

    // ---- x87 / SSE math ops without a symbolic-engine model ------------
    //
    // `vexop_to_simop` mirrors the symbolic engine, which has no claripy model for the x87
    // transcendental and remainder ops (and a few SSE ones). The converter still knows their
    // shape, so map them to AIL ops here instead of emitting an operand-less
    // `unsupported_*` DirtyExpression that drops the inputs.

    /// `Iop_XxxF64(rm, x)` binops and `Iop_CmpUN*` lane compares.
    fn convert_math_binop(
        &mut self,
        label: &str,
        a1: &R::E,
        a2: &R::E,
        bits: u32,
    ) -> Result<Option<AilExpression>, ConvErr> {
        let unary = match label {
            "Iop_SqrtF32" | "Iop_SqrtF64" | "Iop_SqrtF128" => Some("Sqrt"),
            "Iop_Sqrt32Fx4" | "Iop_Sqrt64Fx2" => Some("SqrtV"),
            "Iop_SinF64" => Some("Sin"),
            "Iop_CosF64" => Some("Cos"),
            "Iop_TanF64" => Some("Tan"),
            _ => None,
        };
        if let Some(ail_op) = unary {
            // the rounding mode (a1) is dropped: AIL unary ops carry none
            let x = self.convert_expr(a2)?;
            return Ok(Some(self.fp_unop(ail_op, x, bits)));
        }
        if label == "Iop_RoundF64toF32" {
            // PPC frsp: round the F64 to single precision; the result stays an F64
            let rm = self.convert_expr(a1)?;
            let x = self.convert_expr(a2)?;
            return Ok(Some(self.round_f64_to_f32(x, vex_rm_value(&rm))));
        }
        if label == "Iop_RndF128" {
            // s390x fixbr: same shape as Iop_RoundF128toInt, (rm Round x)
            let rm = self.convert_expr(a1)?;
            let x = self.convert_expr(a2)?;
            let idx = self.next_atom();
            return Ok(Some(new_binop(
                idx,
                "Round".to_string(),
                rm,
                x,
                false,
                false,
                None,
                Some(bits),
                None,
                None,
                self.tags(),
            )));
        }
        if label == "Iop_2xm1F64" {
            // f2xm1: 2^x - 1
            let x = self.convert_expr(a2)?;
            let exp2 = self.fp_unop("Exp2", x, bits);
            let one = self.make_const(ConstValue::Float(1.0), bits)?;
            return Ok(Some(self.fp_binop("Sub", exp2, one, bits)));
        }
        if let Some((count, size)) = cmpun_vector_shape(label) {
            let lhs = self.convert_expr(a1)?;
            let rhs = self.convert_expr(a2)?;
            let idx = self.next_atom();
            return Ok(Some(new_binop(
                idx,
                "CmpUNV".to_string(),
                lhs,
                rhs,
                false,
                true,
                None,
                Some(bits),
                Some(count),
                Some(size),
                self.tags(),
            )));
        }
        Ok(None)
    }

    /// `Iop_XxxF64(rm, a, b)` triops.
    fn convert_math_triop(
        &mut self,
        label: &str,
        a: &R::E,
        b: &R::E,
        bits: u32,
    ) -> Result<Option<AilExpression>, ConvErr> {
        let binary = match label {
            "Iop_AtanF64" => Some("Atan2"),  // fpatan: atan2(ST1, ST0)
            "Iop_PRemF64" => Some("PRem"),   // fprem: fmod(ST0, ST1)
            "Iop_PRem1F64" => Some("PRem1"), // fprem1: remainder(ST0, ST1)
            _ => None,
        };
        if let Some(ail_op) = binary {
            let lhs = self.convert_expr(a)?;
            let rhs = self.convert_expr(b)?;
            return Ok(Some(self.fp_binop(ail_op, lhs, rhs, bits)));
        }
        match label {
            "Iop_ScaleF64" => {
                // fscale: ST0 * 2^trunc(ST1) == ldexp(ST0, (int)ST1)
                let lhs = self.convert_expr(a)?;
                let rhs = self.convert_expr(b)?;
                let idx = self.next_atom();
                let exp = new_convert(
                    idx,
                    bits,
                    32,
                    true,
                    rhs,
                    ConvertType::TypeFp,
                    ConvertType::TypeInt,
                    Some(RoundingModeOrExpr::Mode(RoundingMode::RmTowardsZero)),
                    self.tags(),
                );
                Ok(Some(self.fp_binop("Scale", lhs, exp, bits)))
            }
            "Iop_Yl2xF64" | "Iop_Yl2xp1F64" => {
                // fyl2x: ST1 * log2(ST0); fyl2xp1: ST1 * log2(ST0 + 1)
                let y = self.convert_expr(a)?;
                let mut x = self.convert_expr(b)?;
                if label == "Iop_Yl2xp1F64" {
                    let one = self.make_const(ConstValue::Float(1.0), bits)?;
                    x = self.fp_binop("Add", x, one, bits);
                }
                let log2 = self.fp_unop("Log2", x, bits);
                Ok(Some(self.fp_binop("Mul", y, log2, bits)))
            }
            "Iop_PRemC3210F64" | "Iop_PRem1C3210F64" => {
                // the C3/C2/C0 status bits of fprem/fprem1, in FPU status-word layout: an intrinsic
                let callee = if label == "Iop_PRemC3210F64" {
                    "x87_fprem_c3210"
                } else {
                    "x87_fprem1_c3210"
                };
                let operands = vec![self.convert_expr(a)?, self.convert_expr(b)?];
                let idx = self.next_atom();
                Ok(Some(AilExpression {
                    header: ExprHeader::new(idx, 1, bits, self.tags()),
                    inner: ExprInner::DirtyExpression(Box::new(DirtyExpr {
                        callee: callee.to_string(),
                        operands,
                        guard: None,
                        mfx: None,
                        maddr: None,
                        msize: None,
                    })),
                }))
            }
            _ => Ok(None),
        }
    }

    fn fp_unop(&mut self, op: &str, operand: AilExpression, bits: u32) -> AilExpression {
        let idx = self.next_atom();
        let depth = operand.header.depth + 1;
        AilExpression {
            header: ExprHeader::new(idx, depth, bits, self.tags()),
            inner: ExprInner::UnaryOp {
                op: op.to_string(),
                operand: Arc::new(operand),
                floating_point: true,
            },
        }
    }

    fn fp_binop(
        &mut self,
        op: &str,
        lhs: AilExpression,
        rhs: AilExpression,
        bits: u32,
    ) -> AilExpression {
        let idx = self.next_atom();
        new_binop(
            idx,
            op.to_string(),
            lhs,
            rhs,
            true, // all floating-point operations are signed
            true,
            None,
            Some(bits),
            None,
            None,
            self.tags(),
        )
    }

    fn fp_binop_rm(
        &mut self,
        op: &str,
        lhs: AilExpression,
        rhs: AilExpression,
        bits: u32,
        rm: RoundingModeOrExpr,
    ) -> AilExpression {
        let idx = self.next_atom();
        new_binop(
            idx,
            op.to_string(),
            lhs,
            rhs,
            true,
            true,
            Some(rm),
            Some(bits),
            None,
            None,
            self.tags(),
        )
    }

    /// An op no mapping understood becomes an `unsupported_<Iop>` DirtyExpression that keeps the
    /// converted operands, so the inputs are not lost.
    fn finish_op(
        &mut self,
        r: Result<AilExpression, ConvErr>,
        op_label: String,
        bits: u32,
        args: &[R::E],
    ) -> PyResult<AilExpression> {
        match r {
            Ok(o) => Ok(o),
            Err(ConvErr::Unsupported) => {
                let operands = self.convert_list(args)?;
                let idx = self.next_atom();
                Ok(new_dirty_expr_with_operands(
                    idx,
                    format!("unsupported_{op_label}"),
                    operands,
                    bits,
                    self.tags(),
                ))
            }
            Err(ConvErr::Py(e)) => Err(e),
        }
    }

    // ---- Qop -----------------------------------------------------------

    /// Fused multiply-add family: `Iop_M{Add,Sub}F{32,64,128}(rm, a, b, c)` = `a * b +/- c`, the
    /// `NegM*F128` negations, and the PPC `*F64r32` forms rounded to single precision.
    fn convert_qop(
        &mut self,
        op: &OpRef,
        args: &[R::E],
        bits: u32,
    ) -> Result<AilExpression, ConvErr> {
        let label = op.label();
        let (sub, neg, round32) = match label.as_str() {
            "Iop_MAddF32" | "Iop_MAddF64" | "Iop_MAddF128" => (false, false, false),
            "Iop_MSubF32" | "Iop_MSubF64" | "Iop_MSubF128" => (true, false, false),
            "Iop_NegMAddF128" => (false, true, false),
            "Iop_NegMSubF128" => (true, true, false),
            "Iop_MAddF64r32" => (false, false, true),
            "Iop_MSubF64r32" => (true, false, true),
            _ => return Err(ConvErr::Unsupported),
        };
        if args.len() != 4 {
            return Err(ConvErr::Unsupported);
        }
        let rm_e = self.convert_expr(&args[0])?;
        let rm = vex_rm_value(&rm_e);
        let a = self.convert_expr(&args[1])?;
        let b = self.convert_expr(&args[2])?;
        let c = self.convert_expr(&args[3])?;
        let mul = self.fp_binop_rm("Mul", a, b, bits, rm.clone());
        let mut e = self.fp_binop_rm(if sub { "Sub" } else { "Add" }, mul, c, bits, rm.clone());
        if neg {
            e = self.fp_unop("Neg", e, bits);
        }
        if round32 {
            e = self.round_f64_to_f32(e, rm);
        }
        Ok(e)
    }

    /// `Conv(32->64F, Conv(64->32F, x))`: an F64 rounded to single precision (PPC `frsp`,
    /// `fadds` & co.).
    fn round_f64_to_f32(&mut self, e: AilExpression, rm: RoundingModeOrExpr) -> AilExpression {
        let idx = self.next_atom();
        let narrowed = new_convert(
            idx,
            64,
            32,
            false,
            e,
            ConvertType::TypeFp,
            ConvertType::TypeFp,
            Some(rm),
            self.tags(),
        );
        let idx = self.next_atom();
        new_convert(
            idx,
            32,
            64,
            false,
            narrowed,
            ConvertType::TypeFp,
            ConvertType::TypeFp,
            None,
            self.tags(),
        )
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
                if let Some(zext) = self.vector_zext(&data, &val)? {
                    self.zext_tmps.insert(tmp as i64, zext);
                }
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
                let mut val = self.convert_expr(&data)?;
                let bits = val.header.bits;
                if !self.reader.result_is_float(&data) && self.arch.is_fp_scalar_slot(offset, bits)
                {
                    // an integer write into an FP register (fmov d0, x0 / movq xmm0, rax) stores a bit pattern
                    let idx = self.next_atom();
                    val = self.make_reinterpret(idx, val, "I", "F", bits);
                } else {
                    if let Some((scalar, from_bits, to_bits)) = self.vector_zext(&data, &val)?
                        && self.arch.is_fp_scalar_slot(offset, from_bits)
                    {
                        // a scalar zero-extended into a vector register (movq xmm0, rax) stores a bit pattern in lane 0
                        let idx = self.next_atom();
                        let lane =
                            self.make_reinterpret(idx, (*scalar).clone(), "I", "F", from_bits);
                        let idx = self.next_atom();
                        val = new_convert(
                            idx,
                            from_bits,
                            to_bits,
                            false,
                            lane,
                            ConvertType::TypeInt,
                            ConvertType::TypeInt,
                            None,
                            self.tags(),
                        );
                    }
                }
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
            StmtKind::PutI {
                ix,
                data,
                base,
                bias,
                n_elems,
            } => {
                let bits = self.reader.result_bits(&data);
                let dst = self.make_iregister(&ix, bits, base, bias, n_elems)?;
                let val = self.convert_expr(&data)?;
                let idx = self.next_atom();
                out.push(new_stmt(
                    idx,
                    self.tags(),
                    StmtInner::Assignment {
                        dst: Arc::new(dst),
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
                let mut ops = Vec::with_capacity(args.len());
                for a in &args {
                    if matches!(self.reader.expr_kind(self.py, a)?, ExprKind::GsPtr) {
                        continue;
                    }
                    ops.push(self.convert_expr(a)?);
                }
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
                    inner: ExprInner::DirtyExpression(Box::new(DirtyExpr {
                        callee,
                        operands: ops,
                        guard: g.map(Arc::new),
                        mfx,
                        maddr: ma.map(Arc::new),
                        msize,
                    })),
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

    fn convert_block(&mut self) -> PyResult<Block> {
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
        let py_stmts = PyList::new(self.py, statements)?;
        Ok(Block {
            addr,
            original_size: self.reader.block_size(),
            statements: py_stmts.unbind(),
            idx: None,
            cached_hash: CachedHash::new(),
        })
    }

    fn emit_call_tail(&mut self, jk: &str, statements: &mut Vec<AilStatement>) -> PyResult<()> {
        let ret_offset: i64 = self.arch.arch.getattr("ret_offset")?.extract()?;
        let bits = self.arch.bits;
        let ret_name = self.arch.reg_name(ret_offset, bits)?;
        let ret_expr = {
            let aidx = self.next_atom();
            let mut tags = self.tags();
            if let Some(n) = ret_name {
                tags.insert_extra(TagKey::RegName, TagExtra::Str(n));
            }
            AilExpression {
                header: ExprHeader::new(aidx, 0, bits, tags),
                inner: ExprInner::Register {
                    reg_offset: ret_offset,
                },
            }
        };

        let fp_ret_offset: Option<i64> = self.arch.arch.getattr("fp_ret_offset")?.extract()?;
        let fp_ret_expr: Option<AilExpression> = if let Some(fp_ret_offset) = fp_ret_offset {
            if fp_ret_offset == ret_offset {
                None
            } else {
                let fp_name = self.arch.reg_name(fp_ret_offset, bits)?;
                let aidx = self.next_atom();
                let mut tags = self.tags();
                if let Some(n) = fp_name {
                    tags.insert_extra(TagKey::RegName, TagExtra::Str(n));
                }
                Some(AilExpression {
                    header: ExprHeader::new(aidx, 0, bits, tags),
                    inner: ExprInner::Register {
                        reg_offset: fp_ret_offset,
                    },
                })
            }
        } else {
            None
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
/// The scalar AIL op name for a VEX scalar-in-vector ("F0x") generic name, if it is one we lower.
fn scalar_in_vector_op_name(generic: Option<&str>) -> Option<&'static str> {
    match generic {
        Some("Add") => Some("Add"),
        Some("Sub") => Some("Sub"),
        Some("Mul") => Some("Mul"),
        Some("Div") => Some("Div"),
        Some("Max") => Some("MaxF"),
        Some("Min") => Some("MinF"),
        _ => None,
    }
}

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
    new_convert_v(
        idx,
        from_bits,
        to_bits,
        is_signed,
        operand,
        from_type,
        to_type,
        rounding_mode,
        None,
        tags,
    )
}

/// `new_convert` with a lane count for vector conversions (`Iop_F32toI32Sx4` etc.).
#[allow(clippy::too_many_arguments)]
fn new_convert_v(
    idx: i64,
    from_bits: u32,
    to_bits: u32,
    is_signed: bool,
    operand: AilExpression,
    from_type: ConvertType,
    to_type: ConvertType,
    rounding_mode: Option<RoundingModeOrExpr>,
    vector_count: Option<u32>,
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
            vector_count,
        },
    }
}

fn convert_type_of(t: Option<&str>) -> ConvertType {
    if t == Some("F") {
        ConvertType::TypeFp
    } else {
        ConvertType::TypeInt
    }
}

/// Rounding mode baked into an op name (`Iop_F32toI32Sx4_RZ`), if any. The deprecated `_DEP`
/// forms carry no rounding mode at all.
fn suffix_rounding_mode(name: &str) -> Option<RoundingModeOrExpr> {
    let mode = match name.rsplit_once('_')?.1 {
        "RZ" => RoundingMode::RmTowardsZero,
        "RN" => RoundingMode::RmNearestTiesEven,
        "RM" => RoundingMode::RmTowardsNegativeInf,
        "RP" => RoundingMode::RmTowardsPositiveInf,
        _ => return None,
    };
    Some(RoundingModeOrExpr::Mode(mode))
}

/// `(lane count, lane bits)` of an `Iop_CmpUN<bits>F[0]x<count>` unordered lane compare.
fn cmpun_vector_shape(label: &str) -> Option<(i64, i64)> {
    let (size, lanes) = label.strip_prefix("Iop_CmpUN")?.split_once('F')?;
    let count = lanes.trim_start_matches('0').strip_prefix('x')?;
    Some((count.parse().ok()?, size.parse().ok()?))
}

/// `_new_dirty_expression` with no operands: depth is a constant 1.
fn new_dirty_expr(idx: i64, callee: String, bits: u32, tags: Tags) -> AilExpression {
    new_dirty_expr_with_operands(idx, callee, Vec::new(), bits, tags)
}

fn new_dirty_expr_with_operands(
    idx: i64,
    callee: String,
    operands: Vec<AilExpression>,
    bits: u32,
    tags: Tags,
) -> AilExpression {
    AilExpression {
        header: ExprHeader::new(idx, 1, bits, tags),
        inner: ExprInner::DirtyExpression(Box::new(DirtyExpr {
            callee,
            operands,
            guard: None,
            mfx: None,
            maddr: None,
            msize: None,
        })),
    }
}

/// AIL op of a PPC `Iop_<Op>F64r32(rm, a, b)` (F64 arithmetic rounded to single precision).
fn f64r32_op_name(label: &str) -> Option<&'static str> {
    Some(match label {
        "Iop_AddF64r32" => "Add",
        "Iop_SubF64r32" => "Sub",
        "Iop_MulF64r32" => "Mul",
        "Iop_DivF64r32" => "Div",
        _ => return None,
    })
}

const EXIT_SKIP_JK: &[&str] = &[
    "Ijk_EmWarn",
    "Ijk_NoDecode",
    "Ijk_MapFail",
    "Ijk_NoRedir",
    "Ijk_SigTRAP",
    "Ijk_SigSEGV",
    // alignment-check exits (AArch64 ldar/stlr, PPC lwarx); amd64 emits the same checks as Ijk_SigSEGV
    "Ijk_SigBUS",
    "Ijk_ClientReq",
    "Ijk_SigFPE_IntDiv",
];

fn loadg_sizes(cvt: &str) -> PyResult<(u32, u32, bool)> {
    Ok(match cvt {
        "ILGop_Ident32" => (32, 32, false),
        "ILGop_Ident64" => (64, 64, false),
        "ILGop_IdentV128" => (128, 128, false),
        "ILGop_Ident16" => (16, 16, false),
        "ILGop_Ident8" => (8, 8, false),
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
            ICO_U128 => (expand_vector(ico.u128 as u64, 16), 128),
            ICO_F32 | ICO_F32I => (ConstValue::Float(ico.f32_ as f64), 32),
            ICO_F64 | ICO_F64I => (ConstValue::Float(ico.f64_), 64),
            ICO_V128 => (expand_vector(ico.v128 as u64, 16), 128),
            ICO_V256 => (expand_vector(ico.v256 as u64, 32), 256),
            ICO_V512 => (expand_vector(ico.v512, 64), 512),
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
        0x1D04 => "ILGop_Ident16",
        0x1D05 => "ILGop_Ident8",
        0x1D06 => "ILGop_16Uto32",
        0x1D07 => "ILGop_16Sto32",
        0x1D08 => "ILGop_8Uto32",
        0x1D09 => "ILGop_8Sto32",
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
                IST_PUTI => {
                    let d = &*ist.puti.details;
                    let descr = &*d.descr;
                    StmtKind::PutI {
                        ix: d.ix,
                        data: d.data,
                        base: descr.base as i64,
                        bias: d.bias as i64,
                        n_elems: descr.n_elems as i64,
                    }
                }
                _ => {
                    // MBE / LLSC etc.: the Python converter labels these
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
                    float: vex_ffi::ity_float_name(iex.get.ty).is_some(),
                },
                IEX_LOAD => ExprKind::Load {
                    end: endness_str(iex.load.end).to_string(),
                    bits: type_size_bits(iex.load.ty),
                    addr: iex.load.addr,
                    data_type: vex_ffi::ity_float_name(iex.load.ty).map(str::to_string),
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
                IEX_QOP => {
                    let d = &*iex.qop.details;
                    ExprKind::Qop {
                        op: OpRef::Int(d.op),
                        args: vec![d.arg1, d.arg2, d.arg3, d.arg4],
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
                IEX_GETI => {
                    let g = &iex.geti;
                    let descr = &*g.descr;
                    ExprKind::GetI {
                        ix: g.ix,
                        bits: type_size_bits(descr.elem_ty),
                        base: descr.base as i64,
                        bias: g.bias as i64,
                        n_elems: descr.n_elems as i64,
                    }
                }
                IEX_GSPTR => ExprKind::GsPtr,
                _ => {
                    // VECRET / Binder: the Python converter
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

    fn result_is_float(&self, e: &Self::E) -> bool {
        vex_ffi::ity_float_name(unsafe { result_ty_c(self.irsb, *e) }).is_some()
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
    // Const has no IRType; its tag decides the width
    if tag == IEX_CONST {
        return const_bits(unsafe { (*iex.con.con).tag });
    }
    type_size_bits(unsafe { result_ty_c(irsb, e) })
}

/// VEX `result_type` (an ``Ity_*`` tag) for a C expression; ``ITY_INVALID`` if undeterminable.
unsafe fn result_ty_c(irsb: *mut IRSB, e: *mut IRExpr) -> u32 {
    use vex_ffi::*;
    if e.is_null() {
        return ITY_INVALID;
    }
    let tag = unsafe { (*e).tag };
    let iex = unsafe { &(*e).iex };
    unsafe {
        match tag {
            IEX_RDTMP => (*(*irsb).tyenv).lookup(iex.rdtmp.tmp),
            IEX_GET => iex.get.ty,
            IEX_LOAD => iex.load.ty,
            IEX_GETI => (*iex.geti.descr).elem_ty,
            IEX_CONST => const_ty((*iex.con.con).tag),
            IEX_CCALL => iex.ccall.retty,
            IEX_UNOP => vex_ffi::op_result_type(iex.unop.op),
            IEX_BINOP => vex_ffi::op_result_type(iex.binop.op),
            IEX_TRIOP => vex_ffi::op_result_type((*iex.triop.details).op),
            IEX_QOP => vex_ffi::op_result_type((*iex.qop.details).op),
            IEX_ITE => result_ty_c(irsb, iex.ite.iftrue),
            _ => ITY_INVALID,
        }
    }
}

fn const_ty(tag: u32) -> u32 {
    use vex_ffi::*;
    match tag {
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

fn const_bits(tag: u32) -> u32 {
    use vex_ffi::*;
    match tag {
        ICO_U1 => 1,
        ICO_U8 => 8,
        ICO_U16 => 16,
        ICO_U32 | ICO_F32 | ICO_F32I => 32,
        ICO_U64 | ICO_F64 | ICO_F64I => 64,
        ICO_U128 | ICO_V128 => 128,
        ICO_V256 => 256,
        ICO_V512 => 512,
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
    let geti =
        |k: &str| -> PyResult<i64> { Ok(vai.get_item(k)?.extract::<Option<i64>>()?.unwrap_or(0)) };
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
        ppc_scv_supported: geti("ppc_scv_supported").unwrap_or(0) as u8,
        ppc_dcbzl_sz_b: geti("ppc_dcbzl_szB").unwrap_or(0) as u32,
        arm64_d_min_line_lg2_sz_b: geti("arm64_dMinLine_lg2_szB").unwrap_or(0) as u32,
        arm64_i_min_line_lg2_sz_b: geti("arm64_iMinLine_lg2_szB").unwrap_or(0) as u32,
        arm64_cache_block_size: geti("arm64_cache_block_size").unwrap_or(0) as u8,
        arm64_requires_fallback_llsc: geti("arm64_requires_fallback_LLSC").unwrap_or(0) as u8,
        // cr0 == 0 means real mode to the x86 lifter, so a missing key must
        // fall back to libVEX's protected-mode default, not to zero.
        x86_cr0: match geti("x86_cr0") {
            Ok(0) | Err(_) => 0xFFFF_FFFF,
            Ok(v) => v as u32,
        },
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
    ) -> PyResult<Block> {
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
            zext_tmps: HashMap::new(),
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
    ) -> PyResult<Block> {
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

        // libVEX decoders may read the full length of an instruction that
        // *starts* inside the [bytes_offset, bytes_offset + mb) window -- i.e.
        // a few bytes past `mb`, and past the end of the caller's buffer when
        // the window ends at (or near) it. pyvex guards its Python path by
        // lifting from a copy padded with 8 NUL bytes; mirror that here, but
        // only when the window actually ends within 8 bytes of the buffer end
        // so the common case stays zero-copy.
        let window_end = bytes_offset as usize + mb as usize;
        // Held until the end of this function so `insn_start` stays valid.
        let _padded: Option<Vec<u8>>;
        let lift_base: *const u8 = if window_end + 8 <= data_len {
            _padded = None;
            data_ptr
        } else {
            let mut v = Vec::with_capacity(data_len + 8);
            v.extend_from_slice(unsafe { std::slice::from_raw_parts(data_ptr, data_len) });
            v.extend_from_slice(&[0u8; 8]);
            let p = v.as_ptr();
            _padded = Some(v);
            p
        };
        let insn_start = unsafe { lift_base.add(bytes_offset as usize) };

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
    ) -> PyResult<Block> {
        vex_ffi::init_symbols(py);
        let arch = irsb.getattr("arch")?;
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
                    data: data.unbind(),
                    data_bits,
                }
            }
            "Put" => StmtKind::Put {
                offset: stmt.getattr("offset")?.extract()?,
                data: stmt.getattr("data")?.unbind(),
            },
            "PutI" => {
                let descr = stmt.getattr("descr")?;
                StmtKind::PutI {
                    ix: stmt.getattr("ix")?.unbind(),
                    data: stmt.getattr("data")?.unbind(),
                    base: descr.getattr("base")?.extract()?,
                    bias: stmt.getattr("bias")?.extract()?,
                    n_elems: descr.getattr("nElems")?.extract()?,
                }
            }
            "Store" => {
                let data = stmt.getattr("data")?;
                let size_bytes = (self.result_size(&data) / 8) as i32;
                StmtKind::Store {
                    addr: stmt.getattr("addr")?.unbind(),
                    data: data.unbind(),
                    size_bytes,
                    endness: stmt.getattr("endness")?.extract()?,
                }
            }
            "Exit" => StmtKind::Exit {
                guard: stmt.getattr("guard")?.unbind(),
                dst: stmt.getattr("dst")?.unbind(),
                jk: stmt.getattr("jumpkind")?.extract()?,
            },
            "LoadG" => {
                let dst: u32 = stmt.getattr("dst")?.extract()?;
                let dst_bits = self.tyenv.call_method1("sizeof", (dst,))?.extract()?;
                StmtKind::LoadG {
                    dst,
                    dst_bits,
                    cvt: stmt.getattr("cvt")?.extract()?,
                    addr: stmt.getattr("addr")?.unbind(),
                    alt: stmt.getattr("alt")?.unbind(),
                    guard: stmt.getattr("guard")?.unbind(),
                    end: stmt.getattr("end")?.extract()?,
                }
            }
            "StoreG" => {
                let data = stmt.getattr("data")?;
                let size_bytes = (self.result_size(&data) / 8) as i32;
                StmtKind::StoreG {
                    addr: stmt.getattr("addr")?.unbind(),
                    data: data.unbind(),
                    size_bytes,
                    endness: stmt.getattr("endness")?.extract()?,
                    guard: stmt.getattr("guard")?.unbind(),
                }
            }
            "CAS" => {
                let data_hi: Option<Py<PyAny>> = stmt.getattr("dataHi")?.extract()?;
                let expd_hi: Option<Py<PyAny>> = stmt.getattr("expdHi")?.extract()?;
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
                    addr: stmt.getattr("addr")?.unbind(),
                    data_lo: stmt.getattr("dataLo")?.unbind(),
                    data_hi,
                    expd_lo: stmt.getattr("expdLo")?.unbind(),
                    expd_hi,
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
                let guard: Option<Py<PyAny>> = stmt.getattr("guard")?.extract()?;
                let maddr: Option<Py<PyAny>> = stmt.getattr("mAddr")?.extract()?;
                let args: Vec<Py<PyAny>> = stmt.getattr("args")?.extract()?;
                StmtKind::Dirty {
                    callee: stmt.getattr("cee")?.getattr("name")?.extract()?,
                    args,
                    guard,
                    // pyvex leaves mFx/mSize as None when the helper has no memory effect
                    mfx: stmt.getattr("mFx")?.extract()?,
                    maddr,
                    msize: stmt.getattr("mSize")?.extract()?,
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
                float: expr
                    .getattr("ty")?
                    .extract::<String>()
                    .map(|t| t.starts_with("Ity_F"))
                    .unwrap_or(false),
            },
            "GetI" => {
                let descr = expr.getattr("descr")?;
                ExprKind::GetI {
                    ix: expr.getattr("ix")?.unbind(),
                    bits: self.result_size(expr),
                    base: descr.getattr("base")?.extract()?,
                    bias: expr.getattr("bias")?.extract()?,
                    n_elems: descr.getattr("nElems")?.extract()?,
                }
            }
            "Load" => {
                let ty: Option<String> = expr.getattr("ty").ok().and_then(|t| t.extract().ok());
                ExprKind::Load {
                    end: expr.getattr("end")?.extract()?,
                    bits: self.result_size(expr),
                    addr: expr.getattr("addr")?.unbind(),
                    data_type: ty.filter(|t| t.starts_with("Ity_F")),
                }
            }
            "Unop" => ExprKind::Unop {
                op: OpRef::Named {
                    name: expr.getattr("op")?.extract::<String>()?,
                    result_bits: self.result_size(expr),
                },
                arg: expr.getattr("args")?.get_item(0)?.unbind(),
            },
            "Binop" => {
                let args = expr.getattr("args")?;
                ExprKind::Binop {
                    op: OpRef::Named {
                        name: expr.getattr("op")?.extract::<String>()?,
                        result_bits: self.result_size(expr),
                    },
                    arg1: args.get_item(0)?.unbind(),
                    arg2: args.get_item(1)?.unbind(),
                }
            }
            "Triop" => {
                let v: Vec<Py<PyAny>> = expr.getattr("args")?.extract()?;
                ExprKind::Triop {
                    op: OpRef::Named {
                        name: expr.getattr("op")?.extract::<String>()?,
                        result_bits: self.result_size(expr),
                    },
                    args: v,
                }
            }
            "Qop" => {
                let v: Vec<Py<PyAny>> = expr.getattr("args")?.extract()?;
                ExprKind::Qop {
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
                cond: expr.getattr("cond")?.unbind(),
                iftrue: expr.getattr("iftrue")?.unbind(),
                iffalse: expr.getattr("iffalse")?.unbind(),
            },
            "CCall" => {
                let args: Vec<Py<PyAny>> = expr.getattr("args")?.extract()?;
                ExprKind::CCall {
                    callee: expr.getattr("cee")?.getattr("name")?.extract()?,
                    args,
                    bits: self.result_size(expr),
                }
            }
            "GSPTR" => ExprKind::GsPtr,
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

    fn result_is_float(&self, e: &Self::E) -> bool {
        Python::attach(
            |py| match e.bind(py).call_method1("result_type", (&self.tyenv,)) {
                Ok(v) => v
                    .extract::<String>()
                    .map(|t| t.starts_with("Ity_F"))
                    .unwrap_or(false),
                Err(_) => false,
            },
        )
    }
}
