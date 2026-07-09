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

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::ailment::ail_expr::{ExprInner, Expression};
use crate::ailment::const_value::ConstValue;
use crate::ailment::enums::{ConvertType, RoundingMode};
use crate::ailment::manager::Manager;
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

/// A converted constant value (already a Python int/float object) + its width.
struct ConstVal {
    value: Py<PyAny>,
    bits: u32,
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
        op: u32,
        arg: E,
    },
    Binop {
        op: u32,
        arg1: E,
        arg2: E,
    },
    Triop {
        op: u32,
        args: Vec<E>,
    },
    Const {
        value: Py<PyAny>,
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
// Cached AIL class objects.
//
// The concrete AIL classes are the Python-side marker classes (see
// ``angr/ailment/expression.py`` / ``statement.py``); calling one constructs
// the single Rust ``Expression`` / ``Statement`` pyclass with the matching
// variant. ``Block`` is still a Rust pyclass.
// ===========================================================================

struct Ail<'py> {
    const_: Bound<'py, PyAny>,
    tmp: Bound<'py, PyAny>,
    register: Bound<'py, PyAny>,
    load: Bound<'py, PyAny>,
    unary_op: Bound<'py, PyAny>,
    binary_op: Bound<'py, PyAny>,
    convert: Bound<'py, PyAny>,
    reinterpret: Bound<'py, PyAny>,
    ite: Bound<'py, PyAny>,
    vex_ccall: Bound<'py, PyAny>,
    call: Bound<'py, PyAny>,
    dirty_expr: Bound<'py, PyAny>,
    assignment: Bound<'py, PyAny>,
    store: Bound<'py, PyAny>,
    jump: Bound<'py, PyAny>,
    cond_jump: Bound<'py, PyAny>,
    side_effect: Bound<'py, PyAny>,
    ret: Bound<'py, PyAny>,
    cas: Bound<'py, PyAny>,
    dirty_stmt: Bound<'py, PyAny>,
    block: Bound<'py, PyAny>,
}

impl<'py> Ail<'py> {
    fn new(py: Python<'py>) -> PyResult<Self> {
        let exprs = py.import("angr.ailment.expression")?;
        let stmts = py.import("angr.ailment.statement")?;
        Ok(Self {
            const_: exprs.getattr("Const")?,
            tmp: exprs.getattr("Tmp")?,
            register: exprs.getattr("Register")?,
            load: exprs.getattr("Load")?,
            unary_op: exprs.getattr("UnaryOp")?,
            binary_op: exprs.getattr("BinaryOp")?,
            convert: exprs.getattr("Convert")?,
            reinterpret: exprs.getattr("Reinterpret")?,
            ite: exprs.getattr("ITE")?,
            vex_ccall: exprs.getattr("VEXCCallExpression")?,
            call: exprs.getattr("Call")?,
            dirty_expr: exprs.getattr("DirtyExpression")?,
            assignment: stmts.getattr("Assignment")?,
            store: stmts.getattr("Store")?,
            jump: stmts.getattr("Jump")?,
            cond_jump: stmts.getattr("ConditionalJump")?,
            side_effect: stmts.getattr("SideEffectStatement")?,
            ret: stmts.getattr("Return")?,
            cas: stmts.getattr("CAS")?,
            dirty_stmt: stmts.getattr("DirtyStatement")?,
            block: py.get_type::<crate::ailment::block::Block>().into_any(),
        })
    }
}

// ===========================================================================
// Conversion core.
// ===========================================================================

struct Conv<'py, 'r, R: IrReader> {
    py: Python<'py>,
    reader: &'r R,
    ail: Ail<'py>,
    arch: ArchCtx<'py>,
    // atom allocation: local counter, optionally backed by a native Manager.
    atom: i64,
    native_manager: Option<Py<Manager>>,
    py_manager: Bound<'py, PyAny>,
    ins_addr: Option<i64>,
    block_addr: i64,
    vex_stmt_idx: i64,
}

impl<'py, 'r, R: IrReader> Conv<'py, 'r, R> {
    fn next_atom(&mut self) -> PyResult<i64> {
        if self.native_manager.is_some() {
            let v = self.atom;
            self.atom += 1;
            Ok(v)
        } else {
            self.py_manager.call_method0("next_atom")?.extract()
        }
    }

    /// Standard tag dict (ins_addr / vex_block_addr / vex_stmt_idx).
    fn tags(&self) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(self.py);
        if let Some(ia) = self.ins_addr {
            d.set_item("ins_addr", ia)?;
        }
        d.set_item("vex_block_addr", self.block_addr)?;
        d.set_item("vex_stmt_idx", self.vex_stmt_idx)?;
        Ok(d)
    }

    fn build<A>(
        &self,
        cls: &Bound<'py, PyAny>,
        args: A,
        kwargs: &Bound<'py, PyDict>,
    ) -> PyResult<Py<PyAny>>
    where
        A: pyo3::call::PyCallArgs<'py>,
    {
        Ok(cls.call(args, Some(kwargs))?.unbind())
    }

    // ---- expression conversion ----------------------------------------

    fn convert_expr(&mut self, e: &R::E) -> PyResult<Py<PyAny>> {
        let kind = self.reader.expr_kind(self.py, e)?;
        match kind {
            ExprKind::RdTmp { tmp, bits } => self.make_tmp(tmp as i64, bits),
            ExprKind::Get { offset, bits } => self.make_register(offset, bits),
            ExprKind::Load { end, bits, addr } => {
                // Python arg eval order: Load(next_atom(), convert(addr), ...).
                let idx = self.next_atom()?;
                let addr_obj = self.convert_expr(&addr)?;
                let kw = self.tags()?;
                self.build(
                    &self.ail.load.clone(),
                    (idx, addr_obj, (bits / 8) as i32, end),
                    &kw,
                )
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
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                self.build(&self.ail.ite.clone(), (idx, c, f, t), &kw)
            }
            ExprKind::CCall { callee, args, bits } => {
                let mut ops = Vec::with_capacity(args.len());
                for a in &args {
                    ops.push(self.convert_expr(a)?);
                }
                let ops_list = PyList::new(self.py, ops)?;
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                kw.set_item("bits", bits)?;
                self.build(&self.ail.vex_ccall.clone(), (idx, callee, ops_list), &kw)
            }
            ExprKind::Unop { op, arg } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_unop(op, &arg, bits);
                self.finish_op(r, op, bits)
            }
            ExprKind::Binop { op, arg1, arg2 } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_binop(op, &arg1, &arg2);
                self.finish_op(r, op, bits)
            }
            ExprKind::Triop { op, args } => {
                let bits = self.reader.result_bits(e);
                let r = self.convert_triop(op, &args);
                self.finish_op(r, op, bits)
            }
            ExprKind::Unsupported { label, bits } => self.unsupported_expr(label, bits),
        }
    }

    fn convert_list(&mut self, args: &[R::E]) -> PyResult<Vec<Py<PyAny>>> {
        let mut out = Vec::with_capacity(args.len());
        for a in args {
            out.push(self.convert_expr(a)?);
        }
        Ok(out)
    }

    fn make_tmp(&mut self, tmp_idx: i64, bits: u32) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        self.build(&self.ail.tmp.clone(), (idx, tmp_idx, bits), &kw)
    }

    fn make_register(&mut self, offset: i64, bits: u32) -> PyResult<Py<PyAny>> {
        let reg_size = bits / self.arch.byte_width;
        let reg_name = self.arch.reg_name(offset, reg_size)?;
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        if let Some(n) = reg_name {
            kw.set_item("reg_name", n)?;
        }
        self.build(&self.ail.register.clone(), (idx, offset, bits), &kw)
    }

    fn make_const(&mut self, value: Py<PyAny>, bits: u32) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        self.build(&self.ail.const_.clone(), (idx, value, bits), &kw)
    }

    fn unsupported_expr(&mut self, label: String, bits: u32) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        kw.set_item("bits", bits)?;
        let empty = PyList::empty(self.py);
        self.build(
            &self.ail.dirty_expr.clone(),
            (idx, format!("unsupported_{label}"), empty),
            &kw,
        )
    }

    // ---- Unop ----------------------------------------------------------

    /// Returns Err(ConvErr::Unsupported) -> caller emits DirtyExpression
    /// (matches the Python `try/except UnsupportedIROpError`).
    ///
    /// `bits` is the VEX result size of the whole unop expression (the
    /// Python converter's `expr.result_size(manager.tyenv)`).
    fn convert_unop(&mut self, op: u32, arg: &R::E, bits: u32) -> Result<Py<PyAny>, ConvErr> {
        let simop = vexop::vexop_to_simop(op).map_err(|_| ConvErr::Unsupported)?;
        let op_name = simop.generic_name.clone();

        if op_name.as_deref() == Some("Reinterp") {
            // Python arg eval order: Reinterpret(next_atom(), ..., convert(arg)).
            let idx = self.next_atom()?;
            let operand = self.convert_expr(arg)?;
            let kw = self.tags()?;
            return Ok(self.build(
                &self.ail.reinterpret.clone(),
                (
                    idx,
                    simop.from_size.unwrap_or(0),
                    simop.from_type.clone().unwrap_or_default(),
                    simop.to_size.unwrap_or(0),
                    simop.to_type.clone().unwrap_or_default(),
                    operand,
                ),
                &kw,
            )?);
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
                    let idx = self.next_atom()?;
                    let shift_const = self.make_const(to_size.into_py_any(self.py)?, 8)?;
                    let kw = self.tags()?;
                    let operands = PyList::new(self.py, [inner, shift_const])?;
                    self.build(
                        &self.ail.binary_op.clone(),
                        (idx, "Shr", operands, false),
                        &kw,
                    )?
                };
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                return Ok(self.build(
                    &self.ail.convert.clone(),
                    (idx, from_size, to_size, signed, shifted),
                    &kw,
                )?);
            }
            // Python arg eval order: Convert(next_atom(), ..., convert(arg)).
            let idx = self.next_atom()?;
            let operand = self.convert_expr(arg)?;
            let kw = self.tags()?;
            return Ok(self.build(
                &self.ail.convert.clone(),
                (idx, from_size, to_size, signed, operand),
                &kw,
            )?);
        }

        let mut name = op_name.unwrap();
        if name == "Not" && op_label(op) != "Iop_Not1" {
            name = "BitwiseNeg".to_string();
        }
        // Python arg eval order: UnaryOp(next_atom(), name, convert(arg), bits=...).
        let idx = self.next_atom()?;
        let operand = self.convert_expr(arg)?;
        let kw = self.tags()?;
        kw.set_item("bits", bits)?;
        Ok(self.build(&self.ail.unary_op.clone(), (idx, name, operand), &kw)?)
    }

    // ---- Binop ---------------------------------------------------------

    fn convert_binop(&mut self, op: u32, a1: &R::E, a2: &R::E) -> Result<Py<PyAny>, ConvErr> {
        let simop = vexop::vexop_to_simop(op).map_err(|_| ConvErr::Unsupported)?;
        let mut op_name = simop.generic_name.clone();
        let mut operands = vec![self.convert_expr(a1)?, self.convert_expr(a2)?];

        // Add + negative Const -> Sub
        if op_name.as_deref() == Some("Add")
            && let Some((cidx, val, bits)) = const_int_parts(self.py, &operands[1])
            && int_const_sign_bit(&val, bits)
        {
            op_name = Some("Sub".to_string());
            let new_val = int_const_negated(self.py, &val, bits)?;
            operands[1] = self.make_const_no_tags(cidx, new_val, bits)?;
        }

        let mut signed = false;
        let mut vector_count: Option<i64> = None;
        let mut vector_size: Option<i64> = None;
        if simop.vector_count.is_some() && simop.vector_size.is_some() {
            op_name = Some(format!("{}V", op_name.unwrap_or_default()));
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
                let rm = vex_rm_value(self.py, &operands[0])?;
                let operand = operands[1].clone_ref(self.py);
                return Ok(self.make_convert_typed(
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeInt,
                    ConvertType::TypeFp,
                    rm,
                )?);
            }
            if simop.from_side.as_deref() == Some("HL") {
                op_name = Some("Concat".to_string());
            } else if simop.from_type.as_deref() == Some("F")
                && simop.to_type.as_deref() == Some("F")
            {
                let rm = vex_rm_value(self.py, &operands[0])?;
                let operand = operands[1].clone_ref(self.py);
                return Ok(self.make_convert_typed(
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeFp,
                    ConvertType::TypeFp,
                    rm,
                )?);
            } else if simop.from_type.as_deref() == Some("F")
                && simop.to_type.as_deref() == Some("I")
            {
                let rm = vex_rm_value(self.py, &operands[0])?;
                let operand = operands[1].clone_ref(self.py);
                return Ok(self.make_convert_typed(
                    from_size,
                    to_size,
                    simop.is_signed(),
                    operand,
                    ConvertType::TypeFp,
                    ConvertType::TypeInt,
                    rm,
                )?);
            }
        }

        let bits = simop.output_size_bits;

        if op_name.as_deref() == Some("DivMod") {
            let op1_size = simop
                .from_size
                .unwrap_or_else(|| pyobj_bits(operands[0].bind(self.py)).unwrap_or(0));
            let mut op2_size = simop
                .to_size
                .unwrap_or_else(|| pyobj_bits(operands[1].bind(self.py)).unwrap_or(0));
            if op2_size < op1_size {
                let signed_cvt = simop.from_signed.as_deref() != Some("U");
                let o = operands[1].clone_ref(self.py);
                operands[1] = self.make_convert(op2_size, op1_size, signed_cvt, o)?;
                op2_size = op1_size;
            }
            let _ = op2_size;
            let chunk_bits = bits / 2;
            let div = self.make_binop_bits("Div", &operands, signed, op1_size)?;
            let truncated_div = self.make_convert(op1_size, chunk_bits, signed, div)?;
            let modd = self.make_binop_bits("Mod", &operands, signed, op1_size)?;
            let truncated_mod = self.make_convert(op1_size, chunk_bits, signed, modd)?;
            operands = vec![truncated_mod, truncated_div];
            op_name = Some("Concat".to_string());
            signed = false;
            return Ok(self.make_binop(
                op_name.unwrap(),
                &operands,
                signed,
                Some(bits),
                None,
                None,
            )?);
        }

        Ok(self.make_binop(
            op_name.unwrap_or_default(),
            &operands,
            signed,
            Some(bits),
            vector_count,
            vector_size,
        )?)
    }

    fn convert_triop(&mut self, op: u32, args: &[R::E]) -> Result<Py<PyAny>, ConvErr> {
        let simop = vexop::vexop_to_simop(op).map_err(|_| ConvErr::Unsupported)?;
        let op_name = simop.generic_name.clone().unwrap_or_default();
        let operands = self.convert_list(args)?;
        let bits = simop.output_size_bits;
        if simop.float {
            // first operand is the rounding mode -> BinaryOp over the rest
            let rm = vex_rm_value(self.py, &operands[0])?;
            let rest = &operands[1..];
            let idx = self.next_atom()?;
            let kw = self.tags()?;
            kw.set_item("floating_point", true)?;
            kw.set_item("rounding_mode", rm)?;
            kw.set_item("bits", bits)?;
            let operands_list = PyList::new(self.py, rest.iter().map(|o| o.clone_ref(self.py)))?;
            return Ok(self.build(
                &self.ail.binary_op.clone(),
                (idx, op_name, operands_list, true),
                &kw,
            )?);
        }
        // Non-fp triop: Python raises TypeError (unsupported in practice).
        Err(ConvErr::Unsupported)
    }

    fn finish_op(
        &mut self,
        r: Result<Py<PyAny>, ConvErr>,
        op: u32,
        bits: u32,
    ) -> PyResult<Py<PyAny>> {
        match r {
            Ok(o) => Ok(o),
            Err(ConvErr::Unsupported) => self.unsupported_expr(op_label(op), bits),
            Err(ConvErr::Py(e)) => Err(e),
        }
    }

    // ---- small AIL builders -------------------------------------------

    fn make_const_no_tags(&self, idx: i64, value: Py<PyAny>, bits: u32) -> PyResult<Py<PyAny>> {
        let kw = PyDict::new(self.py);
        self.build(&self.ail.const_.clone(), (idx, value, bits), &kw)
    }

    fn make_convert(
        &mut self,
        from: u32,
        to: u32,
        signed: bool,
        operand: Py<PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        self.build(
            &self.ail.convert.clone(),
            (idx, from, to, signed, operand),
            &kw,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_convert_typed(
        &mut self,
        from: u32,
        to: u32,
        signed: bool,
        operand: Py<PyAny>,
        from_type: ConvertType,
        to_type: ConvertType,
        rm: Py<PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        kw.set_item("from_type", from_type)?;
        kw.set_item("to_type", to_type)?;
        kw.set_item("rounding_mode", rm)?;
        self.build(
            &self.ail.convert.clone(),
            (idx, from, to, signed, operand),
            &kw,
        )
    }

    fn make_binop(
        &mut self,
        op_name: String,
        operands: &[Py<PyAny>],
        signed: bool,
        bits: Option<u32>,
        vector_count: Option<i64>,
        vector_size: Option<i64>,
    ) -> PyResult<Py<PyAny>> {
        let idx = self.next_atom()?;
        let kw = self.tags()?;
        if let Some(b) = bits {
            kw.set_item("bits", b)?;
        }
        if let Some(vc) = vector_count {
            kw.set_item("vector_count", vc)?;
        }
        if let Some(vs) = vector_size {
            kw.set_item("vector_size", vs)?;
        }
        let operands_list = PyList::new(self.py, operands.iter().map(|o| o.clone_ref(self.py)))?;
        self.build(
            &self.ail.binary_op.clone(),
            (idx, op_name, operands_list, signed),
            &kw,
        )
    }

    fn make_binop_bits(
        &mut self,
        op_name: &str,
        operands: &[Py<PyAny>],
        signed: bool,
        bits: u32,
    ) -> PyResult<Py<PyAny>> {
        self.make_binop(
            op_name.to_string(),
            operands,
            signed,
            Some(bits),
            None,
            None,
        )
    }

    // ---- statement conversion -----------------------------------------

    /// Returns the converted statement objects (usually one) appended to
    /// `out`, and whether it was a ConditionalJump (for false-target backpatch).
    ///
    /// Statement idx values come from `next_atom()` (like every expression),
    /// allocated at the exact point the Python converter's arg-eval order
    /// reaches the statement constructor's `manager.next_atom()` call.
    fn convert_stmt(&mut self, kind: StmtKind<R::E>, out: &mut Vec<Py<PyAny>>) -> PyResult<bool> {
        match kind {
            StmtKind::WrTmp {
                tmp,
                data,
                data_bits,
            } => {
                let var = self.make_tmp(tmp as i64, data_bits)?;
                let val = self.convert_expr(&data)?;
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                out.push(self.build(&self.ail.assignment.clone(), (idx, var, val), &kw)?);
                Ok(false)
            }
            StmtKind::Put { offset, data } => {
                let val = self.convert_expr(&data)?;
                let bits = pyobj_bits(val.bind(self.py))?;
                let reg = self.make_register(offset, bits)?;
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                out.push(self.build(&self.ail.assignment.clone(), (idx, reg, val), &kw)?);
                Ok(false)
            }
            StmtKind::Store {
                addr,
                data,
                size_bytes,
                endness,
            } => {
                // Python arg eval order: Store(next_atom(), convert(addr), convert(data), ...).
                let idx = self.next_atom()?;
                let a = self.convert_expr(&addr)?;
                let d = self.convert_expr(&data)?;
                let kw = self.tags()?;
                out.push(self.build(
                    &self.ail.store.clone(),
                    (idx, a, d, size_bytes, endness),
                    &kw,
                )?);
                Ok(false)
            }
            StmtKind::Exit { guard, dst, jk } => {
                if EXIT_SKIP_JK.contains(&jk.as_str()) {
                    return Ok(false); // SkipConversionNotice
                }
                // Python arg eval order: ConditionalJump(next_atom(), convert(guard), convert(dst), None).
                let idx = self.next_atom()?;
                let g = self.convert_expr(&guard)?;
                let d = self.convert_expr(&dst)?;
                let kw = self.tags()?;
                out.push(self.build(
                    &self.ail.cond_jump.clone(),
                    (idx, g, d, self.py.None()),
                    &kw,
                )?);
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
                let lidx = self.next_atom()?;
                let a = self.convert_expr(&addr)?;
                let g = self.convert_expr(&guard)?;
                let al = self.convert_expr(&alt)?;
                // Load has NO tags in the Python converter for LoadG.
                let load = {
                    let kw = PyDict::new(self.py);
                    kw.set_item("guard", g)?;
                    kw.set_item("alt", al)?;
                    self.build(
                        &self.ail.load.clone(),
                        (lidx, a, (load_bits / 8) as i32, end),
                        &kw,
                    )?
                };
                let src = if convert_bits != load_bits {
                    let cidx = self.next_atom()?;
                    let kw = PyDict::new(self.py);
                    self.build(
                        &self.ail.convert.clone(),
                        (cidx, load_bits, convert_bits, signed, load),
                        &kw,
                    )?
                } else {
                    load
                };
                let idx = self.next_atom()?;
                let kw = self.tags()?;
                out.push(self.build(&self.ail.assignment.clone(), (idx, dst_var, src), &kw)?);
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
                let idx = self.next_atom()?;
                let a = self.convert_expr(&addr)?;
                let d = self.convert_expr(&data)?;
                let g = self.convert_expr(&guard)?;
                let kw = self.tags()?;
                kw.set_item("guard", g)?;
                out.push(self.build(
                    &self.ail.store.clone(),
                    (idx, a, d, size_bytes, endness),
                    &kw,
                )?);
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
                    Some(e) => self.convert_expr(&e)?,
                    None => self.py.None(),
                };
                let el = self.convert_expr(&expd_lo)?;
                let eh = match expd_hi {
                    Some(e) => self.convert_expr(&e)?,
                    None => self.py.None(),
                };
                let ol = self.make_tmp(old_lo as i64, old_lo_bits)?;
                let oh = match old_hi {
                    Some(t) => self.make_tmp(t as i64, old_hi_bits)?,
                    None => self.py.None(),
                };
                let idx = self.next_atom()?;
                // CAS only sets ins_addr (matches Python).
                let kw = PyDict::new(self.py);
                if let Some(ia) = self.ins_addr {
                    kw.set_item("ins_addr", ia)?;
                }
                out.push(self.build(
                    &self.ail.cas.clone(),
                    (idx, a, dl, dh, el, eh, ol, oh, endness),
                    &kw,
                )?);
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
                let didx = self.next_atom()?;
                let kw = self.tags()?;
                if let Some(g) = g {
                    kw.set_item("guard", g)?;
                }
                if let Some(mfx) = mfx {
                    kw.set_item("mfx", mfx)?;
                }
                if let Some(ma) = ma {
                    kw.set_item("maddr", ma)?;
                }
                if let Some(ms) = msize {
                    kw.set_item("msize", ms)?;
                }
                kw.set_item("bits", tmp_bits)?;
                let ops_list = PyList::new(self.py, ops)?;
                let dirty_expr =
                    self.build(&self.ail.dirty_expr.clone(), (didx, callee, ops_list), &kw)?;
                match tmp {
                    None => {
                        let idx = self.next_atom()?;
                        let kw2 = self.tags()?;
                        out.push(self.build(
                            &self.ail.dirty_stmt.clone(),
                            (idx, dirty_expr),
                            &kw2,
                        )?);
                    }
                    Some(t) => {
                        let tmp_var = self.make_tmp(t as i64, tmp_bits)?;
                        let idx = self.next_atom()?;
                        let kw2 = self.tags()?;
                        out.push(self.build(
                            &self.ail.assignment.clone(),
                            (idx, tmp_var, dirty_expr),
                            &kw2,
                        )?);
                    }
                }
                Ok(false)
            }
            StmtKind::Other { label } => {
                let didx = self.next_atom()?;
                let kw = self.tags()?;
                kw.set_item("bits", 0u32)?;
                let empty = PyList::empty(self.py);
                let dirty_expr =
                    self.build(&self.ail.dirty_expr.clone(), (didx, label, empty), &kw)?;
                let idx = self.next_atom()?;
                let kw2 = self.tags()?;
                out.push(self.build(&self.ail.dirty_stmt.clone(), (idx, dirty_expr), &kw2)?);
                Ok(false)
            }
            StmtKind::IMark { .. } | StmtKind::AbiHint | StmtKind::NoOp => Ok(false),
        }
    }

    // ---- whole IRSB ----------------------------------------------------

    fn convert_block(&mut self) -> PyResult<Py<PyAny>> {
        let mut statements: Vec<Py<PyAny>> = Vec::new();
        let mut addr = self.block_addr;
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
                statements[pos]
                    .bind(self.py)
                    .setattr("false_target", false_target)?;
            } else {
                // Match the original's arg eval order: the Jump's idx
                // (next_atom) is allocated *before* the target is converted.
                let jidx = self.next_atom()?;
                let next = self.reader.next_expr();
                let target = self.convert_expr(&next)?;
                let kw = self.tags()?;
                statements.push(self.build(&self.ail.jump.clone(), (jidx, target), &kw)?);
            }
        } else if jk == "Ijk_Ret" {
            let ridx = self.next_atom()?;
            let kw = self.tags()?;
            let empty = PyList::empty(self.py);
            statements.push(self.build(&self.ail.ret.clone(), (ridx, empty), &kw)?);
        } else if jk == "Ijk_SigTRAP" {
            // int3 -> MSVC __debugbreak() intrinsic: a side-effecting call to
            // an opaque (dirty) intrinsic, mirroring the syscall path.
            let target = {
                let didx = self.next_atom()?;
                let kw = PyDict::new(self.py);
                kw.set_item("bits", self.arch.bits)?;
                let empty = PyList::empty(self.py);
                self.build(
                    &self.ail.dirty_expr.clone(),
                    (didx, "__debugbreak", empty),
                    &kw,
                )?
            };
            let call_expr = {
                let cidx = self.next_atom()?;
                let kw = self.tags()?;
                kw.set_item("args", PyList::empty(self.py))?;
                kw.set_item("bits", self.py.None())?;
                self.build(&self.ail.call.clone(), (cidx, target), &kw)?
            };
            let seidx = self.next_atom()?;
            let kw = self.tags()?;
            statements.push(self.build(&self.ail.side_effect.clone(), (seidx, call_expr), &kw)?);
        } else {
            // Unknown/unsupported jumpkind: an opaque dirty placeholder whose
            // callee is a clean C identifier (never an internal diagnostic
            // string, which must not leak into the AIL/C output).
            let dirty_expr = {
                let didx = self.next_atom()?;
                let kw = PyDict::new(self.py);
                kw.set_item("bits", 0u32)?;
                let empty = PyList::empty(self.py);
                self.build(
                    &self.ail.dirty_expr.clone(),
                    (didx, format!("__unsupported_jumpkind_{jk}"), empty),
                    &kw,
                )?
            };
            let sidx = self.next_atom()?;
            let kw = self.tags()?;
            statements.push(self.build(&self.ail.dirty_stmt.clone(), (sidx, dirty_expr), &kw)?);
        }

        // Build the Block.
        let stmts_list = PyList::new(self.py, statements)?;
        let size = self.reader.block_size();
        let block = self
            .ail
            .block
            .call((addr, size, stmts_list), None::<&Bound<'py, PyDict>>)?;
        Ok(block.unbind())
    }

    fn emit_call_tail(&mut self, jk: &str, statements: &mut Vec<Py<PyAny>>) -> PyResult<()> {
        let ret_offset: i64 = self.arch.arch.getattr("ret_offset")?.extract()?;
        let bits = self.arch.bits;
        let ret_name = self.arch.reg_name(ret_offset, bits)?;
        let ret_expr = {
            let aidx = self.next_atom()?;
            let kw = self.tags()?;
            if let Some(n) = ret_name {
                kw.set_item("reg_name", n)?;
            }
            self.build(&self.ail.register.clone(), (aidx, ret_offset, bits), &kw)?
        };

        let fp_ret_obj = self.arch.arch.getattr("fp_ret_offset")?;
        let fp_ret_expr: Option<Py<PyAny>> = if fp_ret_obj.is_none() {
            None
        } else {
            let fp_ret_offset: i64 = fp_ret_obj.extract()?;
            if fp_ret_offset == ret_offset {
                None
            } else {
                let fp_name = self.arch.reg_name(fp_ret_offset, bits)?;
                let aidx = self.next_atom()?;
                let kw = self.tags()?;
                if let Some(n) = fp_name {
                    kw.set_item("reg_name", n)?;
                }
                Some(self.build(&self.ail.register.clone(), (aidx, fp_ret_offset, bits), &kw)?)
            }
        };

        let target = if jk == "Ijk_Call" {
            let next = self.reader.next_expr();
            self.convert_expr(&next)?
        } else {
            // Ijk_Sys*: hack -- DirtyExpression("syscall")
            let didx = self.next_atom()?;
            let kw = PyDict::new(self.py);
            kw.set_item("bits", bits)?;
            let empty = PyList::empty(self.py);
            self.build(&self.ail.dirty_expr.clone(), (didx, "syscall", empty), &kw)?
        };

        let ret_bits = pyobj_bits(ret_expr.bind(self.py))?;
        let call_expr = {
            let cidx = self.next_atom()?;
            let kw = self.tags()?;
            kw.set_item("bits", ret_bits)?;
            self.build(&self.ail.call.clone(), (cidx, target), &kw)?
        };

        let seidx = self.next_atom()?;
        let kw = self.tags()?;
        kw.set_item("ret_expr", ret_expr)?;
        if let Some(fp) = fp_ret_expr {
            kw.set_item("fp_ret_expr", fp)?;
        }
        statements.push(self.build(&self.ail.side_effect.clone(), (seidx, call_expr), &kw)?);
        Ok(())
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

fn pyobj_bits(o: &Bound<'_, PyAny>) -> PyResult<u32> {
    o.getattr("bits")?.extract()
}

// ---------------------------------------------------------------------------
// Native readers into Const-variant Expressions, used by the Add->Sub rewrite
// and the rounding-mode extraction. These mirror the Python-side `Const.value`
// / `Const.sign_bit` accessors without a Python attribute round-trip.
// ---------------------------------------------------------------------------

/// An integer constant read out of a Const-variant `Expression`.
enum IntConst {
    Small(i128),
    Big(num_bigint::BigInt),
}

/// `(idx, int value, bits)` of a Const-variant int `Expression`; `None` if the
/// object is not a Const or holds a float.
fn const_int_parts(py: Python<'_>, obj: &Py<PyAny>) -> Option<(i64, IntConst, u32)> {
    let e = obj.bind(py).cast::<Expression>().ok()?;
    let b = e.borrow();
    match &b.expr.inner {
        ExprInner::Const { value } => {
            let v = match value {
                ConstValue::Int(v) => IntConst::Small(*v),
                ConstValue::BigInt(bi) => IntConst::Big(bi.clone()),
                ConstValue::Float(_) => return None,
            };
            Some((b.expr.header.idx, v, b.expr.header.bits))
        }
        _ => None,
    }
}

/// Bit `bits - 1` of the value's raw pattern (the Python `Const.sign_bit`).
fn int_const_sign_bit(v: &IntConst, bits: u32) -> bool {
    if bits == 0 {
        return false;
    }
    let top = (bits - 1) as u64;
    match v {
        IntConst::Small(v) if bits <= 128 => (*v >> top) & 1 != 0,
        IntConst::Small(v) => num_bigint::BigInt::from(*v).bit(top),
        IntConst::Big(b) => b.bit(top),
    }
}

/// The Python converter's `(1 << bits) - value`, as a Python int.
fn int_const_negated(py: Python<'_>, v: &IntConst, bits: u32) -> PyResult<Py<PyAny>> {
    match v {
        IntConst::Small(v) if bits < 127 => ((1i128 << bits) - v).into_py_any(py),
        IntConst::Small(v) => {
            ((num_bigint::BigInt::from(1) << bits) - num_bigint::BigInt::from(*v)).into_py_any(py)
        }
        IntConst::Big(b) => ((num_bigint::BigInt::from(1) << bits) - b).into_py_any(py),
    }
}

/// The rounding-mode operand of a float op: a Const int operand maps to the
/// typed `RoundingMode(value & 0b11)` enum; any other expression (e.g. a tmp
/// -- VEX sometimes carries the rounding mode in a tmp that only becomes a
/// constant later in the decompilation pipeline) is passed through as-is.
fn vex_rm_value(py: Python<'_>, rm: &Py<PyAny>) -> PyResult<Py<PyAny>> {
    if let Some((_, v, _)) = const_int_parts(py, rm) {
        let low2 = match v {
            IntConst::Small(v) => Some((v & 3) as i64),
            IntConst::Big(b) => i64::try_from(b & num_bigint::BigInt::from(3)).ok(),
        };
        if let Some(m) = low2.and_then(RoundingMode::from_int) {
            return m.into_py_any(py);
        }
    }
    Ok(rm.clone_ref(py))
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

unsafe fn const_value(py: Python<'_>, c: *const vex_ffi::IRConst) -> PyResult<ConstVal> {
    use vex_ffi::*;
    let tag = unsafe { (*c).tag };
    let ico = unsafe { &(*c).ico };
    let (value, bits): (Py<PyAny>, u32) = unsafe {
        match tag {
            ICO_U1 => ((ico.u1 as i64).into_py_any(py)?, 1),
            ICO_U8 => ((ico.u8_ as i64).into_py_any(py)?, 8),
            ICO_U16 => ((ico.u16_ as i64).into_py_any(py)?, 16),
            ICO_U32 => ((ico.u32_ as i64).into_py_any(py)?, 32),
            ICO_U64 => (ico.u64_.into_py_any(py)?, 64),
            ICO_F32 | ICO_F32I => ((ico.f32_ as f64).into_py_any(py)?, 32),
            ICO_F64 | ICO_F64I => (ico.f64_.into_py_any(py)?, 64),
            ICO_V128 => (expand_vector(py, ico.v128 as u64, 16)?, 128),
            ICO_V256 => (expand_vector(py, ico.v256 as u64, 32)?, 256),
            _ => (0i64.into_py_any(py)?, 0),
        }
    };
    Ok(ConstVal { value, bits })
}

/// Mirror of pyvex V128/V256 `_from_c`: each set bit `i` in `base` becomes a
/// 0xFF byte at position `i`. Returns a Python int.
fn expand_vector(py: Python<'_>, base: u64, nbytes: usize) -> PyResult<Py<PyAny>> {
    let mut bytes = vec![0u8; nbytes];
    for (i, b) in bytes.iter_mut().enumerate() {
        if (base >> i) & 1 == 1 {
            *b = 0xFF;
        }
    }
    let int_ty = py.import("builtins")?.getattr("int")?;
    let pybytes = PyBytes::new(py, &bytes);
    Ok(int_ty
        .call_method1("from_bytes", (pybytes, "little"))?
        .unbind())
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

    fn expr_kind(&self, py: Python<'_>, e: &Self::E) -> PyResult<ExprKind<Self::E>> {
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
                    op: iex.unop.op,
                    arg: iex.unop.arg,
                },
                IEX_BINOP => ExprKind::Binop {
                    op: iex.binop.op,
                    arg1: iex.binop.arg1,
                    arg2: iex.binop.arg2,
                },
                IEX_TRIOP => {
                    let d = &*iex.triop.details;
                    ExprKind::Triop {
                        op: d.op,
                        args: vec![d.arg1, d.arg2, d.arg3],
                    }
                }
                IEX_CONST => {
                    let cv = const_value(py, iex.con.con)?;
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
        manager: Bound<'_, PyAny>,
        arch: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let native_manager: Option<Py<Manager>> = manager
            .clone()
            .cast_into::<Manager>()
            .ok()
            .map(|b| b.unbind());
        let start_atom = match &native_manager {
            Some(m) => m.borrow(py).atom_ctr,
            None => 0,
        };
        let block_addr = block_addr_override.unwrap_or_else(|| reader.block_addr());

        let mut conv = Conv {
            py,
            reader,
            ail: Ail::new(py)?,
            arch: ArchCtx::new(arch)?,
            atom: start_atom,
            native_manager: native_manager.as_ref().map(|m| m.clone_ref(py)),
            py_manager: manager,
            ins_addr: None,
            block_addr,
            vex_stmt_idx: DEFAULT_STATEMENT,
        };
        let block = conv.convert_block()?;
        let final_atom = conv.atom;
        if let Some(m) = &native_manager {
            m.borrow_mut(py).atom_ctr = final_atom;
        }
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
        manager: Bound<'_, PyAny>,
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
        VEXIRSBConverter::run(py, &reader, Some(addr as i64), manager, arch)
    }

    /// Fallback: convert a cached pyvex Python `IRSB` object.
    #[staticmethod]
    fn convert(
        py: Python<'_>,
        irsb: Bound<'_, PyAny>,
        manager: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        vex_ffi::init_symbols(py);
        let arch = manager.getattr("arch")?;
        if arch.is_none() {
            return Err(PyValueError::new_err(
                "manager.arch must be set for VEX conversion",
            ));
        }
        let tyenv = irsb.getattr("tyenv")?;
        let block_addr: i64 = irsb.getattr("addr")?.extract()?;
        // Keep manager state in sync with the legacy converter.
        manager.setattr("tyenv", &tyenv)?;
        manager.setattr("block_addr", block_addr)?;
        let reader = PyReader {
            irsb: irsb.clone(),
            tyenv,
            statements: irsb.getattr("statements")?.cast_into::<PyList>()?,
        };
        VEXIRSBConverter::run(py, &reader, Some(block_addr), manager, arch)
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
                value: expr.getattr("value")?.unbind(),
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
                op: vexop::op_int_from_name(&expr.getattr("op")?.extract::<String>()?).unwrap_or(0),
                arg: unbind_any(expr.getattr("args")?.get_item(0)?),
            },
            "Binop" => {
                let args = expr.getattr("args")?;
                ExprKind::Binop {
                    op: vexop::op_int_from_name(&expr.getattr("op")?.extract::<String>()?)
                        .unwrap_or(0),
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
                    op: vexop::op_int_from_name(&expr.getattr("op")?.extract::<String>()?)
                        .unwrap_or(0),
                    args: v,
                }
            }
            "Const" => {
                let con = expr.getattr("con")?;
                ExprKind::Const {
                    value: con.getattr("value")?.unbind(),
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
