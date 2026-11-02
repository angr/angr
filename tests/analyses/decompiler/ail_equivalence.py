# pylint:disable=missing-class-docstring,no-self-use
"""Translate AIL expressions into claripy so that rewrites can be proved equivalent with the solver."""

from __future__ import annotations

import archinfo

from angr import claripy
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Extract,
    Insert,
    Load,
    Register,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.engines.vex.claripy.ccall import pc_calculate_rdata_all


def to_claripy(expr):
    if isinstance(expr, Const):
        return claripy.BVV(expr.value_int, expr.bits)
    if isinstance(expr, Register):
        return claripy.BVS(f"r{expr.reg_offset}_{expr.bits}", expr.bits, explicit_name=True)
    if isinstance(expr, VirtualVariable):
        return claripy.BVS(f"vvar{expr.varid}_{expr.bits}", expr.bits, explicit_name=True)
    if isinstance(expr, Load):
        # loads of the same address are the same value
        return claripy.BVS(f"load_{expr.addr}_{expr.bits}", expr.bits, explicit_name=True)
    if isinstance(expr, Convert):
        v = to_claripy(expr.operand)
        if expr.to_bits == expr.from_bits:
            return v
        if expr.to_bits < expr.from_bits:
            return v[expr.to_bits - 1 : 0]
        return (v.sign_extend if expr.is_signed else v.zero_extend)(expr.to_bits - expr.from_bits)
    if isinstance(expr, UnaryOp):
        v = to_claripy(expr.operand)
        return {"BitwiseNeg": lambda: ~v, "Neg": lambda: -v, "Not": lambda: v ^ 1}[expr.op]()
    if isinstance(expr, VEXCCallExpression):
        platform = {"x86g_calculate_eflags_all": "X86", "amd64g_calculate_rflags_all": "AMD64"}[expr.callee]
        op = expr.operands[0].value_int
        return pc_calculate_rdata_all(None, op, *(to_claripy(o) for o in expr.operands[1:]), platform=platform)
    if isinstance(expr, ITE):
        return claripy.If(to_claripy(expr.cond) == 1, to_claripy(expr.iftrue), to_claripy(expr.iffalse))
    if isinstance(expr, Insert):
        base, value = to_claripy(expr.base), to_claripy(expr.value)
        off = expr.offset.value_int * 8
        if expr.endness != archinfo.Endness.LE:
            off = expr.bits - off - expr.value.bits
        parts = []
        if off + expr.value.bits < expr.bits:
            parts.append(base[expr.bits - 1 : off + expr.value.bits])
        parts.append(value)
        if off:
            parts.append(base[off - 1 : 0])
        return claripy.Concat(*parts) if len(parts) > 1 else parts[0]
    if isinstance(expr, Extract):
        base = to_claripy(expr.base)
        off = expr.offset.value_int * 8
        if expr.endness != archinfo.Endness.LE:
            off = expr.base.bits - off - expr.bits
        return base[off + expr.bits - 1 : off]
    if isinstance(expr, Call) and isinstance(expr.target, str) and expr.target.startswith("__builtin_bswap"):
        return claripy.Reverse(to_claripy(expr.args[0]))
    if isinstance(expr, BinaryOp):
        a, b = to_claripy(expr.operands[0]), to_claripy(expr.operands[1])
        if expr.op == "Concat":
            return claripy.Concat(a, b)
        if expr.op in ("Shl", "Shr", "Sar", "Rol", "Ror"):
            b = b.zero_extend(a.size() - b.size()) if b.size() < a.size() else b[a.size() - 1 : 0]
            return {
                "Shl": lambda: a << b,
                "Shr": lambda: claripy.LShR(a, b),
                "Sar": lambda: a >> b,
                "Rol": lambda: claripy.RotateLeft(a, b),
                "Ror": lambda: claripy.RotateRight(a, b),
            }[expr.op]()
        if expr.op.startswith("Cmp"):
            signed = expr.signed
            hit = {
                "CmpEQ": lambda: a == b,
                "CmpNE": lambda: a != b,
                "CmpLT": lambda: claripy.SLT(a, b) if signed else claripy.ULT(a, b),
                "CmpLE": lambda: claripy.SLE(a, b) if signed else claripy.ULE(a, b),
                "CmpGT": lambda: claripy.SGT(a, b) if signed else claripy.UGT(a, b),
                "CmpGE": lambda: claripy.SGE(a, b) if signed else claripy.UGE(a, b),
            }[expr.op]()
            return claripy.If(hit, claripy.BVV(1, 1), claripy.BVV(0, 1))
        return {
            "And": lambda: a & b,
            "Or": lambda: a | b,
            "Xor": lambda: a ^ b,
            "Add": lambda: a + b,
            "Sub": lambda: a - b,
            "Mul": lambda: a * b,
        }[expr.op]()
    raise NotImplementedError(type(expr))


def equivalent(a, b) -> bool:
    """Whether two expressions (AIL or claripy) agree on every input."""
    ca = a if isinstance(a, claripy.ast.Base) else to_claripy(a)
    cb = b if isinstance(b, claripy.ast.Base) else to_claripy(b)
    if ca.size() != cb.size():
        return False
    return not claripy.Solver().satisfiable(extra_constraints=[ca != cb])
