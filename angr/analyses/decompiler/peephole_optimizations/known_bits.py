from __future__ import annotations

from collections.abc import Callable

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Insert,
    UnaryOp,
    VEXCCallExpression,
    VirtualVariable,
)
from angr.analyses.decompiler.ccall_rewriters.flags_word import flag_bits, flags_word_ccall, flags_word_support
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase
from .masked_insert import _insert_shift

_MAX_DEPTH = 24

KnownBits = tuple[int, int]
Resolver = Callable[[VirtualVariable, int], KnownBits]


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def known_bits(expr: Expression, resolve: Resolver | None = None, depth: int = 0) -> KnownBits:
    """
    (known zeros, known ones) of ``expr``: bits that are 0, resp. 1, whatever the free variables hold. ``resolve`` maps
    a virtual variable to the known bits of its (single) definition.
    """
    full = _mask(expr.bits)
    if depth > _MAX_DEPTH:
        return 0, 0
    if isinstance(expr, Const):
        if not isinstance(expr.value, int):
            return 0, 0
        c = expr.value_int & full
        return full & ~c, c
    if isinstance(expr, VirtualVariable):
        return resolve(expr, depth + 1) if resolve is not None else (0, 0)
    if isinstance(expr, Convert):
        if expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return 0, 0
        z, o = known_bits(expr.operand, resolve, depth + 1)
        if expr.to_bits <= expr.from_bits:
            return z & full, o & full
        low = _mask(expr.from_bits)
        z, o = z & low, o & low
        high = full & ~low
        if not expr.is_signed:
            return z | high, o
        sign = 1 << (expr.from_bits - 1)
        if z & sign:
            return z | high, o
        if o & sign:
            return z, o | high
        return z, o
    if isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" and expr.operand.bits == expr.bits:
        z, o = known_bits(expr.operand, resolve, depth + 1)
        return o, z
    if isinstance(expr, VEXCCallExpression):
        split = flags_word_ccall(expr)
        if split is None:
            return 0, 0
        support = flags_word_support(*split)
        if support is None:
            # COPY: the stored flags, masked to the modelled ones
            z, o = known_bits(expr.operands[1], resolve, depth + 1)
            support = flag_bits(split[0])
            return (z | ~support) & full, o & support
        return full & ~support, 0
    if isinstance(expr, ITE):
        z0, o0 = known_bits(expr.iftrue, resolve, depth + 1)
        z1, o1 = known_bits(expr.iffalse, resolve, depth + 1)
        return z0 & z1, o0 & o1
    if isinstance(expr, Insert):
        shift = _insert_shift(expr)
        if shift is None:
            return 0, 0
        hole = _mask(expr.value.bits) << shift
        zb, ob = known_bits(expr.base, resolve, depth + 1)
        zv, ov = known_bits(expr.value, resolve, depth + 1)
        return (zb & ~hole) | (zv << shift), (ob & ~hole) | (ov << shift)
    if isinstance(expr, BinaryOp) and not expr.floating_point and not expr.vector_count:
        op0, op1 = expr.operands
        if expr.op == "Concat":
            z0, o0 = known_bits(op0, resolve, depth + 1)
            z1, o1 = known_bits(op1, resolve, depth + 1)
            return (z0 << op1.bits) | z1, (o0 << op1.bits) | o1
        if op0.bits != expr.bits:
            return 0, 0
        if expr.op in {"And", "Or", "Xor", "Add"} and op1.bits == expr.bits:
            z0, o0 = known_bits(op0, resolve, depth + 1)
            z1, o1 = known_bits(op1, resolve, depth + 1)
            if expr.op == "And":
                return z0 | z1, o0 & o1
            if expr.op == "Or":
                return z0 & z1, o0 | o1
            if expr.op == "Add":
                if (z0 | z1) & full != full:
                    # a carry may come out of some bit position
                    return 0, 0
                # no bit is set in both operands: nothing carries, the sum is the disjunction
                return z0 & z1, o0 | o1
            k = (z0 | o0) & (z1 | o1)
            return k & ~(o0 ^ o1), k & (o0 ^ o1)
        if expr.op in {"Shl", "Shr", "Mul"}:
            amount = op1.value_int if isinstance(op1, Const) and isinstance(op1.value, int) else None
            if expr.op == "Mul":
                if amount is None or amount <= 0 or amount & (amount - 1):
                    return 0, 0
                amount = amount.bit_length() - 1
            if amount is None or amount >= expr.bits:
                return 0, 0
            z, o = known_bits(op0, resolve, depth + 1)
            if expr.op == "Shr":
                return (z >> amount) | (full & ~(full >> amount)), o >> amount
            return ((z << amount) | _mask(amount)) & full, (o << amount) & full
    return 0, 0


def block_defs_resolver(block_defs: BlockDefs | None) -> Resolver | None:
    """Known bits of a vvar from its definition: block-local ones first, then the whole graph's."""
    if block_defs is None:
        return None
    graph = block_defs.all_defs
    memo: dict[int, KnownBits] = graph.known_bits_memo if graph is not None else {}
    busy: set[int] = set()

    def resolve(vvar: VirtualVariable, depth: int) -> KnownBits:
        varid = vvar.varid
        if varid in memo:
            return memo[varid]
        if varid in busy:
            return 0, 0
        src = block_defs.vvars.get(varid)
        if src is None and graph is not None:
            src = graph.value_def(varid)
        if src is None or src.bits != vvar.bits:
            return 0, 0
        busy.add(varid)
        try:
            r = known_bits(src, resolve, depth)
        finally:
            busy.discard(varid)
        if depth <= 1:
            # only results reached without hitting the depth cap on the way are complete
            memo[varid] = r
        return r

    return resolve


class KnownBitsAndMask(PeepholeOptimizationExprBase):
    """
    ``x & C`` ==> the constant it always is, when every bit of ``C`` is known in ``x`` -- seeing through the
    definitions of virtual variables. A devirtualized VM tests flags of a packed flags word it built itself, e.g. the
    overflow bit of a word whose overflow position is a constant 0.
    """

    __slots__ = ()

    NAME = "x & C => constant for known bits"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs: BlockDefs | None = None, **kwargs):
        if expr.op != "And" or expr.floating_point or expr.vector_count:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const) and not isinstance(op1, Const):
            op0, op1 = op1, op0
        if not (isinstance(op1, Const) and isinstance(op1.value, int)) or op0.bits != expr.bits:
            return None
        mask = op1.value_int & _mask(expr.bits)
        z, o = known_bits(op0, block_defs_resolver(block_defs))
        if (z | o) & mask != mask:
            return None
        return Const(expr.idx, o & mask, expr.bits, **expr.tags)
