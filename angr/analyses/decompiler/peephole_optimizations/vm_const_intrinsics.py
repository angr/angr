from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Call, Const, UnaryOp

from .base import PeepholeOptimizationExprBase

_BSWAPS = {"__builtin_bswap16": 16, "__builtin_bswap32": 32, "__builtin_bswap64": 64}


def _bswap(value: int, bits: int) -> int:
    return int.from_bytes((value & ((1 << bits) - 1)).to_bytes(bits // 8, "little"), "big")


class ConstBswap(PeepholeOptimizationExprBase):
    """
    ``__builtin_bswapN(C)`` ==> the swapped constant, and ``__builtin_bswapN(c ? A : B)`` ==> ``c ? bswap(A) :
    bswap(B)``. Bswap recognizes the byte shuffle before the VM's key arithmetic around it has become constant.
    """

    __slots__ = ()

    NAME = "bswap of a constant"
    expr_classes = (Call,)

    def optimize(self, expr: Call, **kwargs):
        bits = _BSWAPS.get(expr.target) if isinstance(expr.target, str) else None
        if bits is None or expr.bits != bits or not expr.args or len(expr.args) != 1:
            return None
        arg = expr.args[0]
        if arg.bits != bits:
            return None
        if isinstance(arg, Const) and isinstance(arg.value, int):
            return Const(expr.idx, _bswap(arg.value_int, bits), bits, **expr.tags)
        if (
            isinstance(arg, ITE)
            and isinstance(arg.iftrue, Const)
            and isinstance(arg.iffalse, Const)
            and isinstance(arg.iftrue.value, int)
            and isinstance(arg.iffalse.value, int)
        ):
            return ITE(
                expr.idx,
                arg.cond,
                Const(self.manager.next_atom(), _bswap(arg.iftrue.value_int, bits), bits),
                Const(self.manager.next_atom(), _bswap(arg.iffalse.value_int, bits), bits),
                **expr.tags,
            )
        return None


class ConstRotate(PeepholeOptimizationExprBase):
    """
    ``C1 rol C2`` / ``C1 ror C2`` ==> the rotated constant (the count is taken modulo the width).
    """

    __slots__ = ()

    NAME = "rotate of constants"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op not in {"Rol", "Ror"}:
            return None
        a, b = expr.operands
        if not (isinstance(a, Const) and isinstance(b, Const)):
            return None
        if not (isinstance(a.value, int) and isinstance(b.value, int)):
            return None
        bits = expr.bits
        mask = (1 << bits) - 1
        n = b.value_int % bits
        if expr.op == "Ror":
            n = (bits - n) % bits
        v = a.value_int & mask
        return Const(expr.idx, ((v << n) | (v >> (bits - n))) & mask, bits, **expr.tags)


class ExpCmpNEToCmpNE(PeepholeOptimizationExprBase):
    """
    ``ExpCmpNE(a, b)`` ==> ``a != b``. VEX's ExpCmpNE only asks memcheck for an exact definedness check; its value is
    CmpNE's.
    """

    __slots__ = ()

    NAME = "ExpCmpNE => CmpNE"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op != "ExpCmpNE":
            return None
        return BinaryOp(expr.idx, "CmpNE", list(expr.operands), expr.signed, bits=expr.bits, **expr.tags)


class ConstBitwiseNeg(PeepholeOptimizationExprBase):
    """
    ``~C`` ==> the complemented constant.
    """

    __slots__ = ()

    NAME = "~C => constant"
    expr_classes = (UnaryOp,)

    def optimize(self, expr: UnaryOp, **kwargs):
        if expr.op != "BitwiseNeg" or not (isinstance(expr.operand, Const) and isinstance(expr.operand.value, int)):
            return None
        if expr.operand.bits != expr.bits:
            return None
        return Const(expr.idx, ~expr.operand.value_int & ((1 << expr.bits) - 1), expr.bits, **expr.tags)
