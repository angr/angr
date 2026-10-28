from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, Extract, Load, UnaryOp

from .and_mask_pruning import _pow2_operand, bit_support
from .base import PeepholeOptimizationExprBase
from .constant_derefs import ReadOnlyConstantDereferences


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def _signed(value: int, bits: int) -> int:
    value &= _mask(bits)
    return value - (1 << bits) if value >> (bits - 1) else value


def _is_bool_conv(expr: Expression) -> bool:
    return (
        isinstance(expr, Convert)
        and expr.from_bits == 1
        and not expr.is_signed
        and expr.from_type == Convert.TYPE_INT
        and expr.to_type == Convert.TYPE_INT
    )


def _const_ite(expr: Expression) -> tuple[Expression, int, int] | None:
    """For an ITE whose arms are both integer constants, return (cond, iftrue, iffalse)."""
    if (
        isinstance(expr, ITE)
        and isinstance(expr.iftrue, Const)
        and isinstance(expr.iffalse, Const)
        and isinstance(expr.iftrue.value, int)
        and isinstance(expr.iffalse.value, int)
    ):
        return expr.cond, expr.iftrue.value_int, expr.iffalse.value_int
    return None


def _eval_binop(op: str, a: int, b: int, bits: int, signed: bool) -> tuple[int, int] | None:
    """Evaluate a non-float binary operator on two constants; return (value, result bits)."""
    m = _mask(bits)
    a &= m
    b &= m
    if op == "Add":
        return (a + b) & m, bits
    if op == "Sub":
        return (a - b) & m, bits
    if op == "Mul":
        return (a * b) & m, bits
    if op == "And":
        return a & b, bits
    if op == "Or":
        return a | b, bits
    if op == "Xor":
        return a ^ b, bits
    if op == "Shl":
        return (a << b) & m if b < bits else 0, bits
    if op == "Shr":
        return (a >> b) if b < bits else 0, bits
    if op == "Sar":
        sa = _signed(a, bits)
        return (sa >> min(b, bits - 1)) & m, bits
    if op in {"Rol", "Ror"}:
        b %= bits
        if op == "Ror":
            b = (bits - b) % bits
        return ((a << b) | (a >> (bits - b))) & m, bits
    if op in {"CmpEQ", "CmpNE"}:
        return int((a == b) == (op == "CmpEQ")), 1
    if op in {"CmpLT", "CmpLE", "CmpGT", "CmpGE"}:
        x, y = (_signed(a, bits), _signed(b, bits)) if signed else (a, b)
        result = {"CmpLT": x < y, "CmpLE": x <= y, "CmpGT": x > y, "CmpGE": x >= y}[op]
        return int(result), 1
    return None


class DisjointAddToOr(PeepholeOptimizationExprBase):
    """
    ``a + b`` => ``a | b`` when no bit can be set in both ``a`` and ``b``: there is nothing to carry.
    A flag-merging VM adds the two masked halves of a flags word together.
    """

    __slots__ = ()

    NAME = "a + b => a | b for disjoint bit supports"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op != "Add" or expr.floating_point:
            return None
        op0, op1 = expr.operands
        if op0.bits != expr.bits or op1.bits != expr.bits:
            return None
        if isinstance(op0, Const) or isinstance(op1, Const):
            # keep `x + C` as it is; a constant displacement reads better than a bitwise or
            return None
        if bit_support(op0) & bit_support(op1) != 0:
            return None
        return BinaryOp(expr.idx, "Or", [op0, op1], expr.signed, bits=expr.bits, **expr.tags)


class MulPow2ShrCancel(PeepholeOptimizationExprBase):
    """
    ``(x * 2**k) >> k`` => ``x`` when the multiplication cannot shift a set bit of ``x`` out of the word.
    """

    __slots__ = ()

    NAME = "(x * 2**k) >> k => x"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op != "Shr" or expr.floating_point:
            return None
        inner, amount = expr.operands
        if not (isinstance(amount, Const) and isinstance(amount.value, int)):
            return None
        if not (isinstance(inner, BinaryOp) and inner.op == "Mul" and inner.bits == expr.bits):
            return None
        split = _pow2_operand(inner)
        if split is None or split[1] != amount.value_int:
            return None
        base, k = split
        if bit_support(base) >> (expr.bits - k) != 0:
            return None
        return base


class BoolPlusConstToITE(PeepholeOptimizationExprBase):
    """
    ``Conv(1->n, c) + K`` => ``c ? K + 1 : K``. The devirtualized select idiom builds its all-ones-or-zero mask
    as ``(flag >> 6) - 1``; as an ITE the mask folds through the constant arithmetic that uses it.
    """

    __slots__ = ()

    NAME = "bool + K => c ? K + 1 : K"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if expr.op != "Add" or expr.floating_point:
            return None
        for conv, const in (expr.operands, expr.operands[::-1]):
            if (
                _is_bool_conv(conv)
                and conv.to_bits == expr.bits
                and isinstance(const, Const)
                and isinstance(const.value, int)
            ):
                k = const.value_int & _mask(expr.bits)
                return ITE(
                    expr.idx,
                    conv.operand,
                    Const(self.manager.next_atom(), (k + 1) & _mask(expr.bits), expr.bits),
                    Const(self.manager.next_atom(), k, expr.bits),
                    **expr.tags,
                )
        return None


class ITEConstArms(PeepholeOptimizationExprBase):
    """
    Fold pure operations over an ITE whose arms are constants into the arms:

    - ``op(c ? a : b, K)`` and ``op(K, c ? a : b)`` for a constant ``K``
    - ``op(c ? a : b, c ? a' : b')`` over the same condition
    - ``~``, ``-``, conversions and extractions of ``c ? a : b``
    - ``*(c ? A : B)`` when both addresses read from read-only memory
    - ``c ? 1 : 0`` is ``c`` and ``c ? 0 : 1`` is ``!c`` (1-bit)

    The result is again an ITE of two constants, so a whole constant computation over a selected value
    collapses to a selection between its two outcomes.
    """

    __slots__ = ()

    NAME = "fold constant computation through c ? a : b"
    expr_classes = (BinaryOp, UnaryOp, Convert, Extract, Load, ITE)

    def optimize(self, expr: Expression, **kwargs):
        if isinstance(expr, ITE):
            return self._optimize_ite(expr)
        if isinstance(expr, BinaryOp):
            return self._optimize_binop(expr)
        if isinstance(expr, UnaryOp):
            return self._optimize_unop(expr)
        if isinstance(expr, Convert):
            return self._optimize_convert(expr)
        if isinstance(expr, Extract):
            return self._optimize_extract(expr)
        if isinstance(expr, Load):
            return self._optimize_load(expr)
        return None

    def _ite(self, expr: Expression, cond: Expression, iftrue: int, iffalse: int, bits: int) -> Expression:
        return ITE(
            expr.idx,
            cond,
            Const(self.manager.next_atom(), iftrue & _mask(bits), bits),
            Const(self.manager.next_atom(), iffalse & _mask(bits), bits),
            **expr.tags,
        )

    @staticmethod
    def _optimize_ite(expr: ITE):
        split = _const_ite(expr)
        if split is None or expr.bits != 1 or expr.cond.bits != 1:
            return None
        cond, iftrue, iffalse = split
        if (iftrue, iffalse) == (1, 0):
            return cond
        if (iftrue, iffalse) == (0, 1):
            return UnaryOp(expr.idx, "Not", cond, bits=1, **expr.tags)
        return None

    def _optimize_binop(self, expr: BinaryOp):
        if expr.floating_point:
            return None
        op0, op1 = expr.operands
        s0, s1 = _const_ite(op0), _const_ite(op1)
        if s0 is not None and s1 is not None:
            if not s0[0].likes(s1[0]) or op0.bits != op1.bits:
                return None
            cond, a, b = s0
            r_true = _eval_binop(expr.op, a, s1[1], op0.bits, expr.signed)
            r_false = _eval_binop(expr.op, b, s1[2], op0.bits, expr.signed)
        elif s0 is not None and isinstance(op1, Const) and isinstance(op1.value, int):
            cond, a, b = s0
            r_true = _eval_binop(expr.op, a, op1.value_int, op0.bits, expr.signed)
            r_false = _eval_binop(expr.op, b, op1.value_int, op0.bits, expr.signed)
        elif s1 is not None and isinstance(op0, Const) and isinstance(op0.value, int):
            cond, a, b = s1
            r_true = _eval_binop(expr.op, op0.value_int, a, op1.bits, expr.signed)
            r_false = _eval_binop(expr.op, op0.value_int, b, op1.bits, expr.signed)
        else:
            return None
        if r_true is None or r_false is None or r_true[1] != expr.bits:
            return None
        return self._ite(expr, cond, r_true[0], r_false[0], expr.bits)

    def _optimize_unop(self, expr: UnaryOp):
        split = _const_ite(expr.operand)
        if split is None or expr.operand.bits != expr.bits:
            return None
        cond, a, b = split
        if expr.op == "BitwiseNeg":
            return self._ite(expr, cond, ~a, ~b, expr.bits)
        if expr.op == "Neg":
            return self._ite(expr, cond, -a, -b, expr.bits)
        if expr.op == "Not" and expr.bits == 1:
            return self._ite(expr, cond, int(not a), int(not b), 1)
        return None

    def _optimize_convert(self, expr: Convert):
        split = _const_ite(expr.operand)
        if split is None or expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
            return None
        cond, a, b = split
        if expr.is_signed and expr.to_bits > expr.from_bits:
            a, b = _signed(a, expr.from_bits), _signed(b, expr.from_bits)
        return self._ite(expr, cond, a, b, expr.to_bits)

    def _optimize_extract(self, expr: Extract):
        split = _const_ite(expr.base)
        if split is None or not (isinstance(expr.offset, Const) and isinstance(expr.offset.value, int)):
            return None
        cond, a, b = split
        shift = expr.offset.value_int
        return self._ite(expr, cond, a >> shift, b >> shift, expr.bits)

    def _optimize_load(self, expr: Load):
        split = _const_ite(expr.addr)
        if split is None or expr.guard is not None:
            return None
        cond, a, b = split
        deref = ReadOnlyConstantDereferences(self.project, self.kb, self.manager, self.func_addr)
        arms = []
        for addr in (a, b):
            load = Load(
                self.manager.next_atom(), Const(self.manager.next_atom(), addr, expr.addr.bits), expr.size, expr.endness
            )
            value = deref.optimize(load)
            if not (isinstance(value, Const) and isinstance(value.value, int)):
                return None
            arms.append(value.value_int)
        return self._ite(expr, cond, arms[0], arms[1], expr.bits)
