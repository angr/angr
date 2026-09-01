from __future__ import annotations

from angr.ailment.expression import BinaryOp, Call, Const, Convert, DirtyExpression, Expression

from .base import PeepholeOptimizationExprBase

_MAX_DEPTH = 8


def _const_operand(expr: Expression) -> tuple[Expression, int] | None:
    """For an And with one constant operand, return (other operand, constant)."""
    if not isinstance(expr, BinaryOp) or expr.op != "And":
        return None
    op0, op1 = expr.operands
    if isinstance(op1, Const) and isinstance(op1.value, int):
        return op0, op1.value_int
    if isinstance(op0, Const) and isinstance(op0.value, int):
        return op1, op0.value_int
    return None


def bit_support(expr: Expression, depth: int = 0) -> int:
    """
    Over-approximate the set of bits of ``expr`` that can be 1.
    """
    full = (1 << expr.bits) - 1
    if depth > _MAX_DEPTH:
        return full
    if isinstance(expr, Const):
        return expr.value_int & full if isinstance(expr.value, int) else full
    if isinstance(expr, Convert):
        if expr.is_signed and expr.to_bits > expr.from_bits:
            return full
        return bit_support(expr.operand, depth + 1) & full
    if isinstance(expr, BinaryOp):
        op0, op1 = expr.operands
        if expr.op == "And":
            return bit_support(op0, depth + 1) & bit_support(op1, depth + 1) & full
        if expr.op in {"Or", "Xor"}:
            return (bit_support(op0, depth + 1) | bit_support(op1, depth + 1)) & full
        if expr.op in {"Shl", "Shr"} and isinstance(op1, Const) and isinstance(op1.value, int):
            amount = op1.value_int
            if amount >= expr.bits:
                # out-of-range shift counts are architecture-dependent; claim nothing
                return full
            base = bit_support(op0, depth + 1)
            return ((base << amount) if expr.op == "Shl" else (base >> amount)) & full
    return full


def _is_pure(expr: Expression, depth: int = 0) -> bool:
    """Whether dropping ``expr`` entirely is observationally silent."""
    if depth > _MAX_DEPTH:
        return False
    if isinstance(expr, (Call, DirtyExpression)):
        return False
    return all(_is_pure(operand, depth + 1) for operand in getattr(expr, "operands", None) or ())


class AndMaskPruning(PeepholeOptimizationExprBase):
    """
    Push a constant And-mask into the expression it masks:

    - ``And(And(x, D), C)`` => ``And(x, C & D)``
    - ``And(Or(a, b), C)``  => ``And(b, C)`` when no bit of ``a`` can survive ``C``

    Packed flag words -- what ``amd64g_calculate_rflags_all`` returns, and the flag-merging idiom
    obfuscators build on top of it -- are disjunctions of individually positioned bits, so a
    single-flag test collapses down to just the flag it reads.
    """

    __slots__ = ()

    NAME = "Push constant And-masks into Or trees"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        split = _const_operand(expr)
        if split is None:
            return None
        inner, mask = split
        mask &= (1 << expr.bits) - 1

        # And(And(x, D), C) => And(x, C & D)
        inner_split = _const_operand(inner)
        if inner_split is not None and inner.bits == expr.bits:
            base, inner_mask = inner_split
            return BinaryOp(
                expr.idx,
                "And",
                [base, Const(self.manager.next_atom(), mask & inner_mask, expr.bits)],
                expr.signed,
                **expr.tags,
            )

        pruned = self._prune(inner, mask)
        if pruned is None:
            return None
        return BinaryOp(
            expr.idx, "And", [pruned, Const(self.manager.next_atom(), mask, expr.bits)], expr.signed, **expr.tags
        )

    def _prune(self, expr: Expression, mask: int, depth: int = 0) -> Expression | None:
        """Rebuild ``expr`` without the parts the mask discards. None means unchanged."""
        if depth > _MAX_DEPTH or not isinstance(expr, BinaryOp):
            return None
        if expr.op == "Or":
            op0, op1 = expr.operands
            if bit_support(op0) & mask == 0 and _is_pure(op0):
                return self._prune(op1, mask, depth + 1) or op1
            if bit_support(op1) & mask == 0 and _is_pure(op1):
                return self._prune(op0, mask, depth + 1) or op0
            new0 = self._prune(op0, mask, depth + 1)
            new1 = self._prune(op1, mask, depth + 1)
            if new0 is None and new1 is None:
                return None
            return BinaryOp(expr.idx, "Or", [new0 or op0, new1 or op1], expr.signed, **expr.tags)
        split = _const_operand(expr)
        if split is not None:
            # under an outer mask, And(x, D) only has to be right on the bits of mask & D
            base, inner_mask = split
            new_base = self._prune(base, mask & inner_mask, depth + 1)
            if new_base is None:
                return None
            return BinaryOp(
                expr.idx,
                "And",
                [new_base, Const(self.manager.next_atom(), inner_mask, expr.bits)],
                expr.signed,
                **expr.tags,
            )
        return None
