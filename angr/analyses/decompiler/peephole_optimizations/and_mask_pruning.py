from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Call, Const, Convert, DirtyExpression, Expression, UnaryOp

from .base import PeepholeOptimizationExprBase

_MAX_DEPTH = 8
# purity is a cheap scan, and an expanded flags word is deeper than the support walk needs to go
_MAX_PURITY_DEPTH = 64


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
        if expr.op == "Mul":
            shift = _pow2_operand(expr)
            if shift is not None:
                return (bit_support(shift[0], depth + 1) << shift[1]) & full
        if expr.op == "Add":
            s0, s1 = bit_support(op0, depth + 1), bit_support(op1, depth + 1)
            if s0 & s1 == 0:
                # no carries between disjoint supports
                return (s0 | s1) & full
    if isinstance(expr, ITE):
        return (bit_support(expr.iftrue, depth + 1) | bit_support(expr.iffalse, depth + 1)) & full
    return full


def _pow2_operand(expr: BinaryOp) -> tuple[Expression, int] | None:
    """For a Mul by a constant power of two, return (other operand, log2 of the constant)."""
    for const, other in ((expr.operands[1], expr.operands[0]), (expr.operands[0], expr.operands[1])):
        if isinstance(const, Const) and isinstance(const.value, int) and const.value_int > 0:
            value = const.value_int
            if value & (value - 1) == 0 and other.bits == expr.bits:
                return other, value.bit_length() - 1
    return None


def _bool_times_const(expr: Expression) -> tuple[Expression, int] | None:
    """For ``Conv(1->n, c) * K`` (either order), return (c, K)."""
    if not isinstance(expr, BinaryOp) or expr.op != "Mul":
        return None
    for const, other in ((expr.operands[1], expr.operands[0]), (expr.operands[0], expr.operands[1])):
        if (
            isinstance(const, Const)
            and isinstance(const.value, int)
            and isinstance(other, Convert)
            and other.from_bits == 1
            and other.to_bits == expr.bits
            and not other.is_signed
            and other.from_type == Convert.TYPE_INT
            and other.to_type == Convert.TYPE_INT
        ):
            return other.operand, const.value_int
    return None


def _is_pure(expr: Expression, depth: int = 0) -> bool:
    """Whether dropping ``expr`` entirely is observationally silent."""
    if depth > _MAX_PURITY_DEPTH:
        return False
    if isinstance(expr, (Call, DirtyExpression)):
        return False
    return all(_is_pure(operand, depth + 1) for operand in getattr(expr, "operands", None) or ())


class AndMaskPruning(PeepholeOptimizationExprBase):
    """
    Push a constant And-mask into the expression it masks:

    - ``And(And(x, D), C)`` => ``And(x, C & D)``
    - ``And(Or(a, b), C)``  => ``And(b, C)`` when no bit of ``a`` can survive ``C``
    - ``And(~X, C)``: the same pruning under a complement -- ``C & ~(a | b)`` is ``C & ~b`` when no bit of ``a``
      can survive ``C``, ``C & ~(x & D)`` is ``C & ~x`` when ``C`` is inside ``D``, and ``C & ~(bool * D)`` is
      ``!bool * C`` when ``C`` is inside ``D``

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

        if isinstance(inner, UnaryOp) and inner.op == "BitwiseNeg" and inner.bits == expr.bits:
            return self._optimize_complement(expr, inner.operand, mask)

        pruned = self._prune(inner, mask)
        if pruned is None:
            return None
        return BinaryOp(
            expr.idx, "And", [pruned, Const(self.manager.next_atom(), mask, expr.bits)], expr.signed, **expr.tags
        )

    def _optimize_complement(self, expr: BinaryOp, negated: Expression, mask: int) -> Expression | None:
        """``And(~negated, mask)``."""
        pruned = self._prune_complement(negated, mask)
        if pruned is not None and isinstance(pruned, Const):
            # nothing of negated survives the mask
            return Const(expr.idx, mask, expr.bits, **expr.tags)
        target = negated if pruned is None else pruned
        split = _bool_times_const(target)
        if split is not None and mask & ~split[1] == 0:
            # mask & ~(bool * D) with mask inside D: the mask bits are exactly where bool is 0
            cond, _ = split
            if isinstance(cond, UnaryOp) and cond.op == "Not":
                # !!y is y only for a 1-bit y; a wider y tests as y != 0
                inner = cond.operand
                negated_cond = (
                    inner
                    if inner.bits == 1
                    else BinaryOp(
                        self.manager.next_atom(),
                        "CmpNE",
                        [inner, Const(self.manager.next_atom(), 0, inner.bits)],
                        False,
                        bits=1,
                    )
                )
            else:
                negated_cond = UnaryOp(self.manager.next_atom(), "Not", cond, bits=1)
            return BinaryOp(
                expr.idx,
                "Mul",
                [
                    Convert(self.manager.next_atom(), 1, expr.bits, False, negated_cond),
                    Const(self.manager.next_atom(), mask, expr.bits),
                ],
                False,
                bits=expr.bits,
                **expr.tags,
            )
        if pruned is None:
            return None
        return BinaryOp(
            expr.idx,
            "And",
            [
                UnaryOp(self.manager.next_atom(), "BitwiseNeg", pruned, bits=expr.bits),
                Const(self.manager.next_atom(), mask, expr.bits),
            ],
            expr.signed,
            **expr.tags,
        )

    def _prune_complement(self, expr: Expression, mask: int, depth: int = 0) -> Expression | None:
        """
        Rebuild ``expr`` so that ``mask & ~expr`` is unchanged but the parts the mask cannot see are gone. None
        means unchanged; a Const 0 means nothing of ``expr`` reaches the mask.
        """
        if depth > _MAX_DEPTH:
            return None
        if bit_support(expr) & mask == 0 and _is_pure(expr):
            return Const(self.manager.next_atom(), 0, expr.bits)
        if not isinstance(expr, BinaryOp):
            return None
        if expr.op in {"Or", "Xor"}:
            # a term with no bit under the mask contributes nothing to either an or or an xor there
            op0, op1 = expr.operands
            new0 = self._prune_complement(op0, mask, depth + 1)
            new1 = self._prune_complement(op1, mask, depth + 1)
            if isinstance(new0, Const) and new0.value_int == 0:
                return new1 if new1 is not None else op1
            if isinstance(new1, Const) and new1.value_int == 0:
                return new0 if new0 is not None else op0
            if new0 is None and new1 is None:
                return None
            return BinaryOp(expr.idx, expr.op, [new0 or op0, new1 or op1], expr.signed, **expr.tags)
        split = _const_operand(expr)
        if split is not None:
            base, inner_mask = split
            if mask & ~inner_mask == 0:
                # mask & ~(x & D) with mask inside D is mask & ~x
                return self._prune_complement(base, mask, depth + 1) or base
        return None

    def _prune(self, expr: Expression, mask: int, depth: int = 0) -> Expression | None:
        """Rebuild ``expr`` without the parts the mask discards. None means unchanged."""
        if depth > _MAX_DEPTH or not isinstance(expr, BinaryOp):
            return None
        if expr.op in {"Or", "Xor"}:
            op0, op1 = expr.operands
            if bit_support(op0) & mask == 0 and _is_pure(op0):
                return self._prune(op1, mask, depth + 1) or op1
            if bit_support(op1) & mask == 0 and _is_pure(op1):
                return self._prune(op0, mask, depth + 1) or op0
            new0 = self._prune(op0, mask, depth + 1)
            new1 = self._prune(op1, mask, depth + 1)
            if new0 is None and new1 is None:
                return None
            return BinaryOp(expr.idx, expr.op, [new0 or op0, new1 or op1], expr.signed, **expr.tags)
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
