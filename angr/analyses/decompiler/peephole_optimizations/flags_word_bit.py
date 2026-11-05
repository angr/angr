from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp, VirtualVariable

from .base import PeepholeOptimizationExprBase
from .bool_scaled_mask import _int_const, _log2, scaled_bool
from .known_bits import block_defs_resolver, known_bits
from .masked_bool_or import _or_terms


class FlagsWordBitThroughVVar(PeepholeOptimizationExprBase):
    """
    ``v & (1 << k)`` ==> ``zext(b) << k`` when ``v`` is (the complement of) a variable defined as a flags word spelled
    out flag by flag, ``... | zext(b) << k | ...``, and every other term has bit ``k`` known zero. Only the boolean of
    bit ``k`` is copied to the test, so this works where inlining the whole (deep) word is refused, e.g. a
    devirtualized VM's loop condition ``(~flags & 1) != 0`` with ``flags = ~(cf | pf << 2 | ...)``.
    """

    __slots__ = ()

    NAME = "v & (1 << k) => the flag bit k of v's flags-word definition"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, *, block_defs=None, **kwargs):
        if expr.op != "And" or expr.floating_point or block_defs is None or block_defs.all_defs is None:
            return None
        op0, op1 = expr.operands
        if isinstance(op0, Const):
            op0, op1 = op1, op0
        k = _log2(_int_const(op1))
        if k is None or op0.bits != expr.bits or k >= expr.bits:
            return None

        # follow complements and (location-independent) definitions down to the word
        defs = block_defs.all_defs
        word = op0
        negated = False
        hops = 0
        seen: set[int] = set()
        while True:
            if isinstance(word, UnaryOp) and word.op == "BitwiseNeg" and word.operand.bits == word.bits:
                negated = not negated
                word = word.operand
                continue
            if isinstance(word, VirtualVariable) and word.varid not in seen:
                seen.add(word.varid)
                src = defs.get(word.varid)
                if src is None or src.bits != word.bits:
                    return None
                word = src
                hops += 1
                continue
            break
        if hops == 0:
            # an inline word is left to the other flag peepholes
            return None

        terms = _or_terms(word)
        if len(terms) < 2:
            return None
        resolver = None
        bit: tuple[Expression, bool] | None = None
        for term in terms:
            sb = scaled_bool(term)
            if sb is not None and sb[1] == k and sb[0].bits == 1:
                if bit is not None:
                    return None
                bit = sb[0], sb[2]
                continue
            if resolver is None:
                resolver = block_defs_resolver(block_defs)
            zeros, _ = known_bits(term, resolver)
            if not (zeros >> k) & 1:
                return None
        if bit is None:
            return None

        b, b_negated = bit
        if b_negated != negated:
            b = UnaryOp(self.manager.next_atom(), "Not", b, bits=1, **b.tags)
        conv = Convert(self.manager.next_atom(), 1, expr.bits, False, b, **expr.tags)
        if k == 0:
            return conv
        return BinaryOp(
            expr.idx,
            "Mul",
            [conv, Const(self.manager.next_atom(), 1 << k, expr.bits)],
            False,
            bits=expr.bits,
            **expr.tags,
        )
