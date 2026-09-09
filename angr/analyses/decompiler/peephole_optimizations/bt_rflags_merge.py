from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const

from .base import PeepholeOptimizationExprBase

# O | S | A | P | Z: the rflags bits that the libVEX 3.27+ amd64 BT/BTS/BTR/BTC lifting preserves (Skylake model)
# alongside the tested bit, which lands in CF (bit 0)
_BT_PRESERVED_FLAGS_MASK = 0x8D4


class BTRflagsMergeBitExtraction(PeepholeOptimizationExprBase):
    """
    Fold CF extractions from the flags merge that the libVEX 3.27+ amd64 BT/BTS/BTR/BTC lifting emits.

    The new lifting preserves O/S/A/P/Z across BT-family instructions by writing
    ``(amd64g_calculate_rflags_all(...) & 0x8D4) | bt_bit`` into the flags thunk. A downstream condition that tests
    the tested bit (CF, bit 0) extracts it as ``(merge & 0x8D4 | bt_bit) & 1``; since 0x8D4 has bit 0 cleared, this
    is just ``bt_bit``, and folding it lets the (otherwise unreducible) rflags_all ccall become dead.
    """

    __slots__ = ()

    NAME = "(x & 0x8d4 | bit) & 1 => bit"
    expr_classes = (BinaryOp,)

    def optimize(self, expr: BinaryOp, **kwargs):
        if not (
            expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 1
            and isinstance(expr.operands[0], BinaryOp)
            and expr.operands[0].op == "Or"
        ):
            return None

        or_expr = expr.operands[0]
        for masked, bit in (or_expr.operands, or_expr.operands[::-1]):
            if (
                isinstance(masked, BinaryOp)
                and masked.op == "And"
                and isinstance(masked.operands[1], Const)
                and masked.operands[1].is_int
                and masked.operands[1].value_int == _BT_PRESERVED_FLAGS_MASK & ((1 << masked.bits) - 1)
                and masked.operands[1].value_int != 0
            ):
                if (
                    isinstance(bit, BinaryOp)
                    and bit.op == "And"
                    and isinstance(bit.operands[1], Const)
                    and bit.operands[1].value == 1
                ):
                    # bit is already (x >> n) & 1; the outer masking is redundant
                    return bit
                return BinaryOp(
                    expr.idx,
                    "And",
                    (bit, expr.operands[1]),
                    False,
                    bits=expr.bits,
                    **expr.tags,
                )

        return None
