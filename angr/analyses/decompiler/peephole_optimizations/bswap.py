from typing import Tuple, Optional

from ailment.expression import BinaryOp, Const, Expression, Convert
from ailment.statement import Call

from .base import PeepholeOptimizationExprBase


class Bswap(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Simplifying bswap_16()"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp):
        # bswap_16
        #   And(
        #     (
        #       ((Conv(16->32, A) << 0x8<8>) & 0xff00ff00<32>) |
        #       ((Conv(16->32, A) >> 0x8<8>) & 0xff00ff<32>)
        #     ),
        #     0xffff<32>
        #   )
        if (
            expr.op == "And"
            and len(expr.operands) == 2
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 0xFFFF
        ):
            inner = expr.operands[0]
            if isinstance(inner, BinaryOp) and inner.op == "Or" and len(inner.operands) == 2:
                or_first, or_second = inner.operands[0], inner.operands[1]
                if (
                    isinstance(or_first, BinaryOp)
                    and or_first.op == "And"
                    and len(or_first.operands) == 2
                    and isinstance(or_second, BinaryOp)
                    and or_second.op == "And"
                    and len(or_second.operands) == 2
                ):
                    r, the_expr = self._match_inner(or_first, or_second)
                    if r:
                        return Call(expr.idx, "__builtin_bswap16", args=[the_expr], bits=expr.bits, **expr.tags)

                    r, the_expr = self._match_inner(or_second, or_first)
                    if r:
                        return Call(expr.idx, "__builtin_bswap16", args=[the_expr], bits=expr.bits, **expr.tags)

                    return None

        return None

    def _match_inner(self, or_first: BinaryOp, or_second: BinaryOp) -> Tuple[bool, Optional[Expression]]:
        if isinstance(or_first.operands[1], Const) and or_first.operands[1].value == 0xFF00FF00:
            if isinstance(or_second.operands[1], Const) and or_second.operands[1].value == 0x00FF00FF:
                inner_first = or_first.operands[0]
                inner_second = or_second.operands[0]
                if (
                    isinstance(inner_first, BinaryOp)
                    and inner_first.op == "Shl"
                    and isinstance(inner_first.operands[1], Const)
                    and inner_first.operands[1].value == 8
                ):
                    if (
                        isinstance(inner_second, BinaryOp)
                        and inner_second.op == "Shr"
                        and isinstance(inner_second.operands[1], Const)
                        and inner_second.operands[1].value == 8
                    ):
                        if isinstance(inner_first.operands[0], Convert):
                            conv: Convert = inner_first.operands[0]
                            if conv.from_bits == 16 and conv.to_bits == 32:
                                the_expr_1 = conv.operand
                                if (
                                    isinstance(inner_second.operands[0], Convert)
                                    and inner_second.operands[0].from_bits == 16
                                    and inner_second.operands[0].to_bits == 32
                                ):
                                    the_expr_2 = inner_second.operands[0].operand
                                    if the_expr_1.likes(the_expr_2):
                                        return True, the_expr_1
        return False, None
