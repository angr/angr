from typing import Tuple, Optional

from ailment.expression import BinaryOp, Const, Expression, Convert
from ailment.statement import Call

from .base import PeepholeOptimizationExprBase


class Bswap(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Simplifying bswap_16() and bswap_32()"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp, **kwargs):
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

        # bswap_32
        #   (Conv(64->32, rax<8>) << 0x18<8>) |
        #   (((Conv(64->32, rax<8>) << 0x8<8>) & 0xff0000<32>) |
        #   (((Conv(64->32, rax<8>) >> 0x8<8>) & 0xff00<32>) |
        #   ((Conv(64->32, rax<8>) >> 0x18<8>) & 0xff<32>))))
        if expr.op == "Or":
            # fully flatten the expression
            or_pieces = []
            queue = [expr]
            while queue:
                operand = queue.pop(0)
                if isinstance(operand, BinaryOp) and operand.op == "Or":
                    queue.append(operand.operands[0])
                    queue.append(operand.operands[1])
                else:
                    or_pieces.append(operand)
            if len(or_pieces) == 4:
                # parse pieces
                shifts = set()
                cores = set()
                for piece in or_pieces:
                    if isinstance(piece, BinaryOp):
                        if piece.op == "Shl" and isinstance(piece.operands[1], Const):
                            cores.add(piece.operands[0])
                            shifts.add(("<<", piece.operands[1].value, 0xFFFFFFFF))
                        elif piece.op == "And" and isinstance(piece.operands[1], Const):
                            and_amount = piece.operands[1].value
                            and_core = piece.operands[0]
                            if (
                                isinstance(and_core, BinaryOp)
                                and and_core.op == "Shl"
                                and isinstance(and_core.operands[1], Const)
                            ):
                                cores.add(and_core.operands[0])
                                shifts.add(("<<", and_core.operands[1].value, and_amount))
                            elif (
                                isinstance(and_core, BinaryOp)
                                and and_core.op == "Shr"
                                and isinstance(and_core.operands[1], Const)
                            ):
                                cores.add(and_core.operands[0])
                                shifts.add((">>", and_core.operands[1].value, and_amount))
                if len(cores) == 1 and shifts == {
                    ("<<", 0x18, 0xFFFFFFFF),
                    ("<<", 8, 0xFF0000),
                    (">>", 0x18, 0xFF),
                    (">>", 8, 0xFF00),
                }:
                    core_expr = next(iter(cores))
                    return Call(expr.idx, "__buildin_bswap32", args=[core_expr], bits=expr.bits, **expr.tags)

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
