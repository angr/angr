# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

from angr.ailment.expression import BinaryOp, Call, Const, Convert, Expression

from .base import PeepholeOptimizationExprBase
from .utils import get_expr_shift_left_amount


class Bswap(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Simplifying bswap_16(), bswap_32(), and bswap_64()"
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
                        if piece.op in {"Shl", "Mul"} and isinstance(piece.operands[1], Const):
                            cores.add(piece.operands[0])
                            shift_amount = get_expr_shift_left_amount(piece)
                            shifts.add(("<<", shift_amount, 0xFFFFFFFF))
                        elif piece.op == "And" and isinstance(piece.operands[1], Const):
                            and_amount = piece.operands[1].value
                            and_core = piece.operands[0]
                            if (
                                isinstance(and_core, BinaryOp)
                                and and_core.op in {"Shl", "Mul"}
                                and isinstance(and_core.operands[1], Const)
                            ):
                                cores.add(and_core.operands[0])
                                shift_amount = get_expr_shift_left_amount(and_core)
                                shifts.add(("<<", shift_amount, and_amount))
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
                    return Call(expr.idx, "__builtin_bswap32", args=[core_expr], bits=expr.bits, **expr.tags)

            # bswap_64 (and the SWAR spelling of bswap_32): a recursive
            # divide-and-conquer tree rather than a flat 4-way Or, so the
            # flattening above never reaches 4 pieces.
            core_expr = self._match_swar_bswap(expr, expr.bits)
            if core_expr is not None:
                return Call(expr.idx, f"__builtin_bswap{expr.bits}", args=[core_expr], bits=expr.bits, **expr.tags)

        return None

    @staticmethod
    def _swar_mask(k: int, bits: int) -> int:
        """The mask selecting the high ``k`` bits of every ``2 * k``-bit group."""
        unit = ((1 << k) - 1) << k  # k=8 -> 0xff00
        mask = 0
        for i in range(0, bits, 2 * k):
            mask |= unit << i
        return mask

    @classmethod
    def _match_swap(cls, expr: Expression, k: int, bits: int) -> Expression | None:
        """One SWAR level: ``Or(Shr(And(e, M), k), And(Shl/Mul(e, k), M))`` -> ``e``.
        Both Or operand orders and both mask-then-shift / shift-then-mask
        spellings of each half are accepted."""
        if not isinstance(expr, BinaryOp) or expr.op != "Or" or expr.bits != bits:
            return None
        mask = cls._swar_mask(k, bits)

        def down(e):
            # the ">> k" half: Shr(And(e, M), k) or And(Shr(e, k), M)
            if not isinstance(e, BinaryOp):
                return None
            if e.op == "Shr" and isinstance(e.operands[1], Const) and e.operands[1].value == k:
                inner = e.operands[0]
                if (
                    isinstance(inner, BinaryOp)
                    and inner.op == "And"
                    and isinstance(inner.operands[1], Const)
                    and inner.operands[1].value == mask
                ):
                    return inner.operands[0]
            if e.op == "And" and isinstance(e.operands[1], Const) and e.operands[1].value == mask:
                inner = e.operands[0]
                if (
                    isinstance(inner, BinaryOp)
                    and inner.op == "Shr"
                    and isinstance(inner.operands[1], Const)
                    and inner.operands[1].value == k
                ):
                    return inner.operands[0]
            return None

        def up(e):
            # the "<< k" half: And(Shl/Mul(e, k), M) or Shl/Mul(And(e, M >> k), k)
            if not isinstance(e, BinaryOp):
                return None
            if e.op == "And" and isinstance(e.operands[1], Const) and e.operands[1].value == mask:
                inner = e.operands[0]
                if (
                    isinstance(inner, BinaryOp)
                    and inner.op in {"Shl", "Mul"}
                    and (get_expr_shift_left_amount(inner) == k)
                ):
                    return inner.operands[0]
            if e.op in {"Shl", "Mul"} and get_expr_shift_left_amount(e) == k:
                inner = e.operands[0]
                if (
                    isinstance(inner, BinaryOp)
                    and inner.op == "And"
                    and isinstance(inner.operands[1], Const)
                    and inner.operands[1].value == (mask >> k)
                ):
                    return inner.operands[0]
            return None

        a, b = expr.operands
        for lo, hi in ((a, b), (b, a)):
            e1, e2 = down(lo), up(hi)
            if e1 is not None and e2 is not None and e1.likes(e2):
                return e1
        return None

    @classmethod
    def _match_swar_bswap(cls, expr: Expression, bits: int) -> Expression | None:
        """``bswap(x) = SWAP(bits/2, ... SWAP(8, x))``; returns ``x`` or None.

        gcc lowers ``bswap rax`` into three nested byte/word/dword exchanges::

            SWAP(k, e) := Or(Shr(And(e, M_k), k), And(Shl(e, k), M_k))
            bswap64(x)  = SWAP(32, SWAP(16, SWAP(8, x)))

        with M_8 = 0xff00ff00ff00ff00, M_16 = 0xffff0000ffff0000 and
        M_32 = 0xffffffff00000000 (and the 32-bit analogues).
        """
        # only whole-register byte swaps exist; without this guard a narrow Or
        # (e.g. a 1-bit boolean) would skip the loop entirely and the expression
        # would be returned as its own "core", producing a self-referential call
        if bits not in (16, 32, 64):
            return None
        k = bits // 2
        cur = expr
        while k >= 8:
            cur = cls._match_swap(cur, k, bits)
            if cur is None:
                return None
            k //= 2
        return cur

    def _match_inner(self, or_first: BinaryOp, or_second: BinaryOp) -> tuple[bool, Expression | None]:
        if (
            isinstance(or_first.operands[1], Const)
            and or_first.operands[1].value == 0xFF00FF00
            and isinstance(or_second.operands[1], Const)
            and or_second.operands[1].value == 0x00FF00FF
        ):
            inner_first = or_first.operands[0]
            inner_second = or_second.operands[0]
            if (
                (
                    isinstance(inner_first, BinaryOp)
                    and inner_first.op in {"Shl", "Mul"}
                    and isinstance(inner_first.operands[1], Const)
                    and get_expr_shift_left_amount(inner_first) == 8
                )
                and (
                    isinstance(inner_second, BinaryOp)
                    and inner_second.op == "Shr"
                    and isinstance(inner_second.operands[1], Const)
                    and inner_second.operands[1].value == 8
                )
                and isinstance(inner_first.operands[0], Convert)
            ):
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
