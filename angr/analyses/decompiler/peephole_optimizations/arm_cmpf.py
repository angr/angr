from __future__ import annotations
from ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class ARMCmpF(PeepholeOptimizationExprBase):
    """
    Optimizes floating-point comparison expressions.
    """

    __slots__ = ()

    NAME = "Simplifying CmpF on ARM"
    expr_classes = (Convert,)  # all expressions are allowed

    def optimize(self, expr: Convert, **kwargs):
        # CmpF values
        # - 0x45 Unordered
        # - 0x01 LT
        # - 0x00 GT
        # - 0x40 EQ

        # we identify nzcv, termL, termR, and ix. then we determine which bit is parsed out of nzcv, and finally convert
        # this large expression into a comparison
        if expr.from_bits == 32 and expr.to_bits == 1:
            convert_from = expr.operand
            negate = False
            bit_mask = None
            if (
                isinstance(convert_from, BinaryOp)
                and convert_from.op == "Xor"
                and isinstance(convert_from.operands[1], Const)
                and convert_from.operands[1].value == 1
            ):
                negate = True
                convert_from = convert_from.operands[0]
            if (
                isinstance(convert_from, BinaryOp)
                and convert_from.op == "And"
                and isinstance(convert_from.operands[1], Const)
            ):
                bit_mask = convert_from.operands[1].value

            if bit_mask is not None and isinstance(convert_from.operands[0], BinaryOp):
                r, high_nzcv0, high_nzcv1, high_nzcv2 = self._match_nzcv_bits_extraction(convert_from.operands[0])
                if not r:
                    return None
                irRes = None
                for high_nczv in [high_nzcv0, high_nzcv1, high_nzcv2]:
                    r, termL, termR = self._match_nzcv(high_nczv)
                    if not r:
                        return None
                    r, ixL = self._match_termL(termL)
                    if not r:
                        return None
                    r, irResL = self._match_ix(ixL)
                    if not r:
                        return None
                    if irRes is None:
                        irRes = irResL
                    elif irRes != irResL:
                        return None
                    r, ixR = self._match_termR(termR)
                    if not r:
                        return None
                    r, irResR = self._match_ix(ixR)
                    if not r:
                        return None
                    if irRes != irResR:
                        return None

                if isinstance(irRes, BinaryOp) and irRes.op == "CmpF":
                    # everything matches
                    if bit_mask == 1:
                        op = "CmpGT" if negate else "CmpLE"
                    else:
                        raise NotImplementedError
                    return BinaryOp(
                        expr.idx,
                        op,
                        irRes.operands[::],
                        False,
                        floating_point=True,
                        **expr.tags,
                    )

        return None

    @staticmethod
    def _match_nzcv_bits_extraction(expr: BinaryOp):
        # ((high_nzcv >> 0x1e<8>) | ((high_nzcv >> 0x1f<8>) ^ (high_nzcv >> 0x1c<8>)))
        if expr.op == "Or" and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "Xor":
            chunk0 = expr.operands[0]
            chunk1, chunk2 = expr.operands[1].operands

            if (
                (
                    isinstance(chunk0, BinaryOp)
                    and chunk0.op == "Shr"
                    and isinstance(chunk0.operands[1], Const)
                    and chunk0.operands[1].value == 0x1E
                )
                and (
                    isinstance(chunk1, BinaryOp)
                    and chunk1.op == "Shr"
                    and isinstance(chunk1.operands[1], Const)
                    and chunk1.operands[1].value == 0x1F
                )
                and (
                    isinstance(chunk2, BinaryOp)
                    and chunk2.op == "Shr"
                    and isinstance(chunk2.operands[1], Const)
                    and chunk2.operands[1].value == 0x1C
                )
            ):
                return True, chunk0.operands[0], chunk1.operands[0], chunk2.operands[0]
        return False, None, None, None

    @staticmethod
    def _match_nzcv(expr: BinaryOp):
        # high_nzcv ==> ((0x0<32> | ((termL - termR) << 0x1c<8>)) & 0xf0000000<32>)
        # TODO: I'm not sure the leading 0x0 is real or just an artifact of me forcing fpscr to 0
        if expr.op == "And" and isinstance(expr.operands[1], Const) and expr.operands[1].value == 0xF000_0000:
            inner = expr.operands[0]
            if isinstance(inner, BinaryOp) and inner.op == "Or":
                # ignore the first operand because it might be optimized away
                inner = inner.operands[1]
            if (
                (
                    isinstance(inner, BinaryOp)
                    and inner.op == "Shl"
                    and isinstance(inner.operands[1], Const)
                    and inner.operands[1].value == 0x1C
                )
                and isinstance(inner.operands[0], BinaryOp)
                and inner.operands[0].op == "Sub"
            ):
                return True, inner.operands[0].operands[0], inner.operands[0].operands[1]
        return False, None, None

    @staticmethod
    def _match_termL(expr: BinaryOp):
        # ((((((ix ^ 0x1<32>) << 0x1e<8>) - 0x1<32>) >> 0x1d<8>) + 0x1<32>)
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "Add"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 1
        ):
            lhs0 = expr.operands[0]
            if (
                isinstance(lhs0, BinaryOp)
                and lhs0.op == "Shr"
                and isinstance(lhs0.operands[1], Const)
                and lhs0.operands[1].value == 0x1D
            ):
                lhs1 = lhs0.operands[0]
                if (
                    isinstance(lhs1, BinaryOp)
                    and lhs1.op == "Sub"
                    and isinstance(lhs1.operands[1], Const)
                    and lhs1.operands[1].value == 1
                ):
                    lhs2 = lhs1.operands[0]
                    if (
                        isinstance(lhs2, BinaryOp)
                        and lhs2.op == "Shl"
                        and isinstance(lhs2.operands[1], Const)
                        and lhs2.operands[1].value == 0x1E
                    ):
                        lhs3 = lhs2.operands[0]
                        if (
                            isinstance(lhs3, BinaryOp)
                            and lhs3.op == "Xor"
                            and isinstance(lhs3.operands[1], Const)
                            and lhs3.operands[1].value == 1
                        ):
                            ix = lhs3.operands[0]
                            return True, ix
        return False, None

    @staticmethod
    def _match_termR(expr: BinaryOp):
        # ((ix & (ix >> 0x1<8>)) & 0x1<32>)
        if (
            isinstance(expr, BinaryOp)
            and expr.op == "And"
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == 1
        ):
            lhs0 = expr.operands[0]
            if isinstance(lhs0, BinaryOp) and lhs0.op == "And":
                ix0, op1 = lhs0.operands
                if (
                    isinstance(op1, BinaryOp)
                    and op1.op == "Shr"
                    and isinstance(op1.operands[1], Const)
                    and op1.operands[1].value == 1
                ):
                    ix1 = op1.operands[0]
                    if ix0 == ix1:
                        return True, ix0
        return False, None

    @staticmethod
    def _match_ix(expr: BinaryOp):
        # ((((Conv(32->s64, r7<4>) CmpF t81) >> 0x5<8>) & 0x3<32>) | ((Conv(32->s64, r7<4>) CmpF t81) & 0x1<32>))
        if isinstance(expr, BinaryOp) and expr.op == "Or":
            left, right = expr.operands
            cmpf_0, cmpf_1 = None, None
            if (
                isinstance(left, BinaryOp)
                and left.op == "And"
                and isinstance(left.operands[1], Const)
                and left.operands[1].value == 3
            ):
                left_inner = left.operands[0]
                if (
                    isinstance(left_inner, BinaryOp)
                    and left_inner.op == "Shr"
                    and isinstance(left_inner.operands[1], Const)
                    and left_inner.operands[1].value == 5
                ):
                    cmpf_0 = left_inner.operands[0]
            if (
                isinstance(right, BinaryOp)
                and right.op == "And"
                and isinstance(right.operands[1], Const)
                and right.operands[1].value == 1
            ):
                cmpf_1 = right.operands[0]

            if cmpf_0 is not None and cmpf_1 is not None and cmpf_0 == cmpf_1:
                return True, cmpf_0
        return None
