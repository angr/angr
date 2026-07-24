from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Tmp, UnaryOp, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump

from .base import PeepholeOptimizationExprBase


class ARMCmpF(PeepholeOptimizationExprBase):
    """
    Optimizes floating-point comparison expressions.
    """

    __slots__ = ()

    NAME = "Simplifying CmpF on ARM"
    expr_classes = (BinaryOp, Convert, UnaryOp)

    _CMP_OUTCOMES = {
        "CmpEQ": (False, True, False, False),
        "CmpNE": (True, False, True, True),
        "CmpLT": (False, False, True, False),
        "CmpLE": (False, True, True, False),
        "CmpGT": (True, False, False, False),
        "CmpGE": (True, True, False, False),
    }
    _FPSCR_FLAGS = (0x2000_0000, 0x6000_0000, 0x8000_0000, 0x3000_0000)
    _OUTCOME_COMPARISONS = {
        (False, True, False, False): ("CmpEQ", False),
        (True, False, True, True): ("CmpNE", False),
        (False, False, True, False): ("CmpLT", False),
        (False, True, True, False): ("CmpLE", False),
        (True, False, False, False): ("CmpGT", False),
        (True, True, False, False): ("CmpGE", False),
        # ARM condition codes can include the unordered result. Keep the explicit
        # negation because, for example, !(a > b) is true for NaN while a <= b is not.
        (True, True, False, True): ("CmpLT", True),
        (True, False, False, True): ("CmpLE", True),
        (False, True, True, True): ("CmpGT", True),
        (False, False, True, True): ("CmpGE", True),
    }

    def optimize(self, expr: BinaryOp | Convert | UnaryOp, *, stmt_idx=None, block=None, **kwargs):
        if self.project is not None and self.project.arch.name not in {"ARMEL", "ARMHF", "ARMCortexM"}:
            return None

        if (
            expr.bits == 1
            and block is not None
            and stmt_idx is not None
            and isinstance(block.statements[stmt_idx], ConditionalJump)
            and not (isinstance(expr, BinaryOp) and expr.floating_point and expr.op in self._CMP_OUTCOMES)
            and not (
                isinstance(expr, UnaryOp)
                and expr.op == "Not"
                and isinstance(expr.operand, BinaryOp)
                and expr.operand.floating_point
                and expr.operand.op in self._CMP_OUTCOMES
            )
        ):
            simplified = self._simplify_fpscr_condition(expr, stmt_idx, block)
            if simplified is not None:
                return simplified

        if not isinstance(expr, Convert):
            return None

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
                        comparison = BinaryOp(
                            expr.idx,
                            "CmpGT",
                            irRes.operands[::],
                            False,
                            floating_point=True,
                            **expr.tags,
                        )
                        if negate:
                            return comparison
                        return UnaryOp(self.manager.next_atom(), "Not", comparison, **expr.tags)
                    raise NotImplementedError

        return None

    @classmethod
    def _simplify_fpscr_condition(cls, expr, stmt_idx, block):
        tmp_definitions = {}
        for stmt in block.statements[:stmt_idx]:
            if not isinstance(stmt, Assignment):
                continue
            if isinstance(stmt.dst, Tmp):
                tmp_definitions[("tmp", stmt.dst.tmp_idx)] = stmt.src
            elif isinstance(stmt.dst, VirtualVariable):
                tmp_definitions[("vvar", stmt.dst.varid)] = stmt.src

        outcomes = []
        source_comparison = None
        for outcome, flags in enumerate(cls._FPSCR_FLAGS):
            evaluated = cls._evaluate_condition(expr, outcome, flags, tmp_definitions)
            if evaluated is None:
                return None
            value, comparison = evaluated
            if comparison is None:
                return None
            if source_comparison is None:
                source_comparison = comparison
            elif not cls._same_comparison_operands(source_comparison, comparison):
                return None
            outcomes.append(bool(value))

        replacement = cls._OUTCOME_COMPARISONS.get(tuple(outcomes))
        if replacement is None or source_comparison is None:
            return None

        op, negate = replacement
        comparison = BinaryOp(
            expr.idx,
            op,
            source_comparison.operands[::],
            False,
            floating_point=True,
            **expr.tags,
        )
        if negate:
            return UnaryOp(expr.idx, "Not", comparison, **expr.tags)
        return comparison

    @classmethod
    def _evaluate_condition(cls, expr, outcome, fpscr_flags, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)

        comparison = cls._match_fpscr_high_bits(expr, tmp_definitions)
        if comparison is not None:
            return fpscr_flags, comparison

        if isinstance(expr, Const):
            if not isinstance(expr.value, int):
                return None
            return expr.value & cls._mask(expr.bits), None

        if isinstance(expr, Convert):
            evaluated = cls._evaluate_condition(expr.operand, outcome, fpscr_flags, tmp_definitions)
            if evaluated is None:
                return None
            value, comparison = evaluated
            value &= cls._mask(expr.from_bits)
            if expr.is_signed and expr.to_bits > expr.from_bits:
                value = cls._to_signed(value, expr.from_bits)
            return value & cls._mask(expr.to_bits), comparison

        if isinstance(expr, UnaryOp):
            if expr.op != "Not":
                return None
            evaluated = cls._evaluate_condition(expr.operand, outcome, fpscr_flags, tmp_definitions)
            if evaluated is None:
                return None
            value, comparison = evaluated
            return (~value) & cls._mask(expr.bits), comparison

        if not isinstance(expr, BinaryOp):
            return None

        if expr.floating_point and expr.op in cls._CMP_OUTCOMES:
            return int(cls._CMP_OUTCOMES[expr.op][outcome]), expr

        evaluated_operands = [
            cls._evaluate_condition(operand, outcome, fpscr_flags, tmp_definitions) for operand in expr.operands
        ]
        if any(evaluated is None for evaluated in evaluated_operands):
            return None
        values = [evaluated[0] for evaluated in evaluated_operands]
        comparisons = [evaluated[1] for evaluated in evaluated_operands if evaluated[1] is not None]
        comparison = comparisons[0] if comparisons else None
        if any(not cls._same_comparison_operands(comparison, other) for other in comparisons[1:]):
            return None

        op = expr.op
        if op == "Add":
            value = values[0] + values[1]
        elif op == "Sub":
            value = values[0] - values[1]
        elif op == "Mul":
            value = values[0] * values[1]
        elif op in {"And", "LogicalAnd"}:
            value = values[0] & values[1]
        elif op in {"Or", "LogicalOr"}:
            value = values[0] | values[1]
        elif op in {"Xor", "LogicalXor"}:
            value = values[0] ^ values[1]
        elif op == "Shl":
            value = values[0] << values[1]
        elif op == "Shr":
            value = (values[0] & cls._mask(expr.operands[0].bits)) >> values[1]
        elif op == "Sar":
            value = cls._to_signed(values[0], expr.operands[0].bits) >> values[1]
        elif op in {"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}:
            lhs, rhs = values
            if expr.signed:
                lhs = cls._to_signed(lhs, expr.operands[0].bits)
                rhs = cls._to_signed(rhs, expr.operands[1].bits)
            if op == "CmpEQ":
                value = lhs == rhs
            elif op == "CmpNE":
                value = lhs != rhs
            elif op == "CmpLT":
                value = lhs < rhs
            elif op == "CmpLE":
                value = lhs <= rhs
            elif op == "CmpGT":
                value = lhs > rhs
            else:
                value = lhs >= rhs
        else:
            return None

        return int(value) & cls._mask(expr.bits), comparison

    @classmethod
    def _match_fpscr_high_bits(cls, expr, tmp_definitions):
        fpscr_update = cls._match_binop_const(expr, "And", 0xF000_0000, tmp_definitions)
        if fpscr_update is None:
            return None
        fpscr_update = cls._resolve_tmp(fpscr_update, tmp_definitions)
        if not isinstance(fpscr_update, BinaryOp) or fpscr_update.op != "Or":
            return None

        for low_bits, high_bits in (
            fpscr_update.operands,
            fpscr_update.operands[::-1],
        ):
            if cls._match_binop_const(low_bits, "And", 0x0FFF_FFFF, tmp_definitions) is None:
                continue
            nzcv = cls._match_scaled_nzcv(high_bits, tmp_definitions)
            if nzcv is None:
                continue
            comparison = cls._match_nzcv_value(nzcv, tmp_definitions)
            if comparison is not None:
                return comparison
        return None

    @classmethod
    def _match_nzcv_value(cls, expr, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)
        if not isinstance(expr, BinaryOp) or expr.op != "Sub":
            return None

        ix_left = cls._match_term_left(expr.operands[0], tmp_definitions)
        ix_right = cls._match_term_right(expr.operands[1], tmp_definitions)
        if ix_left is None or ix_right is None:
            return None

        comparison_left = cls._match_ix_value(ix_left, tmp_definitions)
        comparison_right = cls._match_ix_value(ix_right, tmp_definitions)
        if (
            comparison_left is not None
            and comparison_right is not None
            and cls._same_comparison_operands(comparison_left, comparison_right)
        ):
            return comparison_left
        return None

    @classmethod
    def _match_term_left(cls, expr, tmp_definitions):
        expr = cls._match_binop_const(expr, "Add", 1, tmp_definitions)
        if expr is None:
            return None
        expr = cls._match_ordered_binop_const(expr, "Shr", 29, tmp_definitions)
        if expr is None:
            return None
        expr = cls._match_ordered_binop_const(expr, "Sub", 1, tmp_definitions)
        if expr is None:
            return None
        expr = cls._match_scaled_value(expr, 30, 0x4000_0000, tmp_definitions)
        if expr is None:
            return None
        return cls._match_binop_const(expr, "Xor", 1, tmp_definitions)

    @classmethod
    def _match_term_right(cls, expr, tmp_definitions):
        expr = cls._match_binop_const(expr, "And", 1, tmp_definitions)
        expr = cls._resolve_tmp(expr, tmp_definitions) if expr is not None else None
        if not isinstance(expr, BinaryOp) or expr.op != "And":
            return None

        for value, shifted in (expr.operands, expr.operands[::-1]):
            shifted_value = cls._match_ordered_binop_const(shifted, "Shr", 1, tmp_definitions)
            if shifted_value is not None and cls._same_expression(value, shifted_value, tmp_definitions):
                return value
        return None

    @classmethod
    def _match_ix_value(cls, expr, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)
        if not isinstance(expr, BinaryOp) or expr.op != "Or":
            return None

        for shifted_part, low_part in (expr.operands, expr.operands[::-1]):
            shifted_part = cls._match_binop_const(shifted_part, "And", 3, tmp_definitions)
            if shifted_part is None:
                continue
            comparison_left = cls._match_ordered_binop_const(shifted_part, "Shr", 5, tmp_definitions)
            comparison_right = cls._match_binop_const(low_part, "And", 1, tmp_definitions)
            comparison_left = cls._resolve_tmp(comparison_left, tmp_definitions)
            comparison_right = cls._resolve_tmp(comparison_right, tmp_definitions)
            if (
                isinstance(comparison_left, BinaryOp)
                and comparison_left.op == "CmpF"
                and isinstance(comparison_right, BinaryOp)
                and comparison_right.op == "CmpF"
                and cls._same_comparison_operands(comparison_left, comparison_right)
            ):
                return comparison_left
        return None

    @classmethod
    def _match_scaled_nzcv(cls, expr, tmp_definitions):
        return cls._match_scaled_value(expr, 28, 0x1000_0000, tmp_definitions)

    @classmethod
    def _match_scaled_value(cls, expr, shift, multiplier, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)
        shifted = cls._match_ordered_binop_const(expr, "Shl", shift, tmp_definitions)
        if shifted is not None:
            return shifted
        return cls._match_binop_const(expr, "Mul", multiplier, tmp_definitions)

    @classmethod
    def _match_binop_const(cls, expr, op, value, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)
        if not isinstance(expr, BinaryOp) or expr.op != op:
            return None
        left = cls._resolve_tmp(expr.operands[0], tmp_definitions)
        right = cls._resolve_tmp(expr.operands[1], tmp_definitions)
        if isinstance(right, Const) and right.value == value:
            return left
        if isinstance(left, Const) and left.value == value:
            return right
        return None

    @classmethod
    def _match_ordered_binop_const(cls, expr, op, value, tmp_definitions):
        expr = cls._resolve_tmp(expr, tmp_definitions)
        if (
            isinstance(expr, BinaryOp)
            and expr.op == op
            and isinstance(expr.operands[1], Const)
            and expr.operands[1].value == value
        ):
            return expr.operands[0]
        return None

    @classmethod
    def _resolve_tmp(cls, expr, tmp_definitions, seen=frozenset()):
        while isinstance(expr, (Tmp, VirtualVariable)):
            key = ("tmp", expr.tmp_idx) if isinstance(expr, Tmp) else ("vvar", expr.varid)
            if key in seen:
                break
            definition = tmp_definitions.get(key)
            if definition is None:
                break
            seen |= {key}
            expr = definition
        return expr

    @classmethod
    def _same_expression(cls, left, right, tmp_definitions):
        left = cls._resolve_tmp(left, tmp_definitions)
        right = cls._resolve_tmp(right, tmp_definitions)
        return left.likes(right)

    @staticmethod
    def _same_comparison_operands(left, right):
        if left is None or right is None or len(left.operands) != len(right.operands):
            return False
        return all(
            left_operand.likes(right_operand) for left_operand, right_operand in zip(left.operands, right.operands)
        )

    @staticmethod
    def _mask(bits):
        return (1 << bits) - 1

    @classmethod
    def _to_signed(cls, value, bits):
        value &= cls._mask(bits)
        sign_bit = 1 << (bits - 1)
        return value - (1 << bits) if value & sign_bit else value

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
