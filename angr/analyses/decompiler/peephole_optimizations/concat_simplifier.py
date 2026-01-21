from __future__ import annotations
from angr.ailment.expression import BinaryOp, Const, Convert

from .base import PeepholeOptimizationExprBase


class ConcatSimplifier(PeepholeOptimizationExprBase):
    """
    Simplify Concat expressions:
    - (a CONCAT b) >> bits(b)  =>  a  (high-part extraction)
    - (a CONCAT b) & mask  =>  b  (low-part extraction, where mask = (1 << bits(b)) - 1)
    - (a >> (bits-1)) CONCAT a  =>  Convert(a, signed, 2*bits)  (sign-extension)
    - 0 CONCAT a  =>  Convert(a, unsigned, 2*bits)  (zero-extension)
    - Convert(a CONCAT b, to_bits=bits(b))  =>  b  (truncate to low part)
    """

    __slots__ = ()

    NAME = "Simplify Concat expressions"
    expr_classes = (BinaryOp, Convert)

    def optimize(self, expr: BinaryOp | Convert, stmt_idx: int | None = None, block=None, **kwargs):
        if isinstance(expr, BinaryOp):
            if expr.op == "Concat":
                return self._optimize_concat(expr, stmt_idx, block)
            if expr.op in {"Shr", "Sar"}:
                return self._optimize_shr_concat(expr)
            if expr.op == "And":
                return self._optimize_and_concat(expr)
        elif isinstance(expr, Convert):
            return self._optimize_convert_concat(expr)
        return None

    def _optimize_concat(self, expr: BinaryOp, stmt_idx: int | None = None, block=None) -> BinaryOp | Convert | None:
        """
        Simplify Concat expressions that represent sign/zero extension.
        """
        high, low = expr.operands

        # Pattern: 0 CONCAT a  =>  Convert(a, unsigned, 2*bits)
        if isinstance(high, Const) and high.value == 0:
            return Convert(
                expr.idx,
                low.bits,
                expr.bits,
                False,  # unsigned
                low,
                **expr.tags,
            )

        # Pattern: (a >> (bits-1)) CONCAT a  =>  Convert(a, signed, 2*bits)
        if (
            isinstance(high, BinaryOp)
            and high.op == "Sar"
            and isinstance(high.operands[1], Const)
            and high.operands[1].value == low.bits - 1
            and high.operands[0].likes(low)
        ):
            return Convert(
                expr.idx,
                low.bits,
                expr.bits,
                True,  # signed
                low,
                **expr.tags,
            )

        # Pattern: ((signed)Conv(a) >> (bits-1)) CONCAT a  =>  Convert(a, signed, 2*bits)
        # This handles cases where the sign bit extraction uses a converted value
        if (
            isinstance(high, BinaryOp)
            and high.op == "Sar"
            and isinstance(high.operands[1], Const)
            and isinstance(high.operands[0], Convert)
        ):
            conv = high.operands[0]
            shift_amt = high.operands[1].value
            if conv.is_signed and conv.operand.likes(low) and shift_amt == conv.to_bits - 1:
                return Convert(
                    expr.idx,
                    low.bits,
                    expr.bits,
                    True,  # signed
                    low,
                    **expr.tags,
                )

        # Pattern: v CONCAT a where v = a >> (bits-1)  =>  Convert(a, signed, 2*bits)
        # This handles cases where the sign extension is split across statements
        if stmt_idx is not None and block is not None:
            high_def = self.find_definition(high, stmt_idx, block)
            if (
                high_def is not None
                and isinstance(high_def, BinaryOp)
                and high_def.op == "Sar"
                and isinstance(high_def.operands[1], Const)
                and high_def.operands[1].value == low.bits - 1
                and high_def.operands[0].likes(low)
            ):
                return Convert(
                    expr.idx,
                    low.bits,
                    expr.bits,
                    True,  # signed
                    low,
                    **expr.tags,
                )

        return None

    @staticmethod
    def _optimize_shr_concat(expr: BinaryOp) -> BinaryOp | Convert | None:
        """
        Simplify (a CONCAT b) >> bits(b)  =>  a  (high-part extraction)
        """
        if not isinstance(expr.operands[1], Const):
            return None

        shift_amt = expr.operands[1].value
        inner = expr.operands[0]

        # Handle Convert wrapping the Concat
        outer_convert = None
        if isinstance(inner, Convert):
            outer_convert = inner
            inner = inner.operand

        if not isinstance(inner, BinaryOp) or inner.op != "Concat":
            return None

        high, low = inner.operands

        # Check if we're extracting exactly the high part
        if shift_amt != low.bits:
            return None
        result = high

        # If there was an outer convert, we may need to apply it
        # The shift extracted high part has high.bits bits
        # Apply conversion if needed
        if outer_convert is not None and outer_convert.to_bits != high.bits:
            result = Convert(
                outer_convert.idx,
                high.bits,
                outer_convert.to_bits,
                outer_convert.is_signed,
                result,
                **outer_convert.tags,
            )

        return result

    @staticmethod
    def _optimize_and_concat(expr: BinaryOp) -> BinaryOp | Convert | None:
        """
        Simplify (a CONCAT b) & mask  =>  b  (low-part extraction)
        where mask = (1 << bits(b)) - 1
        """
        if not isinstance(expr.operands[1], Const):
            return None

        mask = expr.operands[1].value
        inner = expr.operands[0]

        # Handle Convert wrapping the Concat
        outer_convert = None
        if isinstance(inner, Convert):
            outer_convert = inner
            inner = inner.operand

        if not isinstance(inner, BinaryOp) or inner.op != "Concat":
            return None

        _high, low = inner.operands

        # Check if the mask extracts exactly the low part
        expected_mask = (1 << low.bits) - 1
        if mask != expected_mask:
            return None

        # The result should be the low part
        result = low

        if outer_convert is not None:
            if outer_convert.to_bits != low.bits:
                result = Convert(
                    outer_convert.idx,
                    low.bits,
                    outer_convert.to_bits,
                    False,  # zero-extend since we masked
                    result,
                    **outer_convert.tags,
                )
        elif expr.bits != low.bits:
            result = Convert(
                expr.idx,
                low.bits,
                expr.bits,
                False,  # zero-extend since we masked
                result,
                **expr.tags,
            )

        return result

    @staticmethod
    def _optimize_convert_concat(expr: Convert) -> BinaryOp | Convert | None:
        """
        Simplify Convert(a CONCAT b, to_bits=bits(b))  =>  b  (truncate to low part)
        """
        if expr.from_bits <= expr.to_bits:
            return None

        inner = expr.operand
        if not isinstance(inner, BinaryOp) or inner.op != "Concat":
            return None

        _high, low = inner.operands

        # Check if we're truncating to exactly the low part size
        if expr.to_bits == low.bits:
            return low

        # Check if we're truncating to less than the low part
        if expr.to_bits < low.bits:
            return Convert(
                expr.idx,
                low.bits,
                expr.to_bits,
                expr.is_signed,
                low,
                **expr.tags,
            )

        return None
