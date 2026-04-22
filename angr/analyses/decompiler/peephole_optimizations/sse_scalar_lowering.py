from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Extract, UnaryOp

from .base import PeepholeOptimizationExprBase

# VEX naming: scalar-in-vector ops have "F0x" in the op name (e.g. Add64F0x2,
# Mul32F0x4).  In AIL they become BinaryOp("AddV", ..., floating_point=True)
# or similar.  This pass lowers those patterns to proper scalar FP ops.
#
# Pattern (common in O0, where values are spilled to stack as N-bit integers
# and widened to 128 bits before the SSE op):
#
#   Extract(
#       BinaryOp("XxxV", Conv(N->128I, a), Conv(N->128I, b), fp=True),
#       N bits @ 0
#   )
#   ->  BinaryOp("Xxx", a, b, bits=N, floating_point=True)
#
# Pattern (O1, where the XMM register value is used directly):
#
#   Extract(BinaryOp("XxxV", a128, b128, fp=True), N bits @ 0)
#   ->  BinaryOp("Xxx", Extract(a128, N@0), Extract(b128, N@0), bits=N, fp=True)
#
# Supported op mappings:
#   AddV -> Add   SubV -> Sub   MulV -> Mul   DivV -> Div
#   MaxV -> MaxF  MinV -> MinF

_V_TO_SCALAR: dict[str, str] = {
    "AddV": "Add",
    "SubV": "Sub",
    "MulV": "Mul",
    "DivV": "Div",
    "MaxV": "MaxF",
    "MinV": "MinF",
}


def _unwrap_conv_or_extract(operand, n_bits: int):
    """Return the N-bit scalar value inside *operand*.

    - If *operand* is ``Conv(N->128I, x)``, return ``x`` (the original N-bit value).
    - Otherwise return ``Extract(operand, N bits @ 0)``.
    """
    if (
        isinstance(operand, Convert)
        and operand.from_type == Convert.TYPE_INT
        and operand.to_type == Convert.TYPE_INT
        and operand.from_bits == n_bits
        and operand.to_bits == 128
    ):
        return operand.operand

    # Generic: extract the lower N bits.
    tags = operand.tags if hasattr(operand, "tags") else {}
    zero = Const(None, None, 0, 64, **tags)
    return Extract(None, n_bits, operand, zero, "Iend_LE", **tags)


class SSEScalarLowering(PeepholeOptimizationExprBase):
    """Lower SSE scalar-in-vector ops to scalar floating-point arithmetic.

    VEX represents SSE scalar ops (addss, mulss, addsd, ...) as full-width
    128-bit vector operations (Add32F0x4, Add64F0x2, ...) followed by a read of
    the lower element.  After AIL lifting and SSAIL propagation this produces::

        Extract(BinaryOp("XxxV", ..., fp=True), N@0)

    This pass rewrites such expressions to their scalar equivalents so that
    type inference, constant folding, and codegen all handle them correctly.
    """

    __slots__ = ()

    NAME = "SSE scalar-in-vector op lowering"
    expr_classes = (Extract,)

    def optimize(self, expr: Extract, **kwargs):
        # The Extract must read the least-significant N bits (little-endian offset 0).
        if not expr.is_lsb_extract():
            return None

        n_bits = expr.bits
        if n_bits not in (32, 64):
            return None

        base = expr.base

        # Pattern: Extract(UnaryOp(Conv(N->128, x)), N@0) -> UnaryOp(x, fp=True)
        if isinstance(base, UnaryOp) and base.operand.bits > n_bits:
            operand = _unwrap_conv_or_extract(base.operand, n_bits)
            if operand is not base.operand:
                return UnaryOp(
                    expr.idx,
                    base.op,
                    operand,
                    floating_point=True,
                    bits=n_bits,
                    **expr.tags,
                )
            return None

        # Pattern: Extract(BinaryOp("XxxV", ..., fp=True), N@0) -> scalar op
        if not isinstance(base, BinaryOp):
            return None

        scalar_op = _V_TO_SCALAR.get(base.op)
        if scalar_op is None:
            return None

        if not base.floating_point:
            return None

        if len(base.operands) != 2:
            return None

        a = _unwrap_conv_or_extract(base.operands[0], n_bits)
        b = _unwrap_conv_or_extract(base.operands[1], n_bits)

        return BinaryOp(
            expr.idx,
            scalar_op,
            [a, b],
            False,
            floating_point=True,
            bits=n_bits,
            **expr.tags,
        )
