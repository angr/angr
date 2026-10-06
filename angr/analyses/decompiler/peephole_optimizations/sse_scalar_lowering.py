from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Convert, Extract, UnaryOp
from angr.ailment.utils import is_lsb_extract

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
#
# Lane-wise conversions (cvtdq2ps, cvtps2dq, cvtps2pd, ...) used on a scalar
# that was widened into lane 0 (movd/movss) are lowered the same way:
#
#   Extract(ConvV(a128), N@0)            ->  Convert(a_lane0)
#   ConvV(Conv(N->128I, x))              ->  Conv(M->128I, Convert(N->M, x))
#
# The second form is bit-exact because every supported conversion maps an
# all-zero lane to an all-zero lane.

_V_TO_SCALAR: dict[str, str] = {
    "AddV": "Add",
    "SubV": "Sub",
    "MulV": "Mul",
    "DivV": "Div",
    "MaxV": "MaxF",
    "MinV": "MinF",
}


def _unwrap_conv_or_extract(operand, n_bits: int, manager):
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
    zero = Const(manager.next_atom(), 0, 64, **tags)
    return Extract(manager.next_atom(), n_bits, operand, zero, "Iend_LE", **tags)


def _lane_widths(conv: Convert) -> tuple[int, int] | None:
    """(from_lane_bits, to_lane_bits) of a lane-wise Convert, or None if it is not one."""
    vc = conv.vector_count
    if vc is None or vc <= 0 or conv.from_bits % vc or conv.to_bits % vc:
        return None
    return conv.from_bits // vc, conv.to_bits // vc


def _scalar_convert(idx, conv: Convert, from_lane: int, to_lane: int, operand, tags) -> Convert:
    return Convert(
        idx,
        from_lane,
        to_lane,
        conv.is_signed,
        operand,
        from_type=conv.from_type,
        to_type=conv.to_type,
        rounding_mode=conv.rounding_mode,
        **tags,
    )


class SSEVectorConvertLowering(PeepholeOptimizationExprBase):
    """Lower a lane-wise conversion of a scalar that was zero-widened into lane 0.

    ConvV(Conv(N->128I, x)) -> Conv(M->128I, Convert(N->M, x)); upper lanes stay zero.
    """

    __slots__ = ()

    NAME = "SSE lane-wise conversion of a widened scalar"
    expr_classes = (Convert,)

    def optimize(self, expr: Convert, **kwargs):
        lanes = _lane_widths(expr)
        if lanes is None:
            return None
        from_lane, to_lane = lanes
        inner = expr.operand
        if not (
            isinstance(inner, Convert)
            and inner.vector_count is None
            and inner.from_type == Convert.TYPE_INT
            and inner.to_type == Convert.TYPE_INT
            and not inner.is_signed
            and inner.from_bits == from_lane
            and inner.to_bits == expr.from_bits
        ):
            return None
        scalar = _scalar_convert(None, expr, from_lane, to_lane, inner.operand, expr.tags)
        return Convert(
            expr.idx,
            to_lane,
            expr.to_bits,
            False,
            scalar,
            from_type=Convert.TYPE_INT,
            to_type=Convert.TYPE_INT,
            **expr.tags,
        )


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
        if not is_lsb_extract(expr):
            return None

        n_bits = expr.bits

        # Lane-0 junk cleanup: an SSE scalar read of a value that was widened into a vector and OR'd with
        # upper-lane garbage (from a masked xorps/andps, or a spilled V128) leaves
        #   Extract(N@0, Or(Conv(k->m, x), upper_junk))
        # where the junk's low N bits are 0. The scalar value is just the low N bits of x.
        stripped = _strip_lane0(expr.base, n_bits)
        if stripped is not None:
            if stripped.bits == n_bits:
                return stripped
            zero = Const(self.manager.next_atom(), 0, 64, **expr.tags)
            return Extract(expr.idx, n_bits, stripped, zero, "Iend_LE", **expr.tags)

        base = expr.base

        # Pattern: Extract(ConvV(a), N@0) with N == lane width -> scalar Convert of lane 0
        if isinstance(base, Convert):
            lanes = _lane_widths(base)
            if lanes is None or lanes[1] != n_bits:
                return None
            from_lane, _ = lanes
            return _scalar_convert(
                expr.idx,
                base,
                from_lane,
                n_bits,
                _unwrap_conv_or_extract(base.operand, from_lane, self.manager),
                expr.tags,
            )

        if n_bits not in (32, 64):
            return None

        # Pattern: Extract(UnaryOp(Conv(N->128, x)), N@0) -> UnaryOp(x, fp=True)
        if isinstance(base, UnaryOp) and base.operand.bits > n_bits:
            operand = _unwrap_conv_or_extract(base.operand, n_bits, self.manager)
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

        a = _unwrap_conv_or_extract(base.operands[0], n_bits, self.manager)
        b = _unwrap_conv_or_extract(base.operands[1], n_bits, self.manager)

        return BinaryOp(
            expr.idx,
            scalar_op,
            [a, b],
            False,
            floating_point=True,
            bits=n_bits,
            **expr.tags,
        )


def _strip_lane0(expr, n_bits: int):
    """Return the value producing the low *n_bits* of *expr*, stripping wrappers that do not affect those
    bits: widening integer Converts, nested lsb Extracts, Or with a constant whose low n_bits are 0, and Concat.
    Returns None if no simplification applies."""
    changed = False
    for _ in range(8):
        if (
            isinstance(expr, Convert)
            and expr.from_type == expr.to_type == Convert.TYPE_INT
            and expr.to_bits > expr.from_bits
            and expr.from_bits >= n_bits
        ):
            expr = expr.operand
            changed = True
        elif (
            isinstance(expr, Extract)
            and isinstance(expr.offset, Const)
            and expr.offset.value == 0
            and expr.bits >= n_bits
        ):
            expr = expr.base
            changed = True
        elif (
            isinstance(expr, BinaryOp)
            and expr.op == "Or"
            and isinstance(expr.operands[1], Const)
            and isinstance(expr.operands[1].value, int)
            and (expr.operands[1].value & ((1 << n_bits) - 1)) == 0
        ):
            expr = expr.operands[0]
            changed = True
        elif isinstance(expr, BinaryOp) and expr.op == "Concat" and expr.operands[1].bits >= n_bits:
            # the low lanes of a Concat (unpckhpd/unpcklpd lane duplication) are its second operand
            expr = expr.operands[1]
            changed = True
        else:
            break
    return expr if changed else None
