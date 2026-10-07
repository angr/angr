from __future__ import annotations

from angr.ailment.expression import ITE, BinaryOp, Const, Convert, Expression, Extract
from angr.ailment.manager import Manager
from angr.ailment.utils import is_lsb_extract

from .base import PeepholeOptimizationExprBase

# Lane-wise SSE ops reach AIL as BinaryOp("XxxV", vector_count=k, vector_size=L). When only the lowest lane is read
# (an lsb Extract or a truncating Convert of at most L bits), the op collapses to its scalar form on lane 0:
#
#   Extract(ShrNV(x, 52), 16@0)        ->  Extract(Shr(lane0(x), 52), 16@0)      (psrlq + pextrw: exponent bits)
#   Conv(128->64, SubV(a, b))          ->  Sub(lane0(a), lane0(b))               (psubq)
#   Extract(CmpEQV(a, b), 64@0)        ->  ITE(lane0(a) == lane0(b), -1, 0)      (pcmpeqq / cmpeqsd)
#   Extract(ConvV(32->s32Fx4, x), 32@0) ->  Conv(32->s32F, lane0(x))             (movd + cvtdq2ps)

_SHIFT_OPS: dict[str, str] = {"ShlN": "Shl", "ShrN": "Shr", "SarN": "Sar"}
_ARITH_OPS: frozenset[str] = frozenset({"Add", "Sub", "Mul", "Div"})
_FP_MINMAX_OPS: dict[str, str] = {"Max": "MaxF", "Min": "MinF"}
_CMP_OPS: frozenset[str] = frozenset({"CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"})


def lane0(expr: Expression, lane_bits: int, manager: Manager) -> Expression:
    """The lowest *lane_bits* bits of a vector operand."""
    if expr.bits == lane_bits:
        return expr
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return Const(expr.idx, expr.value & ((1 << lane_bits) - 1), lane_bits, **expr.tags)
    if (
        isinstance(expr, Convert)
        and expr.from_type == expr.to_type == Convert.TYPE_INT
        and expr.from_bits >= lane_bits
        and expr.to_bits > expr.from_bits
    ):
        return lane0(expr.operand, lane_bits, manager)
    if isinstance(expr, BinaryOp) and expr.op == "Concat" and expr.operands[1].bits >= lane_bits:
        return lane0(expr.operands[1], lane_bits, manager)
    if isinstance(expr, Extract) and is_lsb_extract(expr) and expr.bits >= lane_bits:
        return lane0(expr.base, lane_bits, manager)
    return Extract(manager.next_atom(), lane_bits, expr, Const(manager.next_atom(), 0, 64), "Iend_LE", **expr.tags)


def upper_lanes_zero(expr: Expression, lane_bits: int) -> bool:
    """True if every lane above lane 0 of *expr* is zero (a movd/movq zero-extension, or a lane-wise op that maps
    zero lanes to zero lanes)."""
    if (
        isinstance(expr, Convert)
        and expr.from_type == expr.to_type == Convert.TYPE_INT
        and not expr.is_signed
        and expr.from_bits <= lane_bits < expr.to_bits
    ):
        return True
    if isinstance(expr, Convert) and expr.vector_count is not None:
        # int<->fp conversions map 0 to 0 in every lane
        return upper_lanes_zero(expr.operand, expr.from_bits // expr.vector_count)
    if isinstance(expr, BinaryOp) and expr.vector_size is not None and expr.op[:-1] in _SHIFT_OPS:
        return upper_lanes_zero(expr.operands[0], expr.vector_size)
    return False


def lower_lane0(expr: BinaryOp | Convert, manager: Manager) -> Expression | None:
    """Lane 0 of a lane-wise vector op as a scalar expression of one lane's width, or None."""
    if isinstance(expr, Convert):
        count = expr.vector_count
        if count is None or expr.from_bits % count or expr.to_bits % count:
            return None
        from_lane, to_lane = expr.from_bits // count, expr.to_bits // count
        return Convert(
            expr.idx,
            from_lane,
            to_lane,
            expr.is_signed,
            lane0(expr.operand, from_lane, manager),
            from_type=expr.from_type,
            to_type=expr.to_type,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )

    lane = expr.vector_size
    if lane is None or expr.vector_count is None or not expr.op.endswith("V") or len(expr.operands) != 2:
        return None
    generic = expr.op[:-1]
    lhs, rhs = expr.operands

    if generic in _SHIFT_OPS:
        # the shift amount is a single 8-bit immediate shared by all lanes
        if rhs.bits > lane:
            return None
        return BinaryOp(
            expr.idx, _SHIFT_OPS[generic], [lane0(lhs, lane, manager), rhs], generic == "SarN", bits=lane, **expr.tags
        )

    if generic in _ARITH_OPS:
        return BinaryOp(
            expr.idx,
            generic,
            [lane0(lhs, lane, manager), lane0(rhs, lane, manager)],
            expr.signed,
            bits=lane,
            floating_point=expr.floating_point,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )

    if generic in _FP_MINMAX_OPS and expr.floating_point:
        return BinaryOp(
            expr.idx,
            _FP_MINMAX_OPS[generic],
            [lane0(lhs, lane, manager), lane0(rhs, lane, manager)],
            False,
            bits=lane,
            floating_point=True,
            **expr.tags,
        )

    if generic in _CMP_OPS:
        # a lane-wise compare fills the lane with all-ones when the condition holds
        cond = BinaryOp(
            manager.next_atom(),
            generic,
            [lane0(lhs, lane, manager), lane0(rhs, lane, manager)],
            expr.signed,
            bits=1,
            floating_point=expr.floating_point,
            **expr.tags,
        )
        ones = Const(manager.next_atom(), (1 << lane) - 1, lane)
        return ITE(expr.idx, cond, ones, Const(manager.next_atom(), 0, lane), **expr.tags)

    return None


class SSEVectorLaneLowering(PeepholeOptimizationExprBase):
    """Lower a lane-0 read of a lane-wise vector op to the scalar op on lane 0."""

    __slots__ = ()

    NAME = "SSE lane-0 reads of vector ops to scalar ops"
    expr_classes = (Extract, Convert)

    def optimize(self, expr: Extract | Convert, **kwargs):
        if isinstance(expr, Extract):
            if not is_lsb_extract(expr):
                return None
            base = expr.base
        else:
            if not (expr.from_type == expr.to_type == Convert.TYPE_INT and expr.to_bits < expr.from_bits):
                return None
            base = expr.operand
        n_bits = expr.bits
        if isinstance(base, BinaryOp):
            if base.vector_size is None:
                return None
            lane = base.vector_size
        elif isinstance(base, Convert) and base.vector_count is not None:
            lane = base.to_bits // base.vector_count
        else:
            return None
        if n_bits > lane and not upper_lanes_zero(base, lane):
            return None
        lowered = lower_lane0(base, self.manager)
        if lowered is None:
            return None
        if n_bits == lowered.bits:
            return lowered
        if n_bits > lowered.bits:
            # the read spans zero upper lanes: zero-extend the lane-0 result
            return Convert(expr.idx, lowered.bits, n_bits, False, lowered, **expr.tags)
        if isinstance(lowered, ITE) and isinstance(lowered.iftrue, Const) and isinstance(lowered.iffalse, Const):
            # a narrower read of a compare mask is still a compare mask
            mask = (1 << n_bits) - 1
            return ITE(
                expr.idx,
                lowered.cond,
                Const(self.manager.next_atom(), lowered.iftrue.value & mask, n_bits),
                Const(self.manager.next_atom(), lowered.iffalse.value & mask, n_bits),
                **expr.tags,
            )
        if isinstance(expr, Extract):
            return Extract(expr.idx, n_bits, lowered, expr.offset, expr.endness, **expr.tags)
        return Convert(expr.idx, lowered.bits, n_bits, expr.is_signed, lowered, **expr.tags)
