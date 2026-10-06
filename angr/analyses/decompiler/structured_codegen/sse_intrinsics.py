"""
Intel-intrinsics view of 128-bit SSE vector AIL: lane kinds of variables, ``_mm_*`` names of lane-wise ops, and the
``pshufd`` lane shuffles that VEX spells out as CONCAT trees of 32-bit lane extractions.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Literal, TypeGuard

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp
from angr.ailment.manager import Manager
from angr.ailment.statement import Assignment, Statement, Store
from angr.analyses.decompiler.peephole_optimizations.sse_vector_lane_lowering import lower_lane0
from angr.sim_variable import SimVariable

LaneKind = Literal["int", "float", "double"]

VECTOR_BITS = 128

# (AIL op, lane bits, signed or None for either) -> (intrinsic, swap operands)
_INT_INTRINSICS: dict[tuple[str, int, bool | None], tuple[str, bool]] = {}
for _lane in (8, 16, 32, 64):
    _INT_INTRINSICS[("AddV", _lane, None)] = (f"_mm_add_epi{_lane}", False)
    _INT_INTRINSICS[("SubV", _lane, None)] = (f"_mm_sub_epi{_lane}", False)
    _INT_INTRINSICS[("CmpEQV", _lane, None)] = (f"_mm_cmpeq_epi{_lane}", False)
    _INT_INTRINSICS[("CmpGTV", _lane, True)] = (f"_mm_cmpgt_epi{_lane}", False)
    # VEX InterleaveLO(a, b) puts b in the even lanes; punpckl(a, b) puts a there
    _INT_INTRINSICS[("InterleaveLOV", _lane, None)] = (f"_mm_unpacklo_epi{_lane}", True)
    _INT_INTRINSICS[("InterleaveHIV", _lane, None)] = (f"_mm_unpackhi_epi{_lane}", True)
for _lane in (8, 16, 32):
    _INT_INTRINSICS[("CmpLTV", _lane, True)] = (f"_mm_cmplt_epi{_lane}", False)
    _INT_INTRINSICS[("MaxV", _lane, True)] = (f"_mm_max_epi{_lane}", False)
    _INT_INTRINSICS[("MaxV", _lane, False)] = (f"_mm_max_epu{_lane}", False)
    _INT_INTRINSICS[("MinV", _lane, True)] = (f"_mm_min_epi{_lane}", False)
    _INT_INTRINSICS[("MinV", _lane, False)] = (f"_mm_min_epu{_lane}", False)
for _lane in (8, 16):
    _INT_INTRINSICS[("QAddV", _lane, True)] = (f"_mm_adds_epi{_lane}", False)
    _INT_INTRINSICS[("QAddV", _lane, False)] = (f"_mm_adds_epu{_lane}", False)
    _INT_INTRINSICS[("QSubV", _lane, True)] = (f"_mm_subs_epi{_lane}", False)
    _INT_INTRINSICS[("QSubV", _lane, False)] = (f"_mm_subs_epu{_lane}", False)
for _lane in (16, 32, 64):
    _INT_INTRINSICS[("ShlNV", _lane, None)] = (f"_mm_slli_epi{_lane}", False)
    _INT_INTRINSICS[("ShrNV", _lane, None)] = (f"_mm_srli_epi{_lane}", False)
for _lane in (16, 32):
    _INT_INTRINSICS[("SarNV", _lane, None)] = (f"_mm_srai_epi{_lane}", False)
    _INT_INTRINSICS[("MulV", _lane, None)] = (f"_mm_mullo_epi{_lane}", False)
_INT_INTRINSICS[("MulHiV", 16, True)] = ("_mm_mulhi_epi16", False)
_INT_INTRINSICS[("MulHiV", 16, False)] = ("_mm_mulhi_epu16", False)
# QNarrowBin's lane is the narrowed one; VEX puts its first operand in the high half, packs puts it in the low half
_INT_INTRINSICS[("QNarrowBinV", 8, True)] = ("_mm_packs_epi16", True)
_INT_INTRINSICS[("QNarrowBinV", 8, False)] = ("_mm_packus_epi16", True)
_INT_INTRINSICS[("QNarrowBinV", 16, True)] = ("_mm_packs_epi32", True)
_INT_INTRINSICS[("QNarrowBinV", 16, False)] = ("_mm_packus_epi32", True)

_FP_INTRINSICS: dict[str, str] = {
    "AddV": "add",
    "SubV": "sub",
    "MulV": "mul",
    "DivV": "div",
    "MaxV": "max",
    "MinV": "min",
    "CmpEQV": "cmpeq",
    "CmpLTV": "cmplt",
    "CmpLEV": "cmple",
    "CmpUNV": "cmpunord",
}

# suffix of the bitwise intrinsics and the lane suffix of FP intrinsics, per lane kind
BITWISE_SUFFIX: dict[LaneKind, str] = {"int": "si128", "float": "ps", "double": "pd"}
_FP_SUFFIX: dict[int, str] = {32: "ps", 64: "pd"}
_BITWISE_OPS: dict[str, str] = {"And": "and", "Or": "or", "Xor": "xor"}


def is_vector_op(expr: Expression) -> TypeGuard[BinaryOp]:
    """A lane-wise BinaryOp over a full 128-bit vector."""
    return (
        isinstance(expr, BinaryOp)
        and expr.vector_count is not None
        and expr.vector_size is not None
        and expr.op.endswith("V")
        and expr.bits == VECTOR_BITS
        and expr.vector_count * expr.vector_size == VECTOR_BITS
    )


def vector_op_kind(expr: BinaryOp) -> LaneKind:
    if expr.floating_point:
        return "float" if expr.vector_size == 32 else "double"
    return "int"


def vector_op_intrinsic(expr: BinaryOp) -> tuple[str, bool, int] | None:
    """
    (intrinsic name, swap operands, operand lane bits) of a lane-wise op, or None when no intrinsic matches exactly.
    """
    lane = expr.vector_size
    assert lane is not None
    if expr.floating_point:
        name = _FP_INTRINSICS.get(expr.op)
        sfx = _FP_SUFFIX.get(lane)
        if name is None or sfx is None:
            return None
        return f"_mm_{name}_{sfx}", False, lane
    entry = _INT_INTRINSICS.get((expr.op, lane, expr.signed)) or _INT_INTRINSICS.get((expr.op, lane, None))
    if entry is None:
        return None
    name, swap = entry
    return name, swap, lane * 2 if expr.op == "QNarrowBinV" else lane


def lane_of(expr: Expression, lane_bits: int, any_offset: bool = False) -> tuple[Expression, int] | None:
    """
    (vector, bit offset) when *expr* reads one *lane_bits*-wide, lane-aligned lane of a 128-bit vector through
    truncations and logical right shifts, e.g. ``(uint32_t)((uint64_t)v >> 32)`` is lane 1 of v. With *any_offset*,
    *expr* may be wider than the lane, and the offset need not be lane-aligned.
    """
    if expr.bits != lane_bits and not any_offset:
        return None
    off = 0
    e = expr
    while True:
        if (
            isinstance(e, Convert)
            and e.vector_count is None
            and e.from_type == e.to_type == Convert.TYPE_INT
            and e.to_bits < e.from_bits
        ):
            if off + lane_bits > e.to_bits:
                return None
            e = e.operand
        elif (
            isinstance(e, BinaryOp)
            and e.op == "Shr"
            and isinstance(e.operands[1], Const)
            and isinstance(e.operands[1].value, int)
        ):
            off += e.operands[1].value
            e = e.operands[0]
        else:
            break
    if (e is expr and not any_offset) or e.bits != VECTOR_BITS:
        return None
    if not any_offset and (off % lane_bits or off + lane_bits > VECTOR_BITS):
        return None
    return e, off


def _concat_pieces(expr: Expression, out: list[Expression]) -> None:
    # high to low
    if isinstance(expr, BinaryOp) and expr.op == "Concat":
        _concat_pieces(expr.operands[0], out)
        _concat_pieces(expr.operands[1], out)
    else:
        out.append(expr)


def concat_constant(expr: BinaryOp) -> int | None:
    """The value of a Concat tree of integer constants, or None."""
    pieces: list[Expression] = []
    _concat_pieces(expr, pieces)
    value = 0
    for p in pieces:
        if not isinstance(p, Const) or not isinstance(p.value, int):
            return None
        value = (value << p.bits) | (p.value & ((1 << p.bits) - 1))
    return value


def match_shuffle_epi32(expr: BinaryOp) -> tuple[Expression, int] | None:
    """
    (vector, imm8) when a 128-bit Concat tree picks the four 32-bit lanes of one vector: pshufd.
    """
    pieces: list[Expression] = []
    _concat_pieces(expr, pieces)
    lanes: list[tuple[Expression, int] | None] = []  # high to low, 32-bit lanes
    for p in pieces:
        if p.bits == 32:
            lanes.append(lane_of(p, 32))
        elif p.bits == 64:
            r = lane_of(p, 64)
            if r is None:
                return None
            lanes += [(r[0], r[1] + 32), r]
        else:
            return None
    if len(lanes) != 4:
        return None
    bases = [r[0] for r in lanes if r is not None]
    if not bases:
        return None
    base = bases[0]
    if any(not b.likes(base) for b in bases[1:]):
        return None
    if any(r is None for r in lanes):
        # SSEVectorLaneLowering turns a lane-0 read of a lane-wise op into the scalar op
        if not is_vector_op(base) or base.vector_size != 32 or len(pieces) != 4:
            return None
        lowered = lower_lane0(base, Manager())
        if lowered is None:
            return None
        for i, r in enumerate(lanes):
            if r is None:
                if not lowered.likes(pieces[i]):
                    return None
                lanes[i] = (base, 0)
    imm = 0
    for i, r in enumerate(reversed(lanes)):
        assert r is not None
        imm |= (r[1] // 32) << (2 * i)
    return base, imm


class _VectorExprCollector(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.exprs: list[BinaryOp | UnaryOp] = []

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.bits == VECTOR_BITS:
            self.exprs.append(expr)
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.bits == VECTOR_BITS and expr.op == "Not":
            self.exprs.append(expr)
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


class SSEVectorTyping:
    """
    Lane kinds of 128-bit variables: seeded by the lane-wise ops that read or write them and propagated through copies
    and full-width bitwise ops.

    :param variable_key:    Maps an AIL expression to the (unified) variable it denotes, or None.
    :param eligible:        Whether a variable may be retyped as a vector (its current type is a 128-bit integer).
    """

    def __init__(
        self,
        variable_key: Callable[[Expression | Statement], SimVariable | None],
        eligible: Callable[[SimVariable], bool],
    ):
        self._variable_key = variable_key
        self._eligible = eligible
        self.kinds: dict[SimVariable, LaneKind] = {}

    def kind(self, expr: Expression) -> LaneKind | None:
        """The lane kind of a 128-bit expression, or None if it does not look like a vector."""
        if expr.bits != VECTOR_BITS:
            return None
        if isinstance(expr, BinaryOp):
            if is_vector_op(expr):
                return vector_op_kind(expr)
            if expr.op in _BITWISE_OPS:
                return self.kind(expr.operands[0]) or self.kind(expr.operands[1])
            if expr.op in {"Shl", "Shr"} and isinstance(expr.operands[1], Const):
                return self.kind(expr.operands[0])
            if expr.op == "Concat":
                shuffle = match_shuffle_epi32(expr)
                return self.kind(shuffle[0]) if shuffle is not None else None
        elif isinstance(expr, UnaryOp) and expr.op == "Not":
            return self.kind(expr.operand)
        elif isinstance(expr, Convert) and expr.vector_count is not None:
            if expr.to_type == Convert.TYPE_FP:
                return "float" if expr.to_bits // expr.vector_count == 32 else "double"
            return "int"
        var = self._variable_key(expr)
        return self.kinds.get(var) if var is not None else None

    def _set(self, expr: Expression | Statement, kind: LaneKind) -> bool:
        var = self._variable_key(expr)
        if var is None or var in self.kinds or not self._eligible(var):
            return False
        self.kinds[var] = kind
        return True

    def collect(self, blocks: Iterable[Block]) -> None:
        copies: list[tuple[Expression | Statement, Expression]] = []
        collector = _VectorExprCollector()
        for block in blocks:
            collector.walk(block)
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and stmt.src.bits == VECTOR_BITS:
                    copies.append((stmt.dst, stmt.src))
                elif isinstance(stmt, Store) and stmt.data.bits == VECTOR_BITS:
                    copies.append((stmt, stmt.data))

        for expr in collector.exprs:
            if isinstance(expr, BinaryOp) and is_vector_op(expr):
                kind = vector_op_kind(expr)
                for operand in expr.operands:
                    if operand.bits == VECTOR_BITS:
                        self._set(operand, kind)
            elif isinstance(expr, BinaryOp) and expr.op == "Concat":
                shuffle = match_shuffle_epi32(expr)
                if shuffle is not None:
                    self._set(shuffle[0], "int")

        changed = True
        while changed:
            changed = False
            for dst, src in copies:
                kind = self.kind(src)
                if kind is not None:
                    changed |= self._set(dst, kind)
                else:
                    dst_var = self._variable_key(dst)
                    dst_kind = self.kinds.get(dst_var) if dst_var is not None else None
                    if dst_kind is not None:
                        changed |= self._set(src, dst_kind)
            for expr in collector.exprs:
                if isinstance(expr, BinaryOp) and expr.op not in _BITWISE_OPS:
                    continue
                kind = self.kind(expr)
                if kind is not None:
                    operands = expr.operands if isinstance(expr, BinaryOp) else [expr.operand]
                    for operand in operands:
                        changed |= self._set(operand, kind)

        if self.kinds:
            # alongside vector code, a 128-bit variable that only ever holds constants is a vector constant (a spilled
            # movaps of a literal pool entry)
            const_only: dict[SimVariable, bool] = {}
            for dst, src in copies:
                var = self._variable_key(dst)
                if var is not None:
                    const_only[var] = const_only.get(var, True) and isinstance(src, Const)
            for dst, src in copies:
                var = self._variable_key(dst)
                if var is not None and const_only[var]:
                    self._set(dst, "int")
