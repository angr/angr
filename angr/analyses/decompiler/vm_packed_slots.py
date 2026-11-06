"""
Forward reads of packed VM operand-stack slots to the values written into them.

VMProtect's 32-bit handlers push two dwords and read them back as one qword (NOR, AND, ...), or push the stack pointer
and read a dword through it. Stack SSA unifies such overlapping accesses into one aggregate variable, written by Insert
chains and read by Extracts at other offsets:

    v1 = Insert(Insert(Insert(0, 0, flags), 4, a), 8, a)
    v2 = Insert(v1, 4, Extract(v1, 32bits@8))
    ... (Extract(~Extract(v2, 64bits@4), 32bits@4) & ~Extract(Extract(v2, 64bits@4), 32bits@0)) ...

SPropagator never propagates an Insert definition, so the operands of the VM's boolean operation never meet and the
dead flag words in the slot stay alive. This pass rewrites each such read to the bits of the definition it reads,
recursively through the definitions of the variables it reaches (``~a & ~a`` above). It stops at a definition whose
bits are, or contain, a load, a call, a dirty expression or a tmp: moving those to the read would change what they
read or how often they run. Rewriting a read of an SSA variable to the expression that defined it is otherwise
value-preserving wherever the read is.
"""

from __future__ import annotations

import logging

import archinfo
import networkx

from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Phi,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment

from .ailgraph_walker import AILGraphWalker
from .peephole_optimizations.known_bits import known_bits

l = logging.getLogger(name=__name__)

_MAX_DEPTH = 40
# reads wider than a register are struct copies; their pieces are not what this pass is about
_MAX_READ_BITS = 64


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def _const_int(expr: Expression) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value_int
    return None


def _le_shift(offset: Expression, endness, outer_bits: int, inner_bits: int) -> int | None:
    """Bit position of a little-endian Insert/Extract at a constant byte offset."""
    if not (isinstance(offset, Const) and isinstance(offset.value, int)) or endness != archinfo.Endness.LE:
        return None
    shift = offset.value * 8
    if shift < 0 or shift + inner_bits > outer_bits:
        return None
    return shift


def _is_int_convert(expr: Expression) -> bool:
    return isinstance(expr, Convert) and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT


class _Unmovable(AILBlockViewer):
    """Whether an expression reads memory, has side effects or depends on block-local tmps."""

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Load(self, *args, **kwargs):
        self.found = True

    def _handle_Call(self, *args, **kwargs):
        self.found = True

    def _handle_DirtyExpression(self, *args, **kwargs):
        self.found = True

    def _handle_Tmp(self, *args, **kwargs):
        self.found = True


def _unmovable(expr: Expression) -> bool:
    viewer = _Unmovable()
    viewer.walk_expression(expr)
    return viewer.found


class _BitSlicer:
    """Expressions for bit ranges of a value, looking through stack-variable definitions."""

    def __init__(self, defs: dict[int, Expression]):
        self.defs = defs

    @staticmethod
    def _leaf(expr: Expression, shift: int, width: int) -> Expression:
        if shift == 0 and width == expr.bits:
            return expr
        if (isinstance(expr, VirtualVariable) or expr.bits > 64) and shift % 8 == 0:
            return Extract(None, width, expr, Const(None, shift // 8, 64), archinfo.Endness.LE)
        if shift:
            expr = BinaryOp(None, "Shr", [expr, Const(None, shift, 8)], False, bits=expr.bits)
        return Convert(None, expr.bits, width, False, expr)

    def part(self, expr: Expression, shift: int, width: int, depth: int = 0) -> tuple[Expression, bool]:
        """
        Bits [shift, shift + width) of ``expr``, and whether it was decomposed structurally (False: only wrapped in an
        Extract or Convert).
        """
        if depth > _MAX_DEPTH:
            return self._leaf(expr, shift, width), False
        c = _const_int(expr)
        if c is not None:
            return Const(None, (c >> shift) & _mask(width), width), True
        if isinstance(expr, VirtualVariable):
            return self._part_vvar(expr, shift, width, depth)
        if shift == 0 and width == expr.bits:
            return expr, True
        if expr.bits <= 64:
            zeros, ones = known_bits(expr)
            hole = _mask(width) << shift
            if (zeros | ones) & hole == hole:
                return Const(None, (ones >> shift) & _mask(width), width), True

        if isinstance(expr, Insert):
            r = self._part_insert(expr, shift, width, depth)
            if r is not None:
                return r, True
        elif isinstance(expr, Extract):
            s = _le_shift(expr.offset, expr.endness, expr.base.bits, expr.bits)
            if s is not None:
                return self.part(expr.base, s + shift, width, depth + 1)[0], True
        elif _is_int_convert(expr):
            if shift + width <= min(expr.from_bits, expr.to_bits):
                return self.part(expr.operand, shift, width, depth + 1)[0], True
            if expr.to_bits > expr.from_bits and not expr.is_signed and shift >= expr.from_bits:
                return Const(None, 0, width), True
        elif isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" and expr.operand.bits == expr.bits:
            inner, exact = self.part(expr.operand, shift, width, depth + 1)
            if exact:
                return UnaryOp(None, "BitwiseNeg", inner, bits=width), True
        elif isinstance(expr, BinaryOp) and not expr.floating_point and len(expr.operands) == 2:
            r = self._part_binop(expr, shift, width, depth)
            if r is not None:
                return r, True
        return self._leaf(expr, shift, width), False

    def _part_vvar(self, vvar: VirtualVariable, shift: int, width: int, depth: int) -> tuple[Expression, bool]:
        src = self.defs.get(vvar.varid) if vvar.was_stack else None
        if src is not None and src.bits == vvar.bits:
            out, _ = self.part(src, shift, width, depth + 1)
            if not _unmovable(out):
                return out, True
            # the bits are a load or a call result: read this version of the slot instead
            return self._leaf(vvar, shift, width), True
        return self._leaf(vvar, shift, width), shift == 0 and width == vvar.bits

    def _part_insert(self, expr: Insert, shift: int, width: int, depth: int) -> Expression | None:
        s = _le_shift(expr.offset, expr.endness, expr.bits, expr.value.bits)
        if s is None:
            return None
        end = s + expr.value.bits
        if s <= shift and shift + width <= end:
            return self.part(expr.value, shift - s, width, depth + 1)[0]
        if shift + width <= s or end <= shift:
            return self.part(expr.base, shift, width, depth + 1)[0]
        # the read straddles the inserted value: concatenate the pieces on each side of its boundaries
        cuts = sorted({shift, shift + width, *(x for x in (s, end) if shift < x < shift + width)})
        out = None
        for lo, hi in zip(cuts, cuts[1:]):
            piece = self.part(expr, lo, hi - lo, depth + 1)[0]
            out = piece if out is None else BinaryOp(None, "Concat", [piece, out], False, bits=piece.bits + out.bits)
        return out

    def _part_binop(self, expr: BinaryOp, shift: int, width: int, depth: int) -> Expression | None:
        a, b = expr.operands
        amount = _const_int(b)
        op = expr.op
        if op == "Mul" and amount is not None and amount > 0 and amount & (amount - 1) == 0:
            op, amount = "Shl", amount.bit_length() - 1
        if op in {"And", "Or", "Xor"} and a.bits == b.bits == expr.bits:
            pa, ea = self.part(a, shift, width, depth + 1)
            pb, eb = self.part(b, shift, width, depth + 1)
            if ea or eb:
                return BinaryOp(None, op, [pa, pb], False, bits=width)
        elif op == "Concat":
            low = b.bits
            if shift + width <= low:
                return self.part(b, shift, width, depth + 1)[0]
            if shift >= low:
                return self.part(a, shift - low, width, depth + 1)[0]
            lo_part = self.part(b, shift, low - shift, depth + 1)[0]
            hi_part = self.part(a, 0, shift + width - low, depth + 1)[0]
            return BinaryOp(None, "Concat", [hi_part, lo_part], False, bits=width)
        elif op == "Shl" and amount is not None and a.bits == expr.bits:
            if shift + width <= amount:
                return Const(None, 0, width)
            if shift >= amount:
                return self.part(a, shift - amount, width, depth + 1)[0]
        elif op == "Shr" and amount is not None and a.bits == expr.bits and shift + amount + width <= expr.bits:
            return self.part(a, shift + amount, width, depth + 1)[0]
        return None


def _read_of_part(expr: Expression) -> tuple[Expression, int, int] | None:
    """(value, shift, width) if ``expr`` reads bits of a wider value."""
    if isinstance(expr, Extract):
        s = _le_shift(expr.offset, expr.endness, expr.base.bits, expr.bits)
        if s is not None:
            return expr.base, s, expr.bits
    elif _is_int_convert(expr) and expr.to_bits < expr.from_bits:
        return expr.operand, 0, expr.to_bits
    return None


class _ReadRewriter(AILBlockRewriter):
    def __init__(self, slicer: _BitSlicer):
        super().__init__(update_block=False)
        self.slicer = slicer
        self.rewritten = 0

    def _forward(self, expr: Expression) -> Expression | None:
        read = _read_of_part(expr)
        if read is None:
            return None
        base, shift, width = read
        if width > _MAX_READ_BITS:
            return None
        if isinstance(base, VirtualVariable):
            if not base.was_stack or base.varid not in self.slicer.defs:
                return None
        elif not isinstance(base, (Insert, BinaryOp, UnaryOp, Extract)):
            return None
        out, exact = self.slicer.part(base, shift, width)
        if not exact or out.likes(expr):
            return None
        self.rewritten += 1
        return out

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        out = self._forward(expr)
        if out is not None:
            return out
        return super()._handle_Extract(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        out = self._forward(expr)
        if out is not None:
            return out
        return super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)


def forward_packed_slot_reads(ail_graph: networkx.DiGraph) -> int:
    """Rewrite partial reads of stack variables in ``ail_graph`` in place. Returns the number of reads rewritten."""
    defs: dict[int, Expression] = {}
    for block in ail_graph:
        for stmt in block.statements:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and not isinstance(stmt.src, Phi)
            ):
                defs[stmt.dst.varid] = stmt.src
    if not defs:
        return 0
    slicer = _BitSlicer(defs)
    replacements = {}
    total = 0
    for block in list(ail_graph):
        rewriter = _ReadRewriter(slicer)
        new_block = rewriter.walk(block)
        if rewriter.rewritten and new_block is not block:
            replacements[block] = new_block
            total += rewriter.rewritten
    if replacements:
        AILGraphWalker(ail_graph, replacements.get, replace_nodes=True).walk()
    l.debug("forward_packed_slot_reads: %d reads rewritten", total)
    return total
