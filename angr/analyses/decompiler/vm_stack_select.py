"""
A devirtualized VM branches by loading one of two stack slots through a computed offset:

    slot0 = A; slot1 = B; ...; x = *(S + &slot0)        with S in {0, d}, slot1 at slot0 + d

The load names no single slot, so SSA keeps slot1's definition without a use (and removes it) and nothing folds
through the selection. Rewritten as ``x = S == 0 ? slot0 : slot1`` it reads both slot variables.
"""

from __future__ import annotations

import networkx

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import ITE, BinaryOp, Const, Expression, Load, UnaryOp, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, NoOp, Store

from .peephole_optimizations.known_bits import known_bits

_MAX_DEPTH = 8


class _HasCall(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.found = True


def _may_write_memory(stmt) -> bool:
    if isinstance(stmt, Store):
        return True
    if isinstance(stmt, (Assignment, Label, Jump, ConditionalJump, NoOp)):
        viewer = _HasCall()
        viewer.walk_statement(stmt)
        return viewer.found
    # calls, CAS, dirty statements, ...
    return True


class _BlockSelectFolder:
    def __init__(self, block: Block, ail_manager):
        self.block = block
        self.manager = ail_manager
        # varid -> (statement index, source) of the block's vvar definitions
        self.defs: dict[int, tuple[int, Expression]] = {}
        for idx, stmt in enumerate(block.statements):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                self.defs[stmt.dst.varid] = (idx, stmt.src)

    def _src(self, expr: Expression, before: int) -> Expression | None:
        if isinstance(expr, VirtualVariable):
            d = self.defs.get(expr.varid)
            if d is not None and d[0] < before:
                return d[1]
        return None

    def _resolve(self, expr: Expression, before: int) -> Expression:
        for _ in range(_MAX_DEPTH):
            src = self._src(expr, before)
            if src is None or src.bits != expr.bits:
                break
            expr = src
        return expr

    def _known_bits(self, expr: Expression, before: int):
        def resolve(vvar: VirtualVariable, depth: int):
            src = self._src(vvar, before)
            if src is None or src.bits != vvar.bits:
                return 0, 0
            return known_bits(src, resolve, depth)

        return known_bits(expr, resolve)

    def _slot_def(self, offset: int, size: int, before: int) -> tuple[int, VirtualVariable] | None:
        """The block's last definition of exactly this stack slot before ``before``, if no other write follows it."""
        for idx in range(before - 1, -1, -1):
            stmt = self.block.statements[idx]
            if _may_write_memory(stmt):
                return None
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                dst = stmt.dst
                lo, hi = dst.stack_offset, dst.stack_offset + dst.size
                if lo == offset and dst.size == size:
                    return idx, dst
                if lo < offset + size and offset < hi:
                    # a partial overlap: the slot holds a mix
                    return None
        return None

    def fold(self, load: Load, stmt_idx: int) -> Expression | None:
        if load.guard is not None or load.endness != "Iend_LE":
            return None
        addr = self._resolve(load.addr, stmt_idx)
        if not (isinstance(addr, BinaryOp) and addr.op == "Add" and len(addr.operands) == 2):
            return None
        for sel, ref in (addr.operands, addr.operands[::-1]):
            ref = self._resolve(ref, stmt_idx)
            if (
                isinstance(ref, UnaryOp)
                and ref.op == "Reference"
                and isinstance(ref.operand, VirtualVariable)
                and ref.operand.was_stack
            ):
                break
        else:
            return None
        zeros, ones = self._known_bits(sel, stmt_idx)
        delta = ((1 << sel.bits) - 1) & ~zeros
        # sel is 0 or delta
        if ones or not delta or delta & (delta - 1):
            return None
        offset = ref.operand.stack_offset
        slots = [self._slot_def(offset, load.size, stmt_idx), self._slot_def(offset + delta, load.size, stmt_idx)]
        if None in slots or any(v.bits != load.bits for _, v in slots):
            return None
        reads = [
            VirtualVariable(self.manager.next_atom(), v.varid, v.bits, category=v.category, oident=v.oident, **v.tags)
            for _, v in slots
        ]
        cond = BinaryOp(
            self.manager.next_atom(), "CmpEQ", [sel, Const(self.manager.next_atom(), 0, sel.bits)], False, bits=1
        )
        return ITE(load.idx, cond, reads[0], reads[1], **load.tags)


def fold_stack_select_loads(graph: networkx.DiGraph, ail_manager) -> int:
    """Rewrite two-slot stack selections into ITEs in place. Returns the number of loads rewritten."""
    count = 0

    for block in list(graph):
        folder = _BlockSelectFolder(block, ail_manager)

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)
                self.count = 0

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
                repl = folder.fold(rebuilt if rebuilt is not None else expr, stmt_idx)
                if repl is None:
                    return rebuilt
                self.count += 1
                return repl

        rewriter = _Rewriter()
        new_block = rewriter.walk(block)
        if rewriter.count and new_block is not None:
            block.statements = list(new_block.statements)
            count += rewriter.count
    return count
