"""
Reuse a virtual variable that already holds a value instead of recomputing the value.

When the decompiler forwards a VM-context store into several loads, each load gets its own copy of the stored
expression, and later propagation inlines the copies to different depths: ``v1 = E; v2 = E + c`` next to
``... (v1 + c) ...``. Both spell the same value, but peephole rules see two different expressions, so identities
such as ``x + k - k`` stop folding and the VM state that ``k`` comes from stays alive. Rewriting ``E`` to ``v1``
wherever a definition ``v1 = E`` dominates restores one spelling per value (common subexpression elimination).

Only expressions over constants, virtual variables and stack addresses are reused, and only virtual variables
without a register or stack identity hold them, so that leaving SSA never merges the reused variable with a later
definition of the same register or slot.
"""

from __future__ import annotations

from collections import defaultdict

import networkx

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment


class _Subexpressions(AILBlockViewer):
    """Every expression of a statement, outermost first."""

    def __init__(self):
        super().__init__()
        self.exprs: list[Expression] = []

    def _handle_expr(self, expr_idx, expr, stmt_idx, stmt, block):
        self.exprs.append(expr)
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class _ValueKeys:
    """
    Structural value numbers of pure expressions: equal numbers for expressions that likes() each other. None for an
    expression that reads anything but constants, virtual variables and stack addresses.
    """

    def __init__(self):
        self._numbers: dict[tuple, int] = {}
        self._memo: dict[int, tuple[Expression, int | None]] = {}

    def of(self, expr) -> int | None:
        memo = self._memo.get(id(expr))
        if memo is not None and memo[0] is expr:
            return memo[1]
        key = self._key(expr)
        number = None if key is None else self._numbers.setdefault(key, len(self._numbers))
        # keep expr alive so that its id is not reused
        self._memo[id(expr)] = expr, number
        return number

    def _key(self, expr) -> tuple | None:
        if isinstance(expr, VirtualVariable):
            return ("v", expr.varid)
        if isinstance(expr, Const):
            return ("c", expr.value, expr.bits)
        if isinstance(expr, StackBaseOffset):
            return ("s", expr.offset, expr.bits)
        if isinstance(expr, BinaryOp):
            ops = [self.of(op) for op in expr.operands]
            if None in ops:
                return None
            return ("b", expr.op, expr.bits, expr.signed, expr.floating_point, *ops)
        if isinstance(expr, UnaryOp):
            op = self.of(expr.operand)
            return None if op is None else ("u", expr.op, expr.bits, op)
        if isinstance(expr, Convert):
            op = self.of(expr.operand)
            return None if op is None else ("x", expr.from_bits, expr.to_bits, expr.is_signed, str(expr.from_type), op)
        return None


def _is_compound(expr) -> bool:
    if isinstance(expr, UnaryOp):
        # an address-of reads better as itself
        return expr.op != "Reference"
    return isinstance(expr, (BinaryOp, Convert))


class EqualValueReuser:
    """
    Rewrite each pure compound expression that a dominating definition ``vvar = expr`` already computed to ``vvar``.
    """

    MAX_REWRITES_PER_STMT = 64

    def __init__(self, graph: networkx.DiGraph, entry: Block):
        self._graph = graph
        self._entry = entry
        self._keys = _ValueKeys()
        self.reused = 0

    def run(self) -> dict[Block, Block]:
        """The rewritten blocks, ``{old block: new block}``. The graph is not modified."""
        idom = networkx.immediate_dominators(self._graph, self._entry)
        # networkx may leave the entry out of its own dominator map
        idom[self._entry] = self._entry
        holders: defaultdict[int, list[tuple[Expression, VirtualVariable, Block, int]]] = defaultdict(list)
        for block in self._graph:
            if block not in idom:
                continue
            for stmt_idx, stmt in enumerate(block.statements):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_tmp
                    and _is_compound(stmt.src)
                ):
                    number = self._keys.of(stmt.src)
                    if number is not None:
                        holders[number].append((stmt.src, stmt.dst, block, stmt_idx))
        if not holders:
            return {}

        def dominates(def_block: Block, def_idx: int, block: Block, stmt_idx: int) -> bool:
            if def_block is block:
                return def_idx < stmt_idx
            node = block
            while True:
                parent = idom.get(node)
                if parent is None or parent is node:
                    return False
                if parent is def_block:
                    return True
                node = parent

        def holder_of(expr, own_varid, block, stmt_idx) -> VirtualVariable | None:
            number = self._keys.of(expr)
            if number is None:
                return None
            for held, vvar, def_block, def_idx in holders.get(number, ()):
                if vvar.varid != own_varid and dominates(def_block, def_idx, block, stmt_idx) and held.likes(expr):
                    return vvar
            return None

        replacements = {}
        for block in self._graph:
            if block not in idom:
                continue
            new_stmts = None
            for stmt_idx, stmt in enumerate(block.statements):
                own_varid = (
                    stmt.dst.varid if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) else None
                )
                for _ in range(self.MAX_REWRITES_PER_STMT):
                    walker = _Subexpressions()
                    walker.walk_statement(stmt)
                    for sub in walker.exprs:
                        if not _is_compound(sub):
                            continue
                        vvar = holder_of(sub, own_varid, block, stmt_idx)
                        if vvar is None:
                            continue
                        replaced, new_stmt = stmt.replace(sub, vvar)
                        if replaced and not new_stmt.likes(stmt):
                            stmt = new_stmt
                            self.reused += 1
                            if new_stmts is None:
                                new_stmts = list(block.statements)
                            new_stmts[stmt_idx] = stmt
                            break
                    else:
                        break
            if new_stmts is not None:
                replacements[block] = block.copy(statements=new_stmts)
        return replacements
