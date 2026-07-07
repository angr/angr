from __future__ import annotations

from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.block import Block
from angr.ailment.expression import Tmp
from angr.ailment.statement import Assignment, Statement


class TmpUsesCollector(AILBlockViewer):
    """
    Collect all uses of temporary variables and their use statement IDs in an AIL block.
    """

    def __init__(self):
        super().__init__()

        self.tmp_and_uselocs: dict[tuple[int, int], set[tuple[Tmp, int]]] = defaultdict(set)
        self._walking_assignment_dst: bool = False

    def reset(self) -> None:
        self.tmp_and_uselocs = defaultdict(set)
        self._walking_assignment_dst = False

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block: Block | None):
        # Read ``stmt.dst`` / ``stmt.src`` exactly once per statement (each
        # access clones the whole subtree) and discriminate the def site
        # positionally instead of via ``idx`` comparison -- see
        # ``VVarUsesCollector._handle_Assignment``.
        dst = stmt.dst
        src = stmt.src
        prev = self._walking_assignment_dst
        self._walking_assignment_dst = True
        try:
            self._handle_expr(0, dst, stmt_idx, stmt, block)
            self._walking_assignment_dst = False
            self._handle_expr(1, src, stmt_idx, stmt, block)
        finally:
            self._walking_assignment_dst = prev

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Block | None):
        if self._walking_assignment_dst:
            # the def site itself, not a use
            return
        self.tmp_and_uselocs[(expr.tmp_idx, expr.bits)].add((expr, stmt_idx))
