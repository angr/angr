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

    def reset(self) -> None:
        self.tmp_and_uselocs = defaultdict(set)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Block | None):
        # ``stmt.dst`` materializes a fresh wrapper, so an
        # ``expr is stmt.dst`` identity check never matches. Match through ``idx``, which
        # is unique per AIL expression and survives the wrapper clone.
        if isinstance(stmt, Assignment) and expr.idx == stmt.dst.idx:
            return
        self.tmp_and_uselocs[(expr.tmp_idx, expr.bits)].add((expr, stmt_idx))
