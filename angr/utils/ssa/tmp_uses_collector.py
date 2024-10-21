from __future__ import annotations
from collections import defaultdict

from ailment import AILBlockWalkerBase
from ailment.expression import Tmp
from ailment.statement import Statement, Assignment
from ailment.block import Block


class TmpUsesCollector(AILBlockWalkerBase):
    """
    Collect all uses of temporary variables and their use statement IDs in an AIL block.
    """

    def __init__(self):
        super().__init__()

        self.tmp_and_uselocs: dict[tuple[int, int], set[tuple[Tmp, int]]] = defaultdict(set)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt: Statement, block: Block | None):
        if isinstance(stmt, Assignment) and expr is stmt.dst:
            return
        self.tmp_and_uselocs[(expr.tmp_idx, expr.bits)].add((expr, stmt_idx))
