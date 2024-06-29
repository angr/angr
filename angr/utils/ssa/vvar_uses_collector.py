from __future__ import annotations
from collections import defaultdict

from ailment import AILBlockWalkerBase
from ailment.expression import VirtualVariable
from ailment.statement import Statement, Assignment, Expression
from ailment.block import Block

from angr.code_location import CodeLocation


class VVarUsesCollector(AILBlockWalkerBase):
    def __init__(self):
        super().__init__()

        self.vvar_and_uselocs: dict[int, set[tuple[VirtualVariable, CodeLocation]]] = defaultdict(set)

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement, block: Block | None
    ):
        if isinstance(stmt, Assignment) and expr is stmt.dst:
            return
        self.vvar_and_uselocs[expr.varid].add(
            (expr, CodeLocation(block.addr, stmt_idx, ins_addr=stmt.ins_addr, block_idx=block.idx))
        )
