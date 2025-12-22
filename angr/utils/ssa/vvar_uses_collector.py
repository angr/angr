from __future__ import annotations
from collections import defaultdict

from angr.ailment import AILBlockViewer
from angr.ailment.expression import VirtualVariable, Phi
from angr.ailment.statement import Statement, Assignment
from angr.ailment.block import Block
from angr.code_location import AILCodeLocation


class VVarUsesCollector(AILBlockViewer):
    """
    Collect all uses of virtual variables and their use locations in an AIL block. Skip collecting use locations if
    block is not specified.
    """

    def __init__(self):
        super().__init__()

        self.vvar_and_uselocs: dict[int, list[tuple[VirtualVariable, AILCodeLocation]]] = defaultdict(list)
        self.vvars: set[int] = set()

    def _handle_VirtualVariable(
        self, expr_idx: int, expr: VirtualVariable, stmt_idx: int, stmt: Statement | None, block: Block | None
    ):
        if isinstance(stmt, Assignment):
            if expr is stmt.dst:
                return
            if isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi) and expr.varid == stmt.dst.varid:
                # avoid phi loops
                return
        if block is not None and stmt is not None:
            self.vvar_and_uselocs[expr.varid].append(
                (expr, AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr")))
            )
        self.vvars.add(expr.varid)
