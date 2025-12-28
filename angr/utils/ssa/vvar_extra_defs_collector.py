from __future__ import annotations

from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import VirtualVariable
from angr.code_location import AILCodeLocation


class FindExtraDefs(AILBlockViewer):
    """
    Find any referenced tagged extra_def=True
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.found: dict[int, tuple[VirtualVariable, AILCodeLocation]] = {}

    def _handle_UnaryOp(self, expr_idx: int, expr, stmt_idx: int, stmt, block):
        assert block is not None
        assert stmt is not None
        if expr.op == "Reference" and expr.tags.get("extra_def", False):
            assert isinstance(expr.operand, VirtualVariable)
            self.found[expr.operand.varid] = (
                expr.operand,
                AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags["ins_addr"]),
            )
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)
