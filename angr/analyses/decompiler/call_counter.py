from typing import Optional, TYPE_CHECKING

from ailment.block_walker import AILBlockWalkerBase

if TYPE_CHECKING:
    from ailment import Block
    from ailment.statement import Call


class AILCallCounter(AILBlockWalkerBase):
    """
    Helper class to count AIL Calls and call-expressions in a block
    """

    calls = 0

    def _handle_CallExpr(self, expr_idx: int, expr: "Call", stmt_idx: int, stmt, block: Optional["Block"]):
        self.calls += 1
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: "Call", block: Optional["Block"]):
        self.calls += 1
        super()._handle_Call(stmt_idx, stmt, block)
