from typing import Optional, TYPE_CHECKING

from ailment import Block
from ailment.block_walker import AILBlockWalkerBase

from .sequence_walker import SequenceWalker

if TYPE_CHECKING:
    from ailment.statement import Call


class AILBlockCallCounter(AILBlockWalkerBase):
    """
    Helper class to count AIL calls and call-expressions in a block
    """

    calls = 0

    def _handle_CallExpr(self, expr_idx: int, expr: "Call", stmt_idx: int, stmt, block: Optional["Block"]):
        self.calls += 1
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: "Call", block: Optional["Block"]):
        self.calls += 1
        super()._handle_Call(stmt_idx, stmt, block)


class AILCallCounter(SequenceWalker):
    """
    Helper class to count AIL calls and call expressions in a structuring node.
    """

    def __init__(self):
        handlers = {
            Block: self._handle_Block,
        }
        super().__init__(handlers)
        self.calls = 0

    def _handle_Block(self, node: Block, **kwargs):  # pylint:disable=unused-argument
        ctr = AILBlockCallCounter()
        ctr.walk(node)
        self.calls += ctr.calls
