from __future__ import annotations
from typing import TYPE_CHECKING

from angr.ailment import Block
from angr.ailment.statement import Label, ConditionalJump
from angr.ailment.block_walker import AILBlockViewer

from angr.analyses.decompiler.sequence_walker import SequenceWalker

if TYPE_CHECKING:
    from angr.ailment import Address
    from angr.ailment.statement import Call


class AILBlockCallCounter(AILBlockViewer):
    """
    Helper class to count AIL calls and call-expressions in a block, or collect call statements and call expressions
    as well as their locations.
    """

    def __init__(self, consider_conditions: bool = False):
        super().__init__()
        self.calls: int = 0
        self.consider_conditions = consider_conditions
        self.call_stmts: list[tuple[tuple[Address | None, int], Call]] = []
        self.call_exprs: list[tuple[tuple[Address | None, int], Call]] = []

    def _handle_ConditionalJump(self, stmt_idx: int, stmt: ConditionalJump, block: Block | None):
        if not self.consider_conditions:
            return
        super()._handle_ConditionalJump(stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: Call, stmt_idx: int, stmt, block: Block | None):
        self.calls += 1
        self.call_exprs.append((((block.addr, block.idx) if block is not None else None, stmt_idx), expr))
        super()._handle_CallExpr(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, stmt_idx: int, stmt: Call, block: Block | None):
        self.calls += 1
        self.call_stmts.append((((block.addr, block.idx) if block is not None else None, stmt_idx), stmt))
        super()._handle_Call(stmt_idx, stmt, block)


class AILCallCounter(SequenceWalker):
    """
    Helper class to count AIL calls and call expressions in a structuring node, or collect call statements and call
    expressions as well as their locations.
    """

    def __init__(self, consider_conditions: bool = False):
        handlers = {
            Block: self._handle_Block,
        }
        super().__init__(handlers)
        self.calls = 0
        self.non_label_stmts = 0
        self.consider_conditions = consider_conditions
        self.call_stmts: list[tuple[tuple[Address | None, int], Call]] = []
        self.call_exprs: list[tuple[tuple[Address | None, int], Call]] = []

    def _handle_Condition(self, node, **kwargs):
        if self.consider_conditions:
            super()._handle(node, **kwargs)
        else:
            # do not count calls in conditions
            if node.true_node is not None:
                super()._handle(node.true_node, **kwargs)
            if node.false_node is not None:
                super()._handle(node.false_node, **kwargs)

    def _handle_Block(self, node: Block, **kwargs):  # pylint:disable=unused-argument
        ctr = AILBlockCallCounter(consider_conditions=self.consider_conditions)
        ctr.walk(node)
        self.calls += ctr.calls
        self.call_stmts += ctr.call_stmts
        self.call_exprs += ctr.call_exprs
        self.non_label_stmts += sum(1 for stmt in node.statements if not isinstance(stmt, Label))
