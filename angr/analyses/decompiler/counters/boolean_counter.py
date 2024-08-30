from __future__ import annotations
import typing

from ailment import AILBlockWalkerBase

if typing.TYPE_CHECKING:
    from ailment.expression import BinaryOp
    from ailment.statement import Statement
    from ailment.block import Block


class BooleanCounter(AILBlockWalkerBase):
    """
    This class counts the number of Boolean operators an expression has.
    In the case of: `if (a || (b && c))`, it will count 2 Boolean operators.
    """

    def __init__(self):
        super().__init__()
        self.boolean_cnt = 0

    def _handle_BinaryOp(self, expr_idx: int, expr: BinaryOp, stmt_idx: int, stmt: Statement, block: Block | None):
        if expr.op in {"LogicalAnd", "LogicalOr"}:
            self.boolean_cnt += 1

        self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
