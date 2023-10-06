from typing import Optional, Any, DefaultDict, Tuple
from collections import defaultdict

from ailment.expression import Expression, Register
from ailment.statement import Statement
from ailment.block_walker import AILBlockWalkerBase
from ailment import Block


class SingleExpressionCounter(AILBlockWalkerBase):
    """
    Count the occurrence of subexpr in expr.
    """

    def __init__(self, stmt, subexpr):
        super().__init__()
        self.subexpr = subexpr
        self.count = 0
        self.walk_statement(stmt)

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Optional[Statement], block: Optional[Block]
    ) -> Any:
        if expr == self.subexpr:
            self.count += 1
        return super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)


class RegisterExpressionCounter(AILBlockWalkerBase):
    """
    Count the occurrence of all register expressions in expr
    """

    def __init__(self, expr):
        super().__init__()
        self.counts: DefaultDict[Tuple[int, int], int] = defaultdict(int)
        self.walk_expression(expr)

    def _handle_Register(self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        self.counts[expr.reg_offset, expr.size] += 1
