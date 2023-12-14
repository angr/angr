from typing import Optional, Any, DefaultDict, Tuple, Union, Iterable, Set, TYPE_CHECKING
from collections import defaultdict

from ailment.expression import Expression, Register
from ailment.statement import Statement
from ailment.block_walker import AILBlockWalkerBase
from ailment import Block

if TYPE_CHECKING:
    from ailment.expression import BinaryOp, UnaryOp


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

    def __init__(self, expr_or_stmt: Union[Expression, Statement]):
        super().__init__()
        self.counts: DefaultDict[Tuple[int, int], int] = defaultdict(int)
        if isinstance(expr_or_stmt, Expression):
            self.walk_expression(expr_or_stmt)
        elif isinstance(expr_or_stmt, Statement):
            self.walk_statement(expr_or_stmt)
        else:
            raise TypeError(f"Unsupported argument type {type(expr_or_stmt)}")

    def _handle_Register(self, expr_idx: int, expr: Register, stmt_idx: int, stmt: Statement, block: Optional[Block]):
        self.counts[expr.reg_offset, expr.size] += 1


class OperatorCounter(AILBlockWalkerBase):
    """
    Count the occurrence of a given expression operator.
    """

    def __init__(self, operator: Union[str, Iterable[str]], expr_or_stmt: Union[Expression, Statement]):
        super().__init__()
        self.count = 0
        self.operators: Set[str] = {operator} if isinstance(operator, str) else set(operator)
        if isinstance(expr_or_stmt, Expression):
            self.walk_expression(expr_or_stmt)
        elif isinstance(expr_or_stmt, Statement):
            self.walk_statement(expr_or_stmt)
        else:
            raise TypeError(f"Unsupported argument type {type(expr_or_stmt)}")

    def _handle_BinaryOp(self, expr_idx: int, expr: "BinaryOp", stmt_idx: int, stmt: Statement, block: Optional[Block]):
        if expr.op in self.operators:
            self.count += 1
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: "UnaryOp", stmt_idx: int, stmt: Statement, block: Optional[Block]):
        if expr.op in self.operators:
            self.count += 1
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)
