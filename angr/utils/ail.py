from __future__ import annotations

from ailment import AILBlockWalkerBase
from ailment.block import Block
from ailment.expression import Expression, VirtualVariable, Phi
from ailment.statement import Assignment, Statement


def is_phi_assignment(stmt: Statement) -> bool:
    return isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and isinstance(stmt.src, Phi)


class HasExprWalker(AILBlockWalkerBase):
    """
    Test if any expressions in exprs_to_check is used in another AIL expression.
    """

    def __init__(self, exprs_to_check: set[Expression]) -> None:
        super().__init__()

        self.exprs_to_check: set[Expression] = exprs_to_check
        self.contains_exprs: bool = False

    def _handle_expr(
        self, expr_idx: int, expr: Expression, stmt_idx: int, stmt: Statement | None, block: Block | None
    ) -> None:
        if expr in self.exprs_to_check:
            self.contains_exprs = True
        if not self.contains_exprs:
            super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
