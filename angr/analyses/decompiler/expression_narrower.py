from typing import Optional, Any, TYPE_CHECKING
from .ailblock_walker import AILBlockWalkerBase

if TYPE_CHECKING:
    from ailment.expression import (
        Expression,
        BinaryOp,
        Load,
        UnaryOp,
        Convert,
        ITE,
        DirtyExpression,
        VEXCCallExpression,
    )
    from ailment.statement import Call, Statement
    from ailment.block import Block


class ExpressionNarrowingWalker(AILBlockWalkerBase):
    """
    Walks a statement or an expression and extracts the operations that are applied on the given expression.

    For example, for target expression rax, `(rax & 0xff) + 0x1` means the following operations are applied on `rax`:
    rax & 0xff
    (rax & 0xff) + 0x1

    The previous expression is always used in the succeeding expression.
    """

    def __init__(self, target_expr: "Expression"):
        super().__init__()
        self._target_expr = target_expr
        self.operations = []

    def _handle_expr(
        self, expr_idx: int, expr: "Expression", stmt_idx: int, stmt: Optional["Statement"], block: Optional["Block"]
    ) -> Any:
        if expr == self._target_expr:
            # we are done!
            return True
        has_target_expr = super()._handle_expr(expr_idx, expr, stmt_idx, stmt, block)
        if has_target_expr:
            # record the current operation
            self.operations.append(expr)
            return True
        return False

    def _handle_Load(self, expr_idx: int, expr: "Load", stmt_idx: int, stmt: "Statement", block: Optional["Block"]):
        return self._handle_expr(0, expr.addr, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr: "Call", stmt_idx: int, stmt: "Statement", block: Optional["Block"]):
        r = False
        if expr.args:
            for i, arg in enumerate(expr.args):
                r |= self._handle_expr(i, arg, stmt_idx, stmt, block)
        return r

    def _handle_BinaryOp(
        self, expr_idx: int, expr: "BinaryOp", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        r = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)
        return r

    def _handle_UnaryOp(
        self, expr_idx: int, expr: "UnaryOp", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        return self._handle_expr(0, expr.operand, stmt_idx, stmt, block)

    def _handle_Convert(
        self, expr_idx: int, expr: "Convert", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        return self._handle_expr(expr_idx, expr.operand, stmt_idx, stmt, block)

    def _handle_ITE(self, expr_idx: int, expr: "ITE", stmt_idx: int, stmt: "Statement", block: Optional["Block"]):
        r = self._handle_expr(0, expr.cond, stmt_idx, stmt, block)
        r |= self._handle_expr(1, expr.iftrue, stmt_idx, stmt, block)
        r |= self._handle_expr(2, expr.iffalse, stmt_idx, stmt, block)
        return r

    def _handle_DirtyExpression(
        self, expr_idx: int, expr: "DirtyExpression", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        return self._handle_expr(0, expr.dirty_expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(
        self, expr_idx: int, expr: "VEXCCallExpression", stmt_idx: int, stmt: "Statement", block: Optional["Block"]
    ):
        r = False
        for idx, operand in enumerate(expr.operands):
            r |= self._handle_expr(idx, operand, stmt_idx, stmt, block)
        return r
