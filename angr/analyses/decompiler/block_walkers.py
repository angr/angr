from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.expression import BinaryOp, Convert, Expression, Let, Load
from angr.ailment.utils import is_effectful_dirty_expression


class HasCallNotification(Exception):
    """
    Abort the walk on the first call or other side effect encountered.
    """


class HasCallExprWalker(AILBlockViewer):
    """
    Singleton walker that raises ``HasCallNotification`` on the first call or other side effect it visits.
    """

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_DirtyStatement(self, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_effectful_dirty_expression(expr):
            raise HasCallNotification
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Load(self, expr_idx, expr: Load, stmt_idx, stmt, block):
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
        guard = expr.guard
        if guard is not None:
            self._handle_expr(1, guard, stmt_idx, stmt, block)
        alt = expr.alt
        if alt is not None:
            self._handle_expr(2, alt, stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr: BinaryOp, stmt_idx, stmt, block):
        super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        rounding_mode = expr.rounding_mode
        if isinstance(rounding_mode, Expression):
            self._handle_expr(2, rounding_mode, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx, expr: Convert, stmt_idx, stmt, block):
        super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)
        rounding_mode = expr.rounding_mode
        if isinstance(rounding_mode, Expression):
            self._handle_expr(1, rounding_mode, stmt_idx, stmt, block)

    def _handle_Let(self, expr_idx, expr: Let, stmt_idx, stmt, block):
        for idx, def_stmt in enumerate(expr.defs):
            self._handle_stmt(idx, def_stmt, None)
        self._handle_expr(0, expr.src, stmt_idx, stmt, block)

    def _top(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr, Let):
            # Let is not part of AILBlockViewer's default dispatch table.
            self._handle_Let(expr_idx, expr, stmt_idx, stmt, block)
