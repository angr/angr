from __future__ import annotations

from angr.ailment import AILBlockViewer
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

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_effectful_dirty_expression(expr):
            raise HasCallNotification
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)
