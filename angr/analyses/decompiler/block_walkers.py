from __future__ import annotations

from angr.ailment import AILBlockViewer
from angr.ailment.utils import is_llsc_expression


class HasCallNotification(Exception):
    """
    Abort the walk on the first Call / SideEffectStatement encountered.
    """


class HasCallExprWalker(AILBlockViewer):
    """
    Singleton walker that raises ``HasCallNotification`` on the first Call / SideEffectStatement it visits.
    """

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_llsc_expression(expr):
            raise HasCallNotification
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)
