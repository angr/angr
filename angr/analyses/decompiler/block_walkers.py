from __future__ import annotations

from angr.ailment import AILBlockViewer


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
