from __future__ import annotations

from angr.ailment import AILBlockViewer

# value-only intrinsics the decompiler synthesizes; they are not calls for liveness or ordering purposes
PURE_INTRINSIC_CALLS = frozenset({"__fxam"})


class HasCallNotification(Exception):
    """
    Abort the walk on the first Call / SideEffectStatement encountered.
    """


class HasCallExprWalker(AILBlockViewer):
    """
    Singleton walker that raises ``HasCallNotification`` on the first Call / SideEffectStatement it visits. Calls to
    pure intrinsics only have their arguments walked.
    """

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if isinstance(expr.target, str) and expr.target in PURE_INTRINSIC_CALLS:
            return super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        raise HasCallNotification

    def _handle_FunctionLikeMacro(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise HasCallNotification
