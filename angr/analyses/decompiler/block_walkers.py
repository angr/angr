from __future__ import annotations

from typing import TYPE_CHECKING

from angr.ailment import AILBlockViewer
from angr.utils import ail_predicates as _pred

if TYPE_CHECKING:
    from angr.ailment import Expression, Statement


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


_HAS_CALL_WALKER = HasCallExprWalker()


def _py_has_call_expr(node: Expression | Statement) -> bool:
    from angr.ailment import Statement as _Statement  # pylint:disable=import-outside-toplevel

    try:
        if isinstance(node, _Statement):
            _HAS_CALL_WALKER.walk_statement(node)
        else:
            _HAS_CALL_WALKER.walk_expression(node)
    except HasCallNotification:
        return True
    return False


def has_call_expr(node: Expression | Statement) -> bool:
    """
    Does ``node`` contain a ``Call`` / ``FunctionLikeMacro`` expression or a ``SideEffectStatement``?

    Native fast path with a fallback to ``HasCallExprWalker`` for non-native AIL nodes.
    """
    return _pred.has_call_expr(node, _py_has_call_expr)
