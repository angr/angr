from __future__ import annotations

from angr.ailment.statement import DirtyStatement, Statement
from angr.ailment.expression import DirtyExpression, Expression


class DirtyRewriterBase:
    """
    The base class for DirtyStatement and DirtyExpression rewriters.
    """

    __slots__ = (
        "arch",
        "result",
    )

    def __init__(self, dirty: DirtyExpression | DirtyStatement, arch):
        self.arch = arch
        self.result: Expression | Statement | None = (
            self._rewrite_expr(dirty) if isinstance(dirty, DirtyExpression) else self._rewrite_stmt(dirty)
        )

    def _rewrite_stmt(self, dirty: DirtyStatement) -> Statement | None:
        raise NotImplementedError

    def _rewrite_expr(self, dirty: DirtyExpression) -> Expression | None:
        raise NotImplementedError
