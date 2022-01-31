from typing import Optional, TYPE_CHECKING

from ailment import Block, Stmt, Expr

from ..decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from .propagator import PropagatorAILState


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """
    def __init__(self, expr, state: 'PropagatorAILState', avoid: Optional[Expr.Expression]=None):
        super().__init__()
        self.expr = expr
        self.state = state
        self.avoid = avoid
        self.expr_handlers[Expr.Register] = self._handle_Register
        self.expr_handlers[Expr.Load] = self._handle_Load
        self.expr_handlers[Expr.Tmp] = self._handle_Tmp
        self.expr_handlers[Expr.VEXCCallExpression] = self._handle_VEXCCallExpression
        self.out_dated = False

    # pylint:disable=unused-argument
    def _handle_Tmp(self, expr_idx: int, tmp_expr: Expr.Tmp, stmt_idx: int, stmt: Stmt.Assignment,
                    block: Optional[Block]):
        if self.avoid is not None and tmp_expr.likes(self.avoid):
            self.out_dated = True

    # pylint:disable=unused-argument
    def _handle_Register(self, expr_idx: int, reg_expr: Expr.Register, stmt_idx: int, stmt: Stmt.Assignment,
                         block: Optional[Block]):
        if self.avoid is not None and reg_expr.likes(self.avoid):
            self.out_dated = True
        else:
            v = self.state.load_register(reg_expr)
            if v is not None:
                if not self.expr.likes(v):
                    self.out_dated = True
                elif isinstance(v, Expr.TaggedObject) and v.tags.get('def_at', None) != self.expr.tags.get('def_at', None):
                    self.out_dated = True

    def _handle_Load(self, expr_idx: int, expr: Expr.Load, stmt_idx: int, stmt: Stmt.Statement, block: Optional[Block]):
        if self.avoid is not None and (expr == self.avoid or expr.addr == self.avoid):
            self.out_dated = True
        else:
            super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VEXCCallExpression(self, expr_idx: int, expr: Expr.VEXCCallExpression, stmt_idx: int,
                                   stmt: Stmt.Statement, block: Optional[Block]):
        if self.avoid is not None:
            if any(op == self.avoid for op in expr.operands):
                self.out_dated = True

        if not self.out_dated:
            super()._handle_VEXCCallExpression(expr_idx, expr, stmt_idx, stmt, block)
