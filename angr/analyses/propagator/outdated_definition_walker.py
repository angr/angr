from typing import Optional, TYPE_CHECKING

from ailment import Block, Stmt, Expr

from ..decompiler.ailblock_walker import AILBlockWalker

if TYPE_CHECKING:
    from .propagator import PropagatorAILState


class OutdatedDefinitionWalker(AILBlockWalker):
    """
    Walks an AIL expression to find outdated definitions.
    """
    def __init__(self, expr, state: 'PropagatorAILState'):
        super().__init__()
        self.expr = expr
        self.state = state
        self.expr_handlers[Expr.Register] = self._handle_Register
        self.out_dated = False

    # pylint:disable=unused-argument
    def _handle_Register(self, expr_idx: int, reg_expr: Expr.Register, stmt_idx: int, stmt: Stmt.Assignment,
                         block: Optional[Block]):
        v = self.state.load_register(reg_expr)
        if v is not None:
            if not self.expr.likes(v):
                self.out_dated = True
            elif isinstance(v, Expr.TaggedObject) and v.tags.get('def_at', None) != self.expr.tags.get('def_at', None):
                self.out_dated = True
