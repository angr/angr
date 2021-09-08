from typing import Optional

from ailment import Block, Stmt

from ..decompiler.ailblock_walker import AILBlockWalker


class CallExprFinder(AILBlockWalker):
    """
    Walks an AIL expression to find if it contains a call expression anywhere.
    """
    def __init__(self):
        super().__init__()
        self.has_call = False

    # pylint:disable=unused-argument
    def _handle_CallExpr(self, expr_idx: int, expr: Stmt.Call, stmt_idx: int, stmt: Stmt.Statement,
                         block: Optional[Block]):
        self.has_call = True
