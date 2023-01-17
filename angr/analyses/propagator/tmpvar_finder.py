from ailment.expression import Expression, Tmp

from ..decompiler.ailblock_walker import AILBlockWalkerBase


class TmpvarFinder(AILBlockWalkerBase):
    """
    Walks an AIL expression to find Tmp expressions.
    """

    def __init__(self, expr: Expression):
        super().__init__()
        self.has_tmp = False

        self.walk_expression(expr)

    def _handle_Tmp(self, expr_idx: int, expr: Tmp, stmt_idx: int, stmt, block):
        self.has_tmp = True
