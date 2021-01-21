from ailment.expression import BinaryOp, UnaryOp


class PeepholeOptimizationStmtBase:

    __slots__ = ('project', )

    name = "Peephole Optimization - Statement"
    description = "Peephole Optimization - Statement"
    stmt_classes = None

    def __init__(self, project):
        self.project = project

    def optimize(self, stmt):
        raise NotImplementedError("_optimize() is not implemented.")


class PeepholeOptimizationExprBase:

    __slots__ = ('project',)

    name = "Peephole Optimization - Expression"
    description = "Peephole Optimization - Expression"
    expr_classes = None

    def __init__(self, project):
        self.project = project

    def optimize(self, expr):
        raise NotImplementedError("_optimize() is not implemented.")

    #
    # Util methods
    #

    @staticmethod
    def is_bool_expr(ail_expr):

        if isinstance(ail_expr, BinaryOp):
            if ail_expr.op in {'CmpEQ', 'CmpNE', 'CmpLT', 'CmpLE', 'CmpGT', 'CmpGE', 'CmpLTs', 'CmpLEs', 'CmpGTs',
                               'CmpGEs'}:
                return True
        if isinstance(ail_expr, UnaryOp) and ail_expr.op == 'Not':
            return True
        return False
