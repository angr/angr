import logging
l = logging.getLogger("simuvex.vex.statements")

class SimIRStmt(object):
    """A class for symbolically translating VEX IRStmts."""

    def __init__(self, stmt, state):
        self.stmt = stmt
        self.state = state

        # references by the statement
        self.actions = []
        self._constraints = [ ]

    def process(self):
        """
        Process the statement, applying its effects on the state.
        """
        # this is where we would choose between different analysis modes
        self._execute()

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        """Translates an IRExpr into a SimIRExpr."""
        e = translate_expr(expr, self.state)
        self._record_expr(e)
        return e

    def _translate_exprs(self, exprs):
        """Translates a sequence of IRExprs into SimIRExprs."""
        return [ self._translate_expr(e) for e in exprs ]

    def _record_expr(self, expr):
        """Records the references of an expression."""
        self.actions.extend(expr.actions)

    def _add_constraints(self, *constraints):
        """Adds constraints to the state."""
        self._constraints.extend(constraints)
        self.state.add_constraints(*constraints)

    def _write_tmp(self, tmp, v, reg_deps, tmp_deps):
        """
        Writes an expression to a tmp.
        """
        self.state.scratch.store_tmp(tmp, v, reg_deps, tmp_deps)


from ..expressions import translate_expr
