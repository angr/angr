
from .base import SimSootStmt

import logging
l = logging.getLogger('angr.engines.soot.statements.invoke')


class SimSootStmt_Invoke(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Invoke, self).__init__(stmt, state)

    def _execute(self):
        invoke_expr = self._translate_expr(self.stmt.invoke_expr)
        self._add_invoke_target(invoke_expr)
