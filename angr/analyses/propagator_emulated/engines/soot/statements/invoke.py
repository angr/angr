
import logging

from .base import SimSootStmt

l = logging.getLogger('angr.engines.soot.statements.invoke')


class SimSootStmt_Invoke(SimSootStmt):
    def _execute(self):
        invoke_expr = self._translate_expr(self.stmt.invoke_expr)
        self._add_invoke_target(invoke_expr)
