
from ..virtual_dispatcher import resolve_method
from .base import SimSootStmt
import logging


l = logging.getLogger('angr.engines.soot.statements.invoke')

class SimSootStmt_Invoke(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Invoke, self).__init__(stmt, state)

    def _execute(self):
        invoke_target = resolve_method(self.state, self.stmt.invoke_expr)

        # Initialize an invoke state, and set the arguments
        self.state.scratch.invoke = True
        self.state.scratch.invoke_target = invoke_target
        self.state.scratch.invoke_expr = self.stmt.invoke_expr


