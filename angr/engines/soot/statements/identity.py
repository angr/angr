
from .base import SimSootStmt
import logging


l = logging.getLogger('angr.engines.soot.statements.identity')

class SimSootStmt_Identity(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Identity, self).__init__(stmt, state)

    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)
        src_val = src_expr.expr
        l.debug("Initializing %s to %s" % (src_val, dst))
        self.state.memory.store(dst, src_val)
