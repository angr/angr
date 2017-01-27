
from .base import SimSootStmt
import logging


l = logging.getLogger('angr.engines.soot.statements.assign')

class SimSootStmt_Assign(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Assign, self).__init__(stmt, state)

    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)

        # The assumption here is that if src_expr contains an invoke, src_expr is just that invoke.
        # In other words, the only possible form of "invoke in assignment" is: reg = invoke
        if self.state.scratch.invoke:
            # what we do in case of invoke is that we deal with this assignment when we the engine applies
            # a special cases for invokes
            # local_var = Invoke(args)
            self.state.scratch.invoke_return_variable = dst
            # exits prematurely
            return

        src_val = src_expr.expr


        #import IPython; IPython.embed();

        l.debug("Assigning %s to %s" % (src_val, dst))
        self.state.memory.store(dst, src_val)
