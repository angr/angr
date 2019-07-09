
import logging

from ..expressions.invoke import InvokeBase
from .base import SimSootStmt

l = logging.getLogger('angr.engines.soot.statements.assign')


class SimSootStmt_Assign(SimSootStmt):
    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)
        if isinstance(src_expr, InvokeBase):
            # right hand side of the the assignment is an invocation
            # => The assumption is that if the src_expr contains an invoke, it
            #    is always just that invoke. In other words, the only possible
            #    form of "invoke in assignment" is: reg = invoke.
            #    This requirement *should* be enforced by the lifting to Soot IR.
            # => We deal with the invoke assignment, by
            #    1) saving the destination variable
            #    2) executing the function
            #    3) assign the return value to the destination variables
            #       after the function returns
            self._add_invoke_target(invoke_expr=src_expr, ret_var=dst)
            # exit prematurely
            return
        src_val = src_expr.expr
        l.debug("Assign %r := %r", dst, src_val)
        self.state.memory.store(dst, src_val)
