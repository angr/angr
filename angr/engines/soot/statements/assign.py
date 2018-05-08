
from .base import SimSootStmt
from ..expressions import SimSootExpr_NewArray
from ..values import SimSootValue_ArrayRef
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

        if isinstance(src_expr, SimSootExpr_NewArray):
            type_ = dst.type.strip("[]")
            size_ = len(src_val)
            # We need to allocate the array on the heap and return the reference
            ref = SimSootValue_ArrayRef(0, type_, dst, size_)
            src_val = ref
            for idx, elem in enumerate(src_expr.expr):
                ref = SimSootValue_ArrayRef(idx, type_, dst, size_)
                self.state.memory.store(ref, elem)
            src_val = SimSootValue_ArrayRef(0, type_, dst, size_)

        l.debug("Assigning %s to %s" % (src_val, dst))
        self.state.memory.store(dst, src_val)
