from .base import SimIRExpr
from .. import size_bits
from ... import s_options as o
from .. import ccall
from ...s_errors import SimCCallError, UnsupportedCCallError

import logging
l = logging.getLogger('simuvex.vex.expressions.ccall')

class SimIRExpr_CCall(SimIRExpr):
    def _execute(self):
        exprs = self._translate_exprs(self._expr.args)

        if o.DO_CCALLS not in self.state.options:
            self.expr = self.state.se.Unconstrained("ccall_ret", size_bits(self._expr.ret_type))
            return

        if hasattr(ccall, self._expr.callee.name):
            s_args = [ e.expr for e in exprs ]

            try:
                func = getattr(ccall, self._expr.callee.name)
                self.expr, retval_constraints = func(self.state, *s_args)
                self._constraints.extend(retval_constraints)
            except SimCCallError:
                if o.BYPASS_ERRORED_IRCCALL not in self.state.options:
                    raise
                self.state.log.add_event('resilience', resilience_type='ccall', callee=self._expr.callee.name, message='ccall raised SimCCallError')
                self.expr = self.state.se.Unconstrained("errored_%s" % self._expr.callee.name, size_bits(self._expr.ret_type))
        else:
            l.error("Unsupported CCall %s", self._expr.callee.name)
            if o.BYPASS_UNSUPPORTED_IRCCALL in self.state.options:
                if o.UNSUPPORTED_BYPASS_ZERO_DEFAULT in self.state.options:
                    self.expr = self.state.se.BVV(0, size_bits(self._expr.ret_type))
                else:
                    self.expr = self.state.se.Unconstrained("unsupported_%s" % self._expr.callee.name, size_bits(self._expr.ret_type))
                self.state.log.add_event('resilience', resilience_type='ccall', callee=self._expr.callee.name, message='unsupported ccall')
            else:
                raise UnsupportedCCallError("Unsupported CCall %s" % self._expr.callee.name)
