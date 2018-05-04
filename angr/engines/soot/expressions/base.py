
import logging
l = logging.getLogger('angr.engines.soot.expressions.base')

from cle.errors import CLEError

class SimSootExpr(object):
    def __init__(self, expr, state):
        self.expr = expr
        self.state = state

    def process(self):
        self._execute()

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        expr_ = translate_expr(expr, self.state)
        return expr_

    def _translate_value(self, value):
        value_ = translate_value(self.state.ip.method.fullname, value)
        return value_

    def get_invoke_target_method(self):
        """
        Returns the target method, if expr is an invoke.
        """
        # check if expr is an invoke
        if not "Invoke" in self.expr.__class__.__name__:
            l.warning("Expression '%s' does not appear to be a invoke." % str(self.expr))
            return None
            
        # get all methods matching name + class
        main_object = self.state.project.loader.main_object
        try:
            methods = list(main_object.get_method(self.expr.method_name, self.expr.class_name))
        except CLEError:
            return None

        if methods:
            if len(methods) != 1: # TODO: use information about the function signature to find the right one
                l.warning("Function %s is ambiguous in class %s" 
                        % (self.expr.method_name, self.expr.class_name))
            return methods[0]

        return None

from . import translate_expr
from ..values import translate_value
