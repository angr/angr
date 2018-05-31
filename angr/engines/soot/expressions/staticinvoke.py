import logging

from ..virtual_dispatcher import resolve_method
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.staticfieldref')

class SimSootExpr_StaticInvoke(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_StaticInvoke, self).__init__(expr, state)

    def _execute(self):
        try:
            class_ = self.state.project.loader.main_bin.classes[self.expr.class_name]
            if not self.state.javavm_classloader.is_class_loaded(class_):
                self.state.javavm_classloader.load_class(class_)
        except KeyError:
            l.warning("Trying to call a Static Method not loaded (%r)", self.expr)

        invoke_target = resolve_method(self.state, self.expr)

        # Initialize an invoke state, and set the arguments
        self.state.scratch.invoke = True
        self.state.scratch.invoke_target = invoke_target
        self.state.scratch.invoke_expr = self.expr
        self.state.scratch.invoke_has_native_target = ('NATIVE' in invoke_target.attrs)