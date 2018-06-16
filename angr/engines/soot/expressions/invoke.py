
from . import translate_expr
from ..method_dispatcher import resolve_method
from .base import SimSootExpr


class InvokeBase(SimSootExpr):
    def __init__(self, expr, state):
        super(InvokeBase, self).__init__(expr, state)
    
    def _execute(self):
        # the invoke target gets resolved differently based on the invoke type
        # => static vs. virtual vs. special (aka non-virtual)
        invoke_target = self._resolve_invoke_target(self.expr, self.state)
        # initialize invocation
        # => everything else is handled by the engine
        self.state.scratch.invoke = True
        self.state.scratch.invoke_target = invoke_target
        self.state.scratch.invoke_expr = self.expr

    def _resolve_invoke_target(self, expr, state):
        NotImplementedError()


class SimSootExpr_VirtualInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        # instance methods are dynamically resolved by the actual type of
        # the base object (i.e. the object that is used for the call) and
        # *not* by the type of the reference variable
        # => get the type of the base object
        base = translate_expr(self.expr.base, self.state).expr
        if base is not None:
            base_type = base.type
        else:
            # if the base is not set, we probably process an invocation of
            # an unloaded library function
            # => fallback: use the statically retrieved type
            base_type = self.expr.class_name

        # based on class of the object base, we resolve the invoke target
        return resolve_method(state=self.state,
                              method_name=self.expr.method_name,
                              class_name=base_type,
                              params=self.expr.method_params,
                              ret=self.expr.type)


class SimSootExpr_SpecialInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        # special invocations are used either for invoking instance methods of
        # a superclass or a constructor. Compared to virtual invokes, the class
        # containing the the method is passed explicitly in the invoke expression
        # (@expr.class_name) rather than determined by the base objects type
        return resolve_method(state=self.state, 
                              method_name=self.expr.method_name,
                              class_name=self.expr.class_name,
                              params=self.expr.method_params,
                              ret=self.expr.type)


class SimSootExpr_StaticInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        return resolve_method(state=self.state, 
                              method_name=self.expr.method_name,
                              class_name=self.expr.class_name,
                              params=self.expr.method_params,
                              ret=self.expr.type)
