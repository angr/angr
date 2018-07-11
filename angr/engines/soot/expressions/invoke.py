
from . import translate_expr
from ..method_dispatcher import resolve_method
from .base import SimSootExpr


class JavaArgument(object):

    __slots__ = ['value', 'type', 'is_this_ref']

    def __init__(self, value, type_, is_this_ref=False):
        """
        :param value:    Value of the argument 
        :param type_:    Type of the argument
        :param this_ref: Indicates if argument, is 'this' reference, i.e.
                         the object on which the method is invoked.
        """
        self.value = value
        self.type = type_
        self.is_this_ref = is_this_ref
    
    def __repr__(self):
        return str(self.value)


class InvokeBase(SimSootExpr):
    def __init__(self, expr, state):
        super(InvokeBase, self).__init__(expr, state)
    
    def _execute(self):
        # the invoke target gets resolved differently based on the invoke type
        # => static vs. virtual vs. special (aka non-virtual)
        self.method = self._resolve_invoke_target(self.expr, self.state)
        # translate arguments
        self.args = self._translate_args()

    def _translate_args(self):
        args = []
        # for instance method calls, add the 'this' reference
        if not isinstance(self, SimSootExpr_StaticInvoke):
            this_ref_base = self._translate_value(self.expr.base)
            this_ref = self.state.memory.load(this_ref_base)
            this_ref_type = this_ref.type if this_ref is not None else None
            args += [JavaArgument(this_ref, this_ref_type, is_this_ref=True)]

        # translate function arguments
        for arg in self.expr.args:
            if "Constant" in arg.__class__.__name__:
                # argument is a constant
                # => translate the expr to get the value
                arg_value = self._translate_expr(arg).expr
            else:
                # argument is a variable
                # => load value from memory
                arg_value = self.state.memory.load(self._translate_value(arg))
            args += [JavaArgument(arg_value, arg.type)]

        return args

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
                              params=self.expr.method_params)


class SimSootExpr_SpecialInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        # special invocations are used either for invoking instance methods of
        # a superclass or a constructor. Compared to virtual invokes, the class
        # containing the the method is passed explicitly in the invoke expression
        # (@expr.class_name) rather than determined by the base objects type
        return resolve_method(state=self.state, 
                              method_name=self.expr.method_name,
                              class_name=self.expr.class_name,
                              params=self.expr.method_params)


class SimSootExpr_StaticInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        return resolve_method(state=self.state, 
                              method_name=self.expr.method_name,
                              class_name=self.expr.class_name,
                              params=self.expr.method_params)
