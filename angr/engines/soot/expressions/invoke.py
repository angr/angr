from __future__ import annotations
from archinfo.arch_soot import SootArgument, SootMethodDescriptor

from . import translate_expr
from ..method_dispatcher import resolve_method
from ..exceptions import SootMethodNotLoadedException
from .base import SimSootExpr


class InvokeBase(SimSootExpr):
    def __init__(self, expr, state):
        super().__init__(expr, state)
        self.method = None
        self.args = None

    def _execute(self):
        # the invoke target gets resolved differently based on the invoke type
        # => static vs. virtual vs. special (= non-virtual)
        self.method = self._resolve_invoke_target(self.expr, self.state)
        # translate arguments
        self.args = self._translate_args()

    def _translate_args(self):
        args = []
        # for instance method calls, add the 'this' reference
        if isinstance(self, (SimSootExpr_VirtualInvoke, SimSootExpr_SpecialInvoke)):
            this_ref_base = self._translate_value(self.expr.base)
            this_ref = self.state.memory.load(this_ref_base, none_if_missing=True)
            this_ref_type = this_ref.type if this_ref is not None else None
            args += [SootArgument(this_ref, this_ref_type, is_this_ref=True)]

        # translate function arguments
        for arg in self.expr.args:
            if "Constant" in arg.__class__.__name__:
                # argument is a constant
                # => translate the expr to get the value
                arg_value = self._translate_expr(arg).expr
            else:
                # argument is a variable
                # => load value from memory
                arg_value = self.state.memory.load(self._translate_value(arg), none_if_missing=True)
            args += [SootArgument(arg_value, arg.type)]

        return args

    def _resolve_invoke_target(self, expr, state):
        raise NotImplementedError


class SimSootExpr_VirtualInvoke(InvokeBase):
    """
    Instance methods are dynamically resolved by the actual type of the
    base object (i.e. the object on which the method is invoked) and *not*
    by the type of the variable storing the reference.
    """

    def _resolve_invoke_target(self, expr, state):
        # get the type of the base object
        base = translate_expr(self.expr.base, self.state).expr
        # if the base is not set, for example if we process an invocation of an
        # unloaded library function
        # => fallback: use the statically retrieved type
        base_type = base.type if base is not None else self.expr.class_name

        # based on the class of the base object, we resolve the invoke target
        try:
            return resolve_method(
                state=self.state,
                method_name=self.expr.method_name,
                class_name=base_type,
                params=self.expr.method_params,
                ret_type=self.expr.type,
                raise_exception_if_not_found=True,
            )
        except SootMethodNotLoadedException:
            # in case that the method is not loaded, continue with the infos
            # available from the invoke expression
            return SootMethodDescriptor(
                self.expr.class_name, self.expr.method_name, self.expr.method_params, ret_type=self.expr.type
            )


class SimSootExpr_SpecialInvoke(InvokeBase):
    """
    Special invocations are used either for invoking instance methods of a
    superclass or a constructor. Compared to virtual invokes, the class
    containing the method is passed explicitly in the invoke expression
    (@expr.class_name) rather than determined dynamically by the type of the
    base objects.
    """

    def _resolve_invoke_target(self, expr, state):
        return resolve_method(
            state=self.state,
            method_name=self.expr.method_name,
            class_name=self.expr.class_name,
            params=self.expr.method_params,
            ret_type=self.expr.type,
        )


class SimSootExpr_StaticInvoke(InvokeBase):
    def _resolve_invoke_target(self, expr, state):
        return resolve_method(
            state=self.state,
            method_name=self.expr.method_name,
            class_name=self.expr.class_name,
            params=self.expr.method_params,
            ret_type=self.expr.type,
        )


class SimSootExpr_InterfaceInvoke(SimSootExpr_VirtualInvoke):
    def _resolve_invoke_target(self, expr, state):
        return super()._resolve_invoke_target(expr, state)
