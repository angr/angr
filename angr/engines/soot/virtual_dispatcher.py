
from archinfo.arch_soot import SootMethodDescriptor


# TODO implement properly
# this will need the expression, the class hierarchy, and the position of the instruction (for invoke-super)
# this will also need the current state to try to figure out the dynamic type


def resolve_method(state, expr):
    return SootMethodDescriptor(expr.class_name, expr.method_name, tuple(a.type for a in expr.args))
