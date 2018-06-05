
from archinfo.arch_soot import SootMethodDescriptor
from angr.engines.soot.expressions import translate_expr

import logging
l = logging.getLogger('angr.engines.soot.virtual_dispatcher')

from cle.errors import CLEError

# TODO implement properly
# this will need the expression, the class hierarchy, and the position of the instruction (for invoke-super)
# this will also need the current state to try to figure out the dynamic type

def resolve_method(state, expr):

    # # get binary containing the method
    # jar = state.regs._ip_binary

    # try:
    #     # get all methods matching class- and method-name
    #     methods = list(jar.get_method(expr.method_name, expr.class_name))

    # except CLEError:
    #     # No methods found
    #     # => We are executing code that is not in CLE (typically library code)
    #     # Fallback: use only infos from the invocation, so we can still use SimProcedures
    #     l.warning("Couldn't find method %s.%s" % (expr.method_name, expr.class_name))
    #     return SootMethodDescriptor(expr.class_name, expr.method_name, expr.method_params)

    # else:
    #     if len(methods) != 1: 
    #         # Found several methods matching class- and method-name
    #         # TODO: use information about the function signature to find the right one
    #         l.warning("Function %s is ambiguous in class %s" % (expr.method_name, expr.class_name))
    #     return SootMethodDescriptor.from_soot_method(methods[0])

    base_this = translate_expr(expr.base, state)
    # Sometimes "this" is None for example when we use a method from a library
    # (i. e. System.out.Println)
    #
    # In this case we just keep the type retrieved statically by soot
    if base_this.expr is None:
        return SootMethodDescriptor(expr.class_name, expr.method_name, expr.method_params)
    return SootMethodDescriptor(base_this.expr.type, expr.method_name, expr.method_params)
