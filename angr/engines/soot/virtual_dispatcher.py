
from archinfo.arch_soot import SootMethodDescriptor
from angr.engines.soot.expressions import translate_expr

import logging
l = logging.getLogger('angr.engines.soot.virtual_dispatcher')

from cle.errors import CLEError

# TODO implement properly
# this will need the expression, the class hierarchy, and the position of the instruction (for invoke-super)
# this will also need the current state to try to figure out the dynamic type

def resolve_instance_method(state, expr):
    base_this = translate_expr(expr.base, state)
    # Sometimes "this" is None for example when we use a method from a library
    # (i. e. System.out.Println)
    if base_this.expr is None:
        # In this case we just keep the type retrieved statically by soot
        class_name = expr.class_name
    else: 
        class_name = base_this.expr.type

    return resolve_method(state=state, method_name=expr.method_name, class_name=class_name,
                          params=expr.method_params, ret=expr.type)


def resolve_static_method(state, expr):
    return resolve_method(state=state, method_name=expr.method_name, class_name=expr.class_name,
                          params=expr.method_params, ret=expr.type)


def resolve_method(state, method_name, class_name, params=(), ret=None, attrs=[], exceptions=()):
    java_binary = state.project.loader.main_object
    class_hierarchy = state.javavm_classloader.get_class_hierarchy(class_name)
    # walk up in class hierarchy
    for class_ in class_hierarchy:
        # try to fetch the method from the binary in every class
        soot_method = java_binary.get_method(method_name, class_.name, attrs, params, 
                                             ret, exceptions, none_if_missing=True)
        if soot_method:
            # if method was found, load der class and return an opaque reference to it
            state.javavm_classloader.load_class(class_)
            return SootMethodDescriptor.from_soot_method(soot_method)

    else:
        # method could not be found in loaded classes
        # => we are executing code that is not in CLE (typically library code)
        # fallback: use only infos from the invocation, so we can still use SimProcedures
        l.warning("Couldn't find method {class_name}.{method_name} in class(es) {class_hierarchy}."
                  "".format(class_name=class_name, method_name=method_name, 
                            class_hierarchy=", ".join([str(c.name) for c in 
                            state.javavm_classloader.get_class_hierarchy(class_name)])))
        return SootMethodDescriptor(class_name, method_name, params)

