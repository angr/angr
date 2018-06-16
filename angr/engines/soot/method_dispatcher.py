
from archinfo.arch_soot import SootMethodDescriptor
from cle.errors import CLEError

import logging
l = logging.getLogger('angr.engines.soot.method_dispatcher')


def resolve_method(state, method_name, class_name, params=(), ret=None):
    """
    Resolves the method based on the given characteristics (name, 
    class, params, ...). The method may be defined in one of the 
    superclasses of the given class (TODO: support interfaces).

    :return: SootMethodDescriptor of the method.
    """
    java_binary = state.project.loader.main_object
    class_hierarchy = state.javavm_classloader.get_class_hierarchy(class_name)
    # walk up in class hierarchy, until method is found
    for class_ in class_hierarchy:
        soot_method = java_binary.get_method(method_name, class_.name, params, 
                                             ret, none_if_missing=True)
        if soot_method:
            # if method was found, load the class and return it
            state.javavm_classloader.load_class(class_)
            return SootMethodDescriptor.from_soot_method(soot_method)

    else:
        # method could not be found
        # => we are executing code that is not loaded (typically library code)
        # => fallback: use only infos from the invocation, so we can use SimProcedures
        l.warning("Couldn't find method {class_name}.{method_name} "
                  "in class(es) {class_hierarchy}."
                  "".format(class_name=class_name, method_name=method_name, 
                            class_hierarchy=", ".join([str(c.name) for c in 
                            state.javavm_classloader.get_class_hierarchy(class_name)])))
        return SootMethodDescriptor(class_name, method_name, params)
