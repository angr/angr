
from archinfo.arch_soot import SootMethodDescriptor

import logging
l = logging.getLogger('angr.engines.soot.method_dispatcher')


def resolve_method(state, method_name, class_name, params=(), include_superclasses=True):
    """
    Resolves the method based on the given characteristics (name, class and 
    params) The method may be defined in one of the superclasses of the 
    given class (TODO: support interfaces).

    :return: SootMethodDescriptor of the method.
    """
    base_class = state.javavm_classloader.get_class(class_name)
    class_hierarchy = state.javavm_classloader.get_class_hierarchy(base_class)
    class_hierarchy = class_hierarchy if include_superclasses else class_hierarchy[:1]
    # walk up in class hierarchy, until method is found
    for class_descriptor in class_hierarchy:
        java_binary = state.project.loader.main_object
        soot_method = java_binary.get_soot_method(method_name, class_descriptor.name, 
                                                  params, none_if_missing=True)
        if soot_method is not None:
            # if method was found, load the class and return it
            state.javavm_classloader.init_class(class_descriptor)
            return SootMethodDescriptor.from_soot_method(soot_method)

    else:
        # method could not be found
        # => we are executing code that is not loaded (typically library code)
        # => fallback: use only infos from the invocation, so we still can use SimProcedures
        l.warning("Couldn't find method {class_name}.{method_name} "
                  "in class(es) {class_hierarchy}."
                  "".format(class_name=class_name, method_name=method_name, 
                            class_hierarchy=class_hierarchy))
        return SootMethodDescriptor(class_name, method_name, params)
