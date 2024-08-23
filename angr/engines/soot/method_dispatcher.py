from __future__ import annotations
import logging

from archinfo.arch_soot import SootMethodDescriptor

from .exceptions import SootMethodNotLoadedException

l = logging.getLogger("angr.engines.soot.method_dispatcher")


def resolve_method(
    state,
    method_name,
    class_name,
    params=(),
    ret_type=None,
    include_superclasses=True,
    init_class=True,
    raise_exception_if_not_found=False,
):
    """
    Resolves the method based on the given characteristics (name, class and
    params) The method may be defined in one of the superclasses of the given
    class (TODO: support interfaces).

    :rtype: archinfo.arch_soot.SootMethodDescriptor
    """
    base_class = state.javavm_classloader.get_class(class_name)
    class_hierarchy = state.javavm_classloader.get_class_hierarchy(base_class) if include_superclasses else [base_class]
    # walk up in class hierarchy, until method is found
    for class_descriptor in class_hierarchy:
        java_binary = state.project.loader.main_object
        soot_method = java_binary.get_soot_method(method_name, class_descriptor.name, params, none_if_missing=True)
        if soot_method is not None:
            # init the class
            if init_class:
                state.javavm_classloader.init_class(class_descriptor)
            return SootMethodDescriptor.from_soot_method(soot_method)

    # method could not be found
    # => we are executing code that is not loaded (typically library code)
    # => fallback: continue with infos available from the invocation, so we
    #              still can use SimProcedures
    if raise_exception_if_not_found:
        raise SootMethodNotLoadedException
    return SootMethodDescriptor(class_name, method_name, params, ret_type=ret_type)
