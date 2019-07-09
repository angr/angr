import logging

from archinfo.arch_soot import SootFieldDescriptor

from .exceptions import SootFieldNotLoadedException


l = logging.getLogger('angr.engines.soot.field_dispatcher')


def resolve_field(state, field_class, field_name, field_type,
                  raise_exception_if_not_found=False):

    # In Java, fields are not polymorphic and the class declaring the field is
    # determined statically by the declaring variable. Also fields are uniquely
    # defined by the tuple (field_name, field_type) and in particular *not* by
    # its attributes (e.g. 'STATIC').
    # => This both together implies that w e do not have to distinguish between
    #    static and instance fields.

    # fields can be defined in superclasses (and TODO: superinterfaces)
    # => walk up in class hierarchy
    class_hierarchy = state.javavm_classloader.get_class_hierarchy(field_class)
    for class_ in class_hierarchy:
        # check for every class, if it contains the field
        if _class_contains_field(class_, field_name, field_type):
            state.javavm_classloader.init_class(class_)
            # if so, create the field_id and return a reference to it
            field_id = SootFieldDescriptor(class_.name, field_name, field_type)
            return field_id

    # field could not be found
    l.warning("Couldn't find field %s in classes %s.", field_name, class_hierarchy)
    if raise_exception_if_not_found:
        raise SootFieldNotLoadedException()
    else:
        return SootFieldDescriptor(field_class, field_name, field_type)

def _class_contains_field(field_class, field_name, field_type):
    # check if field is loaded in CLE
    if not field_class.is_loaded:
        return False
    # check if a field with the given name exists
    if not field_name in field_class.fields:
        return False
    field = field_class.fields[field_name]
    # check type
    if field[1] != field_type:
        return False
    return True
