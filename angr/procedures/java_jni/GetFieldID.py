from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_InstanceFieldRef
from archinfo.arch_soot import SootFieldDescriptor, ArchSoot

import logging
l = logging.getLogger('angr.procedures.java_jni.getfieldid')

class GetFieldID(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_class_, ptr_field_name, ptr_field_sig):

        # object class name
        obj_class = self.state.jni_references.lookup(obj_class_)
        obj_class_name = obj_class.class_name

        # field 
        field_name = self._load_string_from_native_memory(ptr_field_name)

        # field type
        field_sig = self._load_string_from_native_memory(ptr_field_sig)
        field_type = ArchSoot.decode_type_signature(field_sig)

        # walk up in class hierarchy
        class_hierarchy = self.state.javavm_classloader.get_class_hierarchy(obj_class_name)
        for class_ in class_hierarchy:
            # check for every class, if it contains the field
            if self._class_contains_field(class_, field_name, field_type):
                # if so, create the field_id and return an opaque reference to it
                field_id = SootFieldDescriptor(class_.name, field_name, field_type)
                return self.state.jni_references.create_new_reference(field_id)

        else:
            # field couldn't be found 
            # => return null and (TODO:) throw an NoSuchFieldError
            l.debug("Couldn't find field '{field_name}' in classes {class_names}."
                    "".format(class_names=[str(c.name) for c in class_hierarchy],
                              field_name=field_name))
            return 0

    def _class_contains_field(self, field_class, field_name, field_type):
        # check if a field with the given name exists
        if not field_name in field_class.fields:
            return False
        # check the type
        if field_class.fields[field_name][1] != field_type:
            return False
        return True 
