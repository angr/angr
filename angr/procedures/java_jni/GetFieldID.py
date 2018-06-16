from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_InstanceFieldRef
from archinfo.arch_soot import SootFieldDescriptor, ArchSoot

import logging
l = logging.getLogger('angr.procedures.java_jni.getfieldid')

class GetFieldID(JNISimProcedure):

    return_ty = None
    is_static_field = None
    
    def run(self, ptr_env, field_class_, ptr_field_name, ptr_field_sig):
        # class
        field_class = self.state.jni_references.lookup(field_class_)
        # name 
        field_name = self._load_string_from_native_memory(ptr_field_name)
        # type
        field_sig = self._load_string_from_native_memory(ptr_field_sig)
        field_type = ArchSoot.decode_type_signature(field_sig)

        return self._get_field_id(field_class.class_name, field_name,
                                  field_type, self.is_static_field)

    def _get_field_id(self, class_name, field_name, field_type, is_static_field):
        # walk up in class hierarchy
        class_hierarchy = self.state.javavm_classloader.get_class_hierarchy(class_name)
        for class_ in class_hierarchy:
            # check for every class, if it contains the field
            if self._class_contains_field(class_, field_name, field_type, is_static_field):
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

    def _class_contains_field(self, field_class, field_name, field_type, is_static_field):
        # check if a field with the given name exists
        if not field_name in field_class.fields:
            return False
        field = field_class.fields[field_name]
        
        # check type
        if field[1] != field_type:
            return False
        
        # if field is static, check if field attributes contains STATIC
        # otherwise, check that field attributes does not contain STATIC
        if (not is_static_field and "STATIC" in field[0]) or \
           (is_static_field and not "STATIC" in field[0]):
           return False

        return True 

class GetInstanceFieldID(GetFieldID):

    return_ty = 'reference'
    is_static_field = False

class GetStaticFieldID(GetFieldID):

    return_ty = 'reference'
    is_static_field = True
