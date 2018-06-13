from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_InstanceFieldRef
from archinfo.arch_soot import SootFieldDescriptor

import logging
l = logging.getLogger('angr.procedures.java_jni.getfieldid')

class GetFieldID(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_class_, ptr_field_name, ptr_field_sig):
        # lookup parameter
        obj_class = self.state.jni_references.lookup(obj_class_)
        # get field name
        field_name = self._load_string_from_native_memory(ptr_field_name)
        # get field type
        field_sig = self._load_string_from_native_memory(ptr_field_sig)
        field_type = self.state.project.simos.get_java_type_from_signature(field_sig)
        # walk up in the class hierarchy until the field is found
        classes = [self.state.javavm_classloader.get_class(obj_class.class_name)]
        while classes[-1]:
            # if this class contains the field
            if self._class_contains_field(classes[-1], field_name, field_type):
                # then create the field id
                field_id = SootFieldDescriptor(class_name=classes[-1].name, 
                                               name=field_name,
                                               type_=field_type)
                # and return an opaque reference to it
                return self.state.jni_references.create_new_reference(field_id)

            else:
                # otherwise try again with the superclass
                classes.append(self.state.javavm_classloader.get_superclass(classes[-1].name))

        else:
            # field couldn't be found 
            # => return null and (TODO:) throw an NoSuchFieldError
            l.debug("Couldn't find field '{field_name}' in classes {class_names}."
                    "".format(class_names=[str(c.name) for c in classes[:-1]], field_name=field_name))
            return 0

    def _class_contains_field(self, field_class, field_name, field_type):
        # check if a field with the given name exists
        if not field_name in field_class.fields:
            return False
        # check the type
        if field_class.fields[field_name][1] != field_type:
            return False
        return True 
