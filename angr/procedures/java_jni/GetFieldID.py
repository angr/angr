from . import JNISimProcedure

import itertools

from ...engines.soot.values import SimSootValue_InstanceFieldRef

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

        # check if field is valid
        if self._is_valid_field(obj_class.class_name, field_name, field_type):
            # valid field
            # => return reference of that field
            # => w/o the object we can only return a "dummy" reference to this
            #    GetField and SetField function will take care of this
            field_id = SimSootValue_InstanceFieldRef(heap_alloc_id="dummy", 
                                                     class_name=obj_class.class_name,
                                                     field_name=field_name,
                                                     type_=field_type)
            opaque_ref = self.state.jni_references.create_new_reference(field_id)
            return opaque_ref

        else:
            # field couldn't be found 
            # => return null and (TODO:) throw an NoSuchFieldError 
            return 0


    def _is_valid_field(self, class_name, field_name, field_type):

        java_binary = self.state.project.loader.main_object

        # get class, containing this field
        # TODO: consider fields from superclasses
        try:
            field_class = java_binary.classes[class_name]
        except KeyError:
            l.debug("Couldn't find class {class_name}, while trying to access field {field_name}"
                    "".format(class_name=class_name, field_name=field_name))
            return False

        # check if the field is available
        if not field_name in field_class.fields:
            l.debug("Couldn't find field {field_name} in class {class_name}"
                    "".format(class_name=class_name, field_name=field_name))
            return False

        # finally, check the type
        if field_class.fields[field_name][1] != field_type:
            return False

        return True 

    def _load_string_from_native_memory(self, addr_):

        # check if addr is symbolic
        if self.state.solver.symbolic(addr_):
            l.error("Loading strings from symbolic addresses is not implemented. "
                    "Continue execution with an empty string.")
            return ""
        addr = self.state.solver.eval(addr_)

        # load chars one by one
        chars = []
        for i in itertools.count():
            str_byte = self.state.memory.load(addr+i, size=1)
            if self.state.solver.symbolic(str_byte):
                l.error("Loading strings with symbolic chars is not implemented "
                        "Continue execution with an empty string.")
                return ""
            str_byte = self.state.solver.eval(str_byte)
            if str_byte == 0:
                break
            chars.append(chr(str_byte))

        return "".join(chars)
