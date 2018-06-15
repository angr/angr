from . import JNISimProcedure

from ...engines.soot.virtual_dispatcher import resolve_method
from archinfo import ArchSoot

class GetMethodID(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_class_, ptr_method_name, ptr_method_sig):
        
        # object class name
        obj_class = self.state.jni_references.lookup(obj_class_)
        obj_class_name = obj_class.class_name

        # method name
        method_name = self._load_string_from_native_memory(ptr_method_name)

        # param and return types
        method_sig = self._load_string_from_native_memory(ptr_method_sig)
        params, ret = ArchSoot.decode_method_signature(method_sig)

        # get the SootMethodDescriptor for the method and return a opaque reference to it
        method_id = resolve_method(self.state, method_name, obj_class_name, params, ret)
        return self.state.jni_references.create_new_reference(method_id)
