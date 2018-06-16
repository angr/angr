from . import JNISimProcedure

from archinfo.arch_soot import ArchSoot, SootMethodDescriptor

class GetMethodID(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, class_, ptr_method_name, ptr_method_sig):
        
        # class name
        class_name = self.state.jni_references.lookup(class_).class_name

        # method name
        method_name = self._load_string_from_native_memory(ptr_method_name)

        # param and return types
        method_sig = self._load_string_from_native_memory(ptr_method_sig)
        params, ret = ArchSoot.decode_method_signature(method_sig)

        # create SootMethodDescriptor as id and return a opaque reference to it
        # Note: we do not resolve the method at this point, because the method id can be 
        #       used with different objects
        #       TODO test case
        #       used both for virtual invokes and special invokes (see invoke expr in Soot
        #       engine). The actual invoke type gets determined later, based on the type
        #       of jni function (Call<Type>Method vs. CallNonVirtual<Type>Method)
        method_id = SootMethodDescriptor(class_name=class_name, name=method_name, 
                                         params=params, ret=ret)
        return self.state.jni_references.create_new_reference(method_id)
