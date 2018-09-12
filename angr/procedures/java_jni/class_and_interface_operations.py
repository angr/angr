import logging

from . import JNISimProcedure

l = logging.getLogger('angr.procedures.java_jni.getsuperclass')

# pylint: disable=arguments-differ,unused-argument

class GetSuperclass(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, class_):
        class_descriptor = self.state.jni_references.lookup(class_)
        if class_descriptor.name == "java.lang.Object":
            return 0
        superclass = self.state.javavm_classloader.get_superclass(class_descriptor)
        if superclass:
            return self.state.jni_references.create_new_reference(superclass)
        else:
            l.error("Couldn't identify superclass of %r", class_descriptor)
            return 0

class FindClass(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, name_ptr):
        class_name = self._load_string_from_native_memory(name_ptr)
        class_descriptor = self.state.javavm_classloader.get_class(class_name, init_class=True)
        return self.state.jni_references.create_new_reference(class_descriptor)
