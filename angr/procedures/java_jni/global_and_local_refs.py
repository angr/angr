
import logging

from . import JNISimProcedure

l = logging.getLogger('angr.procedures.java_jni.global_and_local_references')

# pylint: disable=arguments-differ,unused-argument

#
# NewGlobalRef / NewWeakGlobalRef
#

class NewGlobalRef(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_):
        obj = self.state.jni_references.lookup(obj_)
        return self.state.jni_references.create_new_reference(obj, global_ref=True)

#
# DeleteGlobalRef / DeleteWeakGlobalRef
#

class DeleteGlobalRef(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, obj_):
        self.state.jni_references.delete_reference(obj_, global_ref=True)

#
# NewLocalRef
#

class NewLocalRef(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_):
        obj = self.state.jni_references.lookup(obj_)
        return self.state.jni_references.create_new_reference(obj)

#
# DeleteLocalRef
#

class DeleteLocalRef(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, obj_):
        self.state.jni_references.delete_reference(obj_)
