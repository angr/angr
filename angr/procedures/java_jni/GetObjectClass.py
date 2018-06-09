from . import JNISimProcedure

from ...engines.soot.values.constants import SimSootValue_ClassConstant

class GetObjectClass(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, obj_):

        # lookup parameter
        obj = self.state.jni_references.lookup(obj_)
        
        # create bew class constant with object type
        obj_class = SimSootValue_ClassConstant.from_classname(obj.type)

        # return local jni reference
        opaque_ref = self.state.jni_references.create_new_reference(obj_class)
        return opaque_ref
