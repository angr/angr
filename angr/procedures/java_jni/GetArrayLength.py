from . import JNISimProcedure

class GetArrayLength(JNISimProcedure):

    return_ty = 'int'

    def run(self, ptr_env, array_):
        array = self.state.jni_references.lookup(array_)
        return array.size
