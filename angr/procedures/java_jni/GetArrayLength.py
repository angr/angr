from . import JNISimProcedure

class GetArrayLength(JNISimProcedure):

    return_ty = 'int'

    def run(self, ptr_env, array):
        array_ref = self.lookup_local_reference(array)
        return array_ref.size
