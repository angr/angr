
from . import JNISimProcedure

# pylint: disable=arguments-differ,unused-argument

class GetVersion(JNISimProcedure):

    return_ty = 'int'

    def run(self, ptr_env):
        # return JNI version 1.8
        return 0x00010008
