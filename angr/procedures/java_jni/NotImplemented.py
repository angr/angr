from . import JNISimProcedure
import logging
l = logging.getLogger("angr.procedures.java_jni.NotImplemented")

class NotImplemented(JNISimProcedure):

    return_ty = 'void'

    def run(self):
        l.warning("SimProcedure for this JNI function is not implemented. State is not updated.")
        return self.state.solver.BVS("ret_of_not_implemented_jni_procedure", 64)