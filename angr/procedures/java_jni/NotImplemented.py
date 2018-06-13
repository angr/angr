from . import JNISimProcedure
import logging
l = logging.getLogger("angr.procedures.java_jni.NotImplemented")

class NotImplemented(JNISimProcedure):

    return_ty = 'void'

    def run(self):
        l.warning("SimProcedure for JNI function not implemented. Returning an unconstrained symbol.")
        native_arch_size = self.state.project.simos.native_arch.bits
        return self.state.solver.Unconstrained('unconstrained_ret_of_jni_func', native_arch_size)
