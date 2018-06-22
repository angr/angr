from . import JNISimProcedure, jni_functions
import logging
l = logging.getLogger("angr.procedures.java_jni.NotImplemented")

class NotImplemented(JNISimProcedure):

    return_ty = 'void'

    def run(self):
        native_arch_size = self.state.project.simos.native_arch.bits

        # get function name
        jni_function_table = self.state.project.simos.jni_function_table
        function_idx = (self.state.addr - jni_function_table) // (native_arch_size//8)
        function_name = jni_functions.keys()[function_idx]

        l.warning("SimProcedure for JNI function '%s' is not implemented. "
                  "Returning unconstrained symbol." % function_name)

        # return unconstrained
        symbol_name = 'unconstrained_ret_of_jni_func_%s' % function_name
        return self.state.solver.Unconstrained(symbol_name, native_arch_size)
