from . import JNISimProcedure
from ...engines.soot.values.arrayref import SimSootValue_ArrayRef

import logging
l = logging.getLogger('angr.procedures.java_jni.releasearrayelements')

class ReleaseArrayElements(JNISimProcedure):

    return_ty = 'void'
    
    JNI_COMMIT = 1
    JNI_ABORT = 2

    def run(self, ptr_env, array_, ptr_elems, mode_):

        if self.state.solver.symbolic(mode_):
            l.warning("Symbolic release mode %s is not supported and gets concretized." % str(mode_))
        mode = self.state.solver.min(mode_) # avoid JNI_ABORT by taking the minimum

        if mode != self.JNI_ABORT:
            array = self.state.jni_references.lookup(array_)
            max_array_size = self.state.solver.max(array.size)
            elements = self.load_from_native_memory(addr=ptr_elems, 
                                                    value_type=array.type, 
                                                    no_of_elements=max_array_size)
            self.store_java_array(self.state, elements, array)

    @staticmethod
    def store_java_array(state, values, array_ref, start_idx=None, end_idx=None):
        if start_idx is None:
            start_idx = 0 
        else:
            start_idx = state.solver.min(start_idx)
            
        if end_idx is None:
            end_idx = state.solver.max(array_ref.size)
        else:
            end_idx = state.solver.max(end_idx)

        javavm_memory = state.get_javavm_view_of_plugin("memory")
        for idx in range(start_idx, end_idx):
            idx_array_ref = SimSootValue_ArrayRef.get_arrayref_for_idx(base=array_ref, idx=idx)
            javavm_memory.store(idx_array_ref, values[idx])
