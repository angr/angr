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
            l.warning("Symbolic mode %s in JNI function ReleaseArrayElements"
                      "is not supported and gets concretized." % mode_)
        mode = self.state.solver.min(mode_) # avoid JNI_ABORT by taking the minimum

        if mode == self.JNI_ABORT:
            return

        array = self.state.jni_references.lookup(array_)

        # load array elements from native memory 
        # => if size is symbolic, we load the maxmimum number of elements
        max_array_size = self.state.solver.max(array.size)
        elements = self.load_from_native_memory(addr=ptr_elems, 
                                                value_type=array.type, 
                                                no_of_elements=max_array_size)

        # store elements in java memory
        javavm_memory = self.state.get_javavm_view_of_plugin("memory")
        javavm_memory.store_array_elements(array, start_idx=0, data=elements)
