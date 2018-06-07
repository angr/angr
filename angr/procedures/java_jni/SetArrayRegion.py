from . import JNISimProcedure
from GetArrayRegion import GetArrayRegion

import logging
l = logging.getLogger('angr.procedures.java_jni.setarrayregion')

class SetArrayRegion(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, array_, start_idx_, length_, ptr_buf):
        
        array = self.state.jni_references.lookup(array_)
        start_idx = self._normalize_array_idx(start_idx_)
        length = self._normalize_array_idx(length_)

        # check if the range, induced by start_idx and length, is valid
        if GetArrayRegion._check_region_bounds(array, start_idx, length, self.state):
            no_of_elements = GetArrayRegion._concretize_region_length(length, self.state)
            # load elements from native memory
            elements = self.load_from_native_memory(addr=ptr_buf,
                                                    value_type=array.type,
                                                    no_of_elements=no_of_elements)
            # and store them in the javavm memory
            javavm_memory = self.state.get_javavm_view_of_plugin("memory")
            javavm_memory.store_array_range(array, elements, start_idx, no_of_elements)

        else:
            pass
