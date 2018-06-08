from . import JNISimProcedure
from ...engines.soot.values.arrayref import SimSootValue_ArrayRef

class GetArrayElements(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, array_, ptr_isCopy):

        array = self.state.jni_references.lookup(array_)

        # load array elements from java memory 
        # => if size is symbolic, we load the maxmimum number of elements
        max_array_length = self.state.solver.max(array.size)
        javavm_memory = self.state.get_javavm_view_of_plugin("memory")
        values = javavm_memory.load_array_elements(array, start_idx=0, no_of_elements=max_array_length)

        # store elements in native memory
        memory_addr = self.store_in_native_memory(values, array.type)

        # if isCopy is not null, store JNI_TRUE at that address
        if self.state.solver.eval(ptr_isCopy != 0):
            self.store_in_native_memory(data=self.JNI_TRUE, data_type='boolean', addr=ptr_isCopy)
        
        # return native address to the elements
        return memory_addr