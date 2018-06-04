from . import JNISimProcedure
from ...engines.soot.values.arrayref import SimSootValue_ArrayRef

class GetArrayElements(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, array, ptr_isCopy):
        array_ref = self.lookup_local_reference(array)
        elements = self.load_java_array(array_ref)
        memory_addr = self.dump_in_native_memory(elements, array_ref.type)
        self.dump_in_native_memory(data=self.JNI_TRUE, data_type='boolean', addr=ptr_isCopy)
        return memory_addr

    def load_java_array(self, array_ref, start_idx=None, end_idx=None):
        if start_idx is None:
            start_idx = 0 
        if end_idx is None:
            end_idx = self.state.solver.max(array_ref.size)

        javavm_memory = self.state.get_javavm_view_of_plugin("memory")
        values = []
        for idx in range(start_idx, end_idx):
            idx_array_ref = SimSootValue_ArrayRef.get_arrayref_for_idx(base=array_ref, idx=idx)
            value = javavm_memory.load(idx_array_ref)
            values.append(value)

        return values