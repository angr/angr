from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_InstanceFieldRef

class SetField(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, obj_, field_id_, value_):
        # lookup parameter
        obj = self.state.jni_references.lookup(obj_)
        field_id = self.state.jni_references.lookup(field_id_)
        # get field reference
        field_ref = SimSootValue_InstanceFieldRef(heap_alloc_id=obj.heap_alloc_id, 
                                                  class_name=field_id.class_name,
                                                  field_name=field_id.name,
                                                  type_=field_id.type)
        # cast value to java type
        value = self.state.project.simos.cast_primitive(value=value_.to_claripy(), 
                                                        to_type=field_id.type)
        # store value in java memory
        javavm_memory = self.state.get_javavm_view_of_plugin('memory')
        javavm_memory.store(field_ref, value)
