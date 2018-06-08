from . import JNISimProcedure

from ...engines.soot.expressions.newArray import SimSootExpr_NewArray

class NewArray(JNISimProcedure):

    array_type = None
    return_ty = 'reference'

    def run(self, ptr_env, length_):
        length = self._normalize_array_idx(length_)
        # create new array
        array = SimSootExpr_NewArray.new_array(self.state, self.array_type, length)
        # map array to a local JNI reference
        opaque_ref = self.state.jni_references.create_new_reference(java_ref=array)
        return opaque_ref

class NewBooleanArray(NewArray):
    array_type = "boolean"

class NewByteArray(NewArray):
    array_type = "byte"

class NewCharArray(NewArray):
    array_type = "char"

class NewShortArray(NewArray):
    array_type = "short"

class NewIntArray(NewArray):
    array_type = "int"

class NewLongArray(NewArray):
    array_type = "long"