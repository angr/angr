
import logging

from claripy import StringV, StrLen

from . import JNISimProcedure
from ...engines.soot.values import SimSootValue_StringRef

l = logging.getLogger('angr.procedures.java_jni.string_operations')

# pylint: disable=arguments-differ,unused-argument

#
# GetStringUTFChars
#

class GetStringUTFChars(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, str_ref_, ptr_isCopy):
         # get string value
        str_ref = self.state.jni_references.lookup(str_ref_)
        str_val = self.state.javavm_memory.load(str_ref)

        # store string in native memory
        addr = self._store_string_in_native_memory(str_val)

        # if isCopy is not null, store JNI_TRUE at that address
        if self.state.solver.eval(ptr_isCopy != 0):
            self._store_in_native_memory(data=self.JNI_TRUE,
                                         data_type='boolean',
                                         addr=ptr_isCopy)

        return addr

#
# ReleaseStringUTFChars
#

class ReleaseStringUTFChars(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, str_ref_, native_buf):
        # FIXME delete this, when claripy fully supports string solving
        # All changes made from the native code to a symbolic string are not
        # reflected in the claripy.String representation (used for Java strings)
        # => when the native code releases a string, the symbolic string gets
        #    replaced with a concretized version that includes all additional
        #    constraints added in the native execution
        str_ref = self.state.jni_references.lookup(str_ref_)
        str_val = self.state.javavm_memory.load(str_ref)
        if self.state.solver.symbolic(str_val):
            str_native = self._load_string_from_native_memory(native_buf)
            self.state.javavm_memory.store(str_ref, StringV(str_native))

#
# NewStringUTF
#

class NewStringUTF(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, ptr_str_bytes):
        # load string from native memory
        str_val = self._load_string_from_native_memory(ptr_str_bytes)

        # create java string and return the reference
        str_ref = SimSootValue_StringRef(self.state.javavm_memory.get_new_uuid())
        self.state.javavm_memory.store(str_ref, StringV(str_val))
        return self.state.jni_references.create_new_reference(str_ref)

#
# GetStringUTFLength
#

class GetStringUTFLength(JNISimProcedure):

    return_ty = 'int'

    def run(self, ptr_env, str_ref_):
        str_ref = self.state.jni_references.lookup(str_ref_)
        str_val = self.state.javavm_memory.load(str_ref)
        return StrLen(str_val, 32)
