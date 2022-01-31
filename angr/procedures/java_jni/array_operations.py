import logging
from typing import Optional

from . import JNISimProcedure
from ...engines.soot.expressions import SimSootExpr_NewArray
from ...engines.soot.values import SimSootValue_ArrayRef

l = logging.getLogger('angr.procedures.java_jni.array_operations')

# pylint: disable=arguments-differ,unused-argument

# pylint: disable=arguments-differ,unused-argument

#
# GetArrayLength
#

class GetArrayLength(JNISimProcedure):

    return_ty = 'int'

    def run(self, ptr_env, array_):
        array = self.state.jni_references.lookup(array_)
        return array.size

#
# New<Type>Array
#

class NewArray(JNISimProcedure):

    element_type: Optional[str] = None
    return_ty = 'reference'

    def run(self, ptr_env, length_):
        length = self._normalize_array_idx(length_)
        array = SimSootExpr_NewArray.new_array(self.state, self.element_type, length)
        return self.state.jni_references.create_new_reference(obj=array)

class NewBooleanArray(NewArray):
    element_type = "boolean"
class NewByteArray(NewArray):
    element_type = "byte"
class NewCharArray(NewArray):
    element_type = "char"
class NewShortArray(NewArray):
    element_type = "short"
class NewIntArray(NewArray):
    element_type = "int"
class NewLongArray(NewArray):
    element_type = "long"

#
# NewObjectArray
#

class NewObjectArray(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, length_, element_type_, initial_element_):

        length = self._normalize_array_idx(length_)
        element_type = self.state.jni_references.lookup(element_type_)

        # create new array
        array = SimSootExpr_NewArray.new_array(self.state, element_type.name, length)

        # if available, set the initial_element as the arrays default value
        if self.state.solver.eval(initial_element_ != 0):
            initial_element = self.state.jni_references.lookup(initial_element_)
            generator = lambda state: initial_element
            array.add_default_value_generator(generator)
        else:
            initial_element = None

        # return reference to array
        return self.state.jni_references.create_new_reference(array)

#
# GetObjectArrayElement / SetObjectArrayElement
#

class GetObjectArrayElement(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, array_, idx_):

        idx = self._normalize_array_idx(idx_)
        array = self.state.jni_references.lookup(array_)

        # check array bounds
        SimSootValue_ArrayRef.check_array_bounds(idx, array, self.state)

        # concretize idx (TODO: handle symbolic idxes)
        if self.state.solver.symbolic(idx):
            idx = self.state.eval(idx)
            l.warning("Symbolic indices are not supported for object arrays %s. "
                      "Index gets concretized to %s", array, idx)

        # load element and return reference to it
        element = self.state.javavm_memory.load_array_element(array, idx)
        return self.state.jni_references.create_new_reference(element)

class SetObjectArrayElement(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, array_, idx_, value_):

        idx = self._normalize_array_idx(idx_)
        array = self.state.jni_references.lookup(array_)
        value = self.state.jni_references.lookup(value_)

        # check array bounds
        SimSootValue_ArrayRef.check_array_bounds(idx, array, self.state)

         # concretize idx (TODO: handle symbolic idxes)
        if self.state.solver.symbolic(idx):
            idx = self.state.eval(idx)
            l.warning("Symbolic indices are not supported for object arrays %s. "
                      "Index gets concretized to %s", array, idx)

        self.state.javavm_memory.store_array_element(array, idx, value)

#
# Get<Type>ArrayElements / Release<Type>ArrayElements
#

class GetArrayElements(JNISimProcedure):

    return_ty = 'reference'

    def run(self, ptr_env, array_, ptr_isCopy):

        array = self.state.jni_references.lookup(array_)

        # load array elements from java memory
        # => if size is symbolic, we load the maximum number of elements
        max_array_length = self.state.solver.max(array.size)
        values = self.state.javavm_memory.load_array_elements(array, start_idx=0, no_of_elements=max_array_length)

        # store elements in native memory
        memory_addr = self._store_in_native_memory(values, array.element_type)

        # if isCopy is not null, store JNI_TRUE at that address
        if self.state.solver.eval(ptr_isCopy != 0):
            self._store_in_native_memory(data=self.JNI_TRUE, data_type='boolean', addr=ptr_isCopy)

        # return native address to the elements
        return memory_addr

class ReleaseArrayElements(JNISimProcedure):

    return_ty = 'void'

    JNI_COMMIT = 1
    JNI_ABORT = 2

    def run(self, ptr_env, array_, ptr_elems, mode_):

        if self.state.solver.symbolic(mode_):
            l.warning("Symbolic mode %s in JNI function ReleaseArrayElements"
                      "is not supported and gets concretized.", mode_)
        mode = self.state.solver.min(mode_) # avoid JNI_ABORT by taking the minimum

        if mode == self.JNI_ABORT:
            return

        array = self.state.jni_references.lookup(array_)

        # load array elements from native memory
        # => if size is symbolic, we load the maximum number of elements
        max_array_size = self.state.solver.max(array.size)
        elements = self._load_from_native_memory(addr=ptr_elems,
                                                 data_type=array.element_type,
                                                 no_of_elements=max_array_size)

        # store elements in java memory
        self.state.javavm_memory.store_array_elements(array, start_idx=0, data=elements)


#
# Get<Type>ArrayRegion / Set<Type>ArrayRegion
#

class GetArrayRegion(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, array_, start_idx_, length_, ptr_buf):

        array = self.state.jni_references.lookup(array_)
        start_idx = self._normalize_array_idx(start_idx_)
        length = self._normalize_array_idx(length_)

        # check if the range (induced by start_idx and length) is valid
        if not self._check_region_bounds(array, start_idx, length, self.state):
            return

        # concretize length (TODO handle symbolic length)
        no_of_elements = self._concretize_region_length(length, self.state)

        # load elements from java memory
        elements = self.state.javavm_memory.load_array_elements(array, start_idx, no_of_elements)

        # and store them in the native memory
        self._store_in_native_memory(data=elements, data_type=array.element_type, addr=ptr_buf)

    @staticmethod
    def _concretize_region_length(length, state):
        # if necessary, concretize length
        # TODO handle symbolic length
        if state.solver.symbolic(length):
            midpoint_length = (state.solver.min(length) + state.solver.max(length)) // 2
            state.solver.add(length == midpoint_length)
            l.warning("Symbolic lengths are currently not supported. "
                      "Length is concretized to a midpoint value.")
        return state.solver.eval_one(length)

    @staticmethod
    def _check_region_bounds(array, start_idx, length, state):
        # A valid range fulfills the following constraints:
        # - 0 <= start_idx < array_size
        # - start_idx <= last_idx < array_size
        #   with last_idx := start_idx+length-1
        # - 0 <= length <= array_size
        range_constraints = state.solver.And(
            start_idx.SGE(0), start_idx.SLT(array.size),
            array.size.SGT(start_idx+length-1),
            length.SGE(0), length.SLE(array.size)
        )

        # Evaluate range constraints
        # => Note: if start_idx and/or length are symbolic, the result can be
        #    True and False at the same time
        range_stays_within_bounds = state.solver.eval_upto(range_constraints, 2)

        if not True in range_stays_within_bounds:
            # There is no valid combination of start_idx and length, s.t. the
            # range stays within the array bounds.
            # Correct simulation must continue with a raised Exception
            # TODO raise java.lang.ArrayIndexOutOfBoundsException
            #      For now, we just skip this SimProcedure.
            l.error("Skipping SimProcedure: "
                    "Every combination of start_idx %s and length %s is invalid (array length %s).",
                    start_idx, length, array.size)
            return False

        if False in range_stays_within_bounds and \
           True  in range_stays_within_bounds:
           # There are some combination of start_idx and length, s.t. the range
           # exceeds array bounds.
           # For now, just constraint values to stay within bounds.
           # TODO split current SimState into two successors:
           #      --> one w/ all valid indexes
           #      --> one w/ all invalid indexes and a raised exception
           l.warning("Possible out-of-bounds access! "
                     "Constraint start_idx %s and length %s to valid values (array length %s).",
                     start_idx, length, array.size)
           state.solver.add(range_constraints)

        return True

class SetArrayRegion(JNISimProcedure):

    return_ty = 'void'

    def run(self, ptr_env, array_, start_idx_, length_, ptr_buf):

        array = self.state.jni_references.lookup(array_)
        start_idx = self._normalize_array_idx(start_idx_)
        length = self._normalize_array_idx(length_)

        # check if the range (induced by start_idx and length) is valid
        if not GetArrayRegion._check_region_bounds(array, start_idx, length, self.state):
            return

        # concretize length (TODO handle symbolic length)
        no_of_elements = GetArrayRegion._concretize_region_length(length, self.state)

        # load elements from native memory
        elements = self._load_from_native_memory(addr=ptr_buf,
                                                 data_type=array.element_type,
                                                 no_of_elements=no_of_elements)

        # and store them in the java memory
        self.state.javavm_memory.store_array_elements(array, start_idx, elements)