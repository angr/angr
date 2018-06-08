from . import JNISimProcedure

import logging
l = logging.getLogger('angr.procedures.java_jni.getarrayregion')

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
        javavm_memory = self.state.get_javavm_view_of_plugin("memory")
        elements = javavm_memory.load_array_elements(array, start_idx, no_of_elements)

        # and store them in the native memory
        self.store_in_native_memory(data=elements, data_type=array.type, addr=ptr_buf)

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
        # => 0 <= start_idx < array_size
        # => start_idx <= last_idx < array_size
        #    with last_idx := start_idx+length-1
        # => 0 <= length <= array_size
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
                    "Every combination of start_idx %s and length %s is invalid (array length %s)."
                    % (start_idx, length, array.size))
            return False

        if False in range_stays_within_bounds and \
           True  in range_stays_within_bounds:
           # There are some combination of start_idx and length, s.t.
           # the range exceeds array bounds.
           # For now, just constraint values to stay within bounds.
           # TODO split current SimState into two successors:
           #      --> one w/ all valid indexes
           #      --> one w/ all invalid indexes and a raised exception
           l.warning("Possible out-of-bounds access! "
                     "Constraint start_idx %s and length %s to valid values (array length %s)." 
                     % (start_idx, length, array.size))
           state.solver.add(range_constraints)

        return True
