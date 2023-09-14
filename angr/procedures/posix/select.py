import angr


class select(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, nfds, readfds, writefds, exceptfds, timeout):  # pylint: disable=unused-argument
        try:
            nfds_v = self.state.solver.eval_one(nfds)
            # readfds_v = self.state.solver.eval_one(readfds)
            writefds_v = self.state.solver.eval_one(writefds)
            exceptfds_v = self.state.solver.eval_one(exceptfds)
        except angr.errors.SimSolverError:
            raise angr.errors.SimProcedureArgumentError("Can't handle symbolic select arguments")

        if writefds_v != 0 or exceptfds_v != 0:
            raise angr.errors.SimProcedureError("Can't handle write or exception events in select")

        arch_bits = self.arch.bits
        arch_bytes = self.arch.bytes

        long_array = []
        long_array_size = ((nfds_v - 1) + arch_bits) // arch_bits
        for offset in range(0, long_array_size):
            long = self.state.memory.load(readfds + offset * arch_bytes, arch_bytes, endness=self.arch.memory_endness)
            long_array.append(long)
        for i in range(0, nfds_v - 1):
            # get a bit
            long_pos = i // arch_bits
            bit_offset = i % arch_bits
            bit = long_array[long_pos][bit_offset]

            if bit.symbolic or self.state.solver.eval(bit) == 1:
                # set this bit to symbolic
                long_array[long_pos] = (
                    long_array[long_pos][arch_bits - 1 : bit_offset + 1]
                    .concat(self.state.solver.BVS("fd_state", 1))
                    .concat(long_array[long_pos][bit_offset - 1 :])
                )

        # write things back
        for offset in range(0, long_array_size):
            self.state.memory.store(readfds + offset * arch_bytes, long_array[offset], endness=self.arch.memory_endness)

        retval = self.state.solver.BVV(0, 1).concat(self.state.solver.BVS("select_ret", 31))
        return retval
