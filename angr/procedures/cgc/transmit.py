import angr

class transmit(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, buf, count, tx_bytes):
        if angr.options.CGC_ENFORCE_FD in self.state.options:
            fd = 1

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            self.state.memory.store(tx_bytes, count, endness='Iend_LE')
            return self.state.solver.BVV(0, self.state.arch.bits)

        if ABSTRACT_MEMORY in self.state.options:
            simfd.write(buf, count)
            self.state.memory.store(tx_bytes, count, endness='Iend_LE')

        else:
            if self.state.solver.solution(count != 0, True):

                # rules for invalid
                # greater than 0xc0 or wraps around
                if self.state.solver.max_int(buf + count) > 0xc0000000 or \
                                self.state.solver.min_int(buf + count) < self.state.solver.min_int(buf):
                    return 2

                try:
                    readable = self.state.solver.eval(self.state.memory.permissions(self.state.solver.eval(buf))) & 1 != 0
                except angr.SimMemoryError:
                    readable = False
                if not readable:
                    return 2

                data = self.state.memory.load(buf, count)
                simfd.write_data(data, count)
                self.data = data
            else:
                self.data = None

            self.size = count
            self.state.memory.store(tx_bytes, count, endness='Iend_LE', condition=tx_bytes != 0)

        # TODO: transmit failure
        return self.state.solver.BVV(0, self.state.arch.bits)

from ...sim_options import ABSTRACT_MEMORY
