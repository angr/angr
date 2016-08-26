import simuvex

class transmit(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, buf, count, tx_bytes):

        if simuvex.options.CGC_ENFORCE_FD in self.state.options:
            fd = 1

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            self.state.memory.store(tx_bytes, count, endness='Iend_LE')
            return self.state.se.BVV(0, self.state.arch.bits)

        if ABSTRACT_MEMORY in self.state.options:
            data = self.state.memory.load(buf, count)
            self.state.posix.write(fd, data, count)

            self.state.memory.store(tx_bytes, count, endness='Iend_LE')

        else:
            # rules for invalid
            # greater than 0xc0 or wraps around
            if self.state.se.max_int(buf + count) > 0xc0000000 or \
                    self.state.se.min_int(buf + count) < self.state.se.min_int(buf):
                return 2

            try:
                readable = self.state.se.any_int(self.state.memory.permissions(self.state.se.any_int(buf))) & 1 != 0
            except simuvex.SimMemoryError:
                readable = False
            if not readable:
                return 2

            if self.state.se.solution(count != 0, True):
                data = self.state.memory.load(buf, count)
                self.state.posix.write(fd, data, count)
                self.data = data
            else:
                self.data = None

            self.size = count
            self.state.memory.store(tx_bytes, count, endness='Iend_LE', condition=tx_bytes != 0)

        # TODO: transmit failure
        return self.state.se.BVV(0, self.state.arch.bits)

from simuvex.s_options import ABSTRACT_MEMORY
