import simuvex

class transmit(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, buf, count, tx_bytes):

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            self.state.memory.store(tx_bytes, count, endness='Iend_LE')
            return self.state.se.BVV(0, self.state.arch.bits)

        if ABSTRACT_MEMORY in self.state.options:
            data = self.state.memory.load(buf, count)
            self.state.posix.write(fd, data, count)

            self.state.memory.store(tx_bytes, count, endness='Iend_LE')

        else:
            if self.state.satisfiable(extra_constraints=[count != 0]):
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
