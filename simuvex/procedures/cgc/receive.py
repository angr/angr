import simuvex

class receive(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, buf, count, rx_bytes):

        if ABSTRACT_MEMORY in self.state.options:
            actual_size = count.ast
        else:
            actual_size = self.state.se.Unconstrained('receive_length', self.state.arch.bits)
            self.state.add_constraints(self.state.se.ULE(actual_size, count))

        if self.state.satisfiable(extra_constraints=[count != 0]):
            pos = self.state.posix.get_file(fd)
            data = self.state.posix.read(fd, count)
            self.state.store_mem(buf, data, size=actual_size)

            a = simuvex.SimActionData(self.state, 'file', 'read', fd=fd, addr=pos, size=actual_size, data=data) #, max_size=count)
            self.state.log._add_event(a)

        self.state.store_mem(rx_bytes, actual_size, condition=rx_bytes != 0, endness='Iend_LE')

        # TODO: receive failure
        return self.state.se.BVV(0, self.state.arch.bits)

from simuvex.s_options import ABSTRACT_MEMORY
