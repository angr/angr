import simuvex
from itertools import count

fastpath_data_counter = count()

class receive(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, buf, count, rx_bytes):

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            if not self.state.se.symbolic(count):
                actual_size = count
                data = self.state.se.Unconstrained(
                    'receive_data_%d' % fastpath_data_counter.next(),
                    self.state.se.exactly_int(actual_size) * 8
                )
                self.state.store_mem(buf, data)
            else:
                actual_size = self.state.se.Unconstrained('receive_length', self.state.arch.bits)
            self.state.store_mem(rx_bytes, actual_size, endness='Iend_LE')

            return self.state.se.BVV(0, self.state.arch.bits)

        if ABSTRACT_MEMORY in self.state.options:
            actual_size = count
        else:
            actual_size = self.state.se.Unconstrained('receive_length', self.state.arch.bits)
            self.state.add_constraints(self.state.se.ULE(actual_size, count), action=True)

        if self.state.satisfiable(extra_constraints=[count != 0]):
            data = self.state.posix.read(fd, count)
            self.state.store_mem(buf, data, size=actual_size)

        self.state.store_mem(rx_bytes, actual_size, condition=rx_bytes != 0, endness='Iend_LE')

        # TODO: receive failure
        return self.state.se.BVV(0, self.state.arch.bits)

from simuvex.s_options import ABSTRACT_MEMORY
