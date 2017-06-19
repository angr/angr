import simuvex
from itertools import count

fastpath_data_counter = count()

class receive(simuvex.SimProcedure):
    #pylint:disable=arguments-differ,attribute-defined-outside-init,redefined-outer-name

    IS_SYSCALL = True

    def run(self, fd, buf, count, rx_bytes):

        if simuvex.options.CGC_ENFORCE_FD in self.state.options:
            fd = 0

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            if not self.state.se.symbolic(count):
                actual_size = count
                data = self.state.se.Unconstrained(
                    'receive_data_%d' % fastpath_data_counter.next(),
                    self.state.se.exactly_int(actual_size) * 8
                )
                self.state.memory.store(buf, data)
            else:
                actual_size = self.state.se.Unconstrained('receive_length', self.state.arch.bits)
            self.state.memory.store(rx_bytes, actual_size, endness='Iend_LE')

            return self.state.se.BVV(0, self.state.arch.bits)

        if CGC_NO_SYMBOLIC_RECEIVE_LENGTH in self.state.options:
            # rules for invalid
            # greater than 0xc0 or wraps around
            if self.state.se.max_int(buf + count) > 0xc0000000 or \
                    self.state.se.min_int(buf + count) < self.state.se.min_int(buf):
                return 2
            try:
                writable = self.state.se.any_int(self.state.memory.permissions(self.state.se.any_int(buf))) & 2 != 0
            except simuvex.SimMemoryError:
                writable = False
            if not writable:
                return 2

            read_length = self.state.posix.read(fd, buf, count)

            self.state.memory.store(rx_bytes, read_length, condition=rx_bytes != 0, endness='Iend_LE')
            self.size = read_length

            return self.state.se.BVV(0, self.state.arch.bits)
        else:
            if ABSTRACT_MEMORY in self.state.options:
                actual_size = count
            else:
                actual_size = self.state.se.Unconstrained('receive_length', self.state.arch.bits)
                self.state.add_constraints(self.state.se.ULE(actual_size, count), action=True)

            if self.state.se.solution(count != 0, True):
                read_length = self.state.posix.read(fd, buf, actual_size)
                action_list = list(self.state.log.actions)

                try:
                    # get and fix up the memory write
                    action = next(
                        a for a in reversed(action_list) if
                        isinstance(a, SimActionData) and a.action == 'write' and a.type == 'mem'
                    )
                    action.size.ast = actual_size
                    action.data.ast = action.actual_value.ast
                    self.data = self.state.memory.load(buf, read_length)
                except StopIteration:
                    # the write didn't occur (i.e., size of 0)
                    self.data = None
            else:
                self.data = None

            self.size = actual_size
            self.state.memory.store(rx_bytes, actual_size, condition=rx_bytes != 0, endness='Iend_LE')

            # return values
            return self.state.se.If(
                actual_size == 0,
                self.state.se.BVV(0xffffffff, self.state.arch.bits),
                self.state.se.BVV(0, self.state.arch.bits)
            )

from ...s_options import ABSTRACT_MEMORY, CGC_NO_SYMBOLIC_RECEIVE_LENGTH
from ...s_action import SimActionData
