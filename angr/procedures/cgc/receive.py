from itertools import count

import angr

from ... import sim_options as o
from ...state_plugins.sim_action import SimActionData

fastpath_data_counter = count()

class receive(angr.SimProcedure):
    #pylint:disable=arguments-differ,attribute-defined-outside-init,missing-class-docstring,redefined-outer-name

    def run(self, fd, buf, count, rx_bytes):
        if o.CGC_ENFORCE_FD in self.state.options:
            fd = 0

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        if self.state.mode == 'fastpath':
            # Special case for CFG generation
            if not self.state.solver.symbolic(count):
                data = self.state.solver.Unconstrained(
                    f'receive_data_{next(fastpath_data_counter)}',
                    self.state.solver.eval_one(count) * 8
                )
                self.state.memory.store(buf, data)
            else:
                count = self.state.solver.Unconstrained('receive_length', self.state.arch.bits)
            self.state.memory.store(rx_bytes, count, endness='Iend_LE')

            return self.state.solver.BVV(0, self.state.arch.bits)

        # check invalid memory accesses
        # rules for invalid: greater than 0xc0 or wraps around
        if self.state.solver.max_int(buf + count) > 0xc0000000 or \
                self.state.solver.min_int(buf + count) < self.state.solver.min_int(buf):
            return 2
        try:
            writable = self.state.solver.eval(self.state.memory.permissions(self.state.solver.eval(buf))) & 2 != 0
        except angr.SimMemoryError:
            writable = False
        if not writable:
            return 2

        if o.CGC_NO_SYMBOLIC_RECEIVE_LENGTH in self.state.options:
            count = self.state.solver.eval(count)
            if self.state.cgc.max_receive_size > 0:
                count = min(count, self.state.cgc.max_receive_size)

            do_concrete_update = o.UNICORN_HANDLE_SYMBOLIC_ADDRESSES in self.state.options or \
                o.UNICORN_HANDLE_SYMBOLIC_CONDITIONS in self.state.options
            read_length = simfd.read(buf, count, short_reads=False, do_concrete_update=do_concrete_update)
            if type(read_length) is int:
                read_length = self.state.solver.BVV(read_length, 32)
            self.state.memory.store(rx_bytes, read_length, condition=rx_bytes != 0, endness='Iend_LE')
            self.size = read_length

            return 0
        else:
            if self.state.solver.solution(count != 0, True):
                data, read_length = simfd.read_data(count)
                if not self.state.solver.is_true(read_length == 0):
                    self.state.memory.store(buf, data, size=read_length)
                action_list = list(self.state.history.recent_actions)

                try:
                    # get and fix up the memory write
                    action = next(
                        a for a in reversed(action_list) if
                        isinstance(a, SimActionData) and a.action == 'write' and a.type == 'mem'
                    )
                    action.size.ast = read_length
                    action.data.ast = action.actual_value.ast
                    self.data = data
                except StopIteration:
                    # the write didn't occur (i.e., size of 0)
                    self.data = None
            else:
                self.data = None

            self.size = read_length
            if type(read_length) is int:
                read_length = self.state.solver.BVV(read_length, 32)
            self.state.memory.store(rx_bytes, read_length, condition=rx_bytes != 0, endness='Iend_LE')
            return 0
