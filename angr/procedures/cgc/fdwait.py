import angr

import itertools
fdcount = itertools.count()

class fdwait(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, nfds, readfds, writefds, timeout, readyfds):

        run_count = next(fdcount)
        total_ready = self.state.solver.BVV(0, self.state.arch.bits)

        read_fds = [ ]
        for fd in range(32):
            if angr.options.CGC_NON_BLOCKING_FDS in self.state.options:
                sym_bit = self.state.solver.BVV(1, 1)
            else:
                sym_bit = self.state.solver.Unconstrained('fdwait_read_%d_%d'%(run_count,fd), 1, key=('syscall', 'fdwait', fd, 'read_ready'))
            fd = self.state.solver.BVV(fd, self.state.arch.bits)
            sym_newbit = self.state.solver.If(self.state.solver.ULT(fd, nfds), sym_bit, 0)
            total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
            read_fds.append(sym_newbit)
        self.state.memory.store(readfds, self.state.solver.Concat(*read_fds), condition=readfds != 0)

        write_fds = [ ]
        for fd in range(32):
            if angr.options.CGC_NON_BLOCKING_FDS in self.state.options:
                sym_bit = self.state.solver.BVV(1, 1)
            else:
                sym_bit = self.state.solver.Unconstrained('fdwait_write_%d_%d' % (run_count, fd), 1, key=('syscall', 'fdwait', fd, 'write_ready'))

            fd = self.state.solver.BVV(fd, self.state.arch.bits)
            sym_newbit = self.state.solver.If(self.state.solver.ULT(fd, nfds), sym_bit, 0)
            total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
            write_fds.append(sym_newbit)
        self.state.memory.store(writefds, self.state.solver.Concat(*write_fds), condition=writefds != 0)

        self.state.memory.store(readyfds, total_ready, endness='Iend_LE', condition=readyfds != 0)

        tv_sec = self.state.memory.load(timeout, 4, endness=self.state.arch.memory_endness, condition=timeout != 0, fallback=0)
        tv_usec = self.state.memory.load(timeout + 4, 4, endness=self.state.arch.memory_endness, condition=timeout != 0, fallback=0)
        total_time = tv_sec*1000000 + tv_usec
        self.state.cgc.time += self.state.solver.If(total_ready == 0, total_time, 0)

        # TODO: errors
        return self.state.solver.BVV(0, self.state.arch.bits)
