import simuvex

import itertools
fdcount = itertools.count()

class fdwait(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, nfds, readfds, writefds, timeout, readyfds):
        read_mask = self.state.mem_expr(readfds, 32)
        write_mask = self.state.mem_expr(writefds, 32)

        run_count = fdcount.next()
        total_ready = self.state.se.BVV(0, self.state.arch.bits)

        read_fds = [ ]
        for fd,_ in enumerate(read_mask.chop()):
            sym_bit = self.state.se.Unconstrained('fdwait_read_%d_%d'%(run_count,fd), 1)

            fd = self.state.se.BVV(fd, self.state.arch.bits)
            sym_newbit = self.state.se.If(self.state.se.ULT(fd, nfds), sym_bit, 0)
            total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
            read_fds.append(sym_newbit)

        write_fds = [ ]
        for fd,_ in enumerate(write_mask.chop()):
            sym_bit = self.state.se.Unconstrained('fdwait_write_%d_%d'%(run_count,fd), 1)

            fd = self.state.se.BVV(fd, self.state.arch.bits)
            sym_newbit = self.state.se.If(self.state.se.ULT(fd, nfds), sym_bit, 0)
            total_ready += sym_newbit.zero_extend(self.state.arch.bits - 1)
            write_fds.append(sym_newbit)

        self.state.store_mem(readfds, self.state.se.Concat(*read_fds))
        self.state.store_mem(writefds, self.state.se.Concat(*write_fds))
        self.state.store_mem(readyfds, total_ready)

        self.state.cgc.time += self.state.se.If(total_ready == 0, timeout, 0)

        # TODO: errors
        return self.state.BVV(0, self.state.arch.bits)
