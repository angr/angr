import angr

class mmap(angr.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument

        # TODO: do this the other way around
        return self.inline_call(angr.SIM_PROCEDURES['linux_kernel']['mmap'],
                                addr,
                                length,
                                prot,
                                flags,
                                fd,
                                offset,
                                ).ret_expr
