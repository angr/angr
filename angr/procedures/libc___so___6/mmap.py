import angr

class mmap(angr.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument

        return self.inline_call(angr.SimProcedures['syscalls']['mmap'],
                                addr,
                                length,
                                prot,
                                flags,
                                fd,
                                offset,
                                ).ret_expr
