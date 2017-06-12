import simuvex

class mmap(simuvex.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument

        return self.inline_call(simuvex.SimProcedures['syscalls']['mmap'],
                                addr,
                                length,
                                prot,
                                flags,
                                fd,
                                offset,
                                ).ret_expr
