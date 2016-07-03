import simuvex

class mmap(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument
        #if self.state.se.symbolic(flags) or self.state.se.any_int(flags) != 0x22:
        #   raise Exception("mmap with other than MAP_PRIVATE|MAP_ANONYMOUS unsupported")

        if self.state.se.symbolic(length):
            size = self.state.se.max_int(length)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(length) * 8

        addr = self.state.libc.mmap_base
        new_base = addr + size
        if new_base & 0xfff:
            new_base = (new_base & ~0xfff) + 0x1000
        self.state.libc.mmap_base = new_base

        self.state.memory.map_region(addr, size, prot[2:0])
        return addr
