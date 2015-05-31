import simuvex

class mmap(simuvex.SimProcedure):
    def run(self, addr, length, prot, flags, fd, offset): #pylint:disable=arguments-differ,unused-argument
        #if self.state.se.symbolic(flags) or self.state.se.any_int(flags) != 0x22:
        #   raise Exception("mmap with other than MAP_PRIVATE|MAP_ANONYMOUS unsupported")

        if self.state.se.symbolic(length):
            size = self.state.se.max_int(length)
            if size > self.state.libc.max_variable_size:
                size = self.state.libc.max_variable_size
        else:
            size = self.state.se.any_int(length) * 8

        # mmap on the heap, lol
        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size
        return addr
