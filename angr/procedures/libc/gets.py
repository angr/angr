import angr

######################################
# gets
######################################

class gets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst):
        simfd = self.state.posix.get_fd(0)
        if simfd is None or dst == 0:
            #TODO: errno should be set to EINVAL
            return 0

        #data is symbolic, we read the same amount of code as unrestricted %s scanf
        data, real_size = simfd.read_data(self.state.libc.buf_symbolic_bytes)
        
        if real_size == 0:
            return 0
        
        for i, byte in enumerate(data.chop(8)):
            self.state.solver.add(self.state.solver.If(
                i+1 != real_size, byte != b'\n', # if not last byte returned, not newline
                self.state.solver.Or( # otherwise one of the following must be true
                    i+2 == size, # we ran out of space, or
                    byte == b'\n' # it is a newline
                )))

        self.state.memory.store(dst, data, size=real_size)
        self.state.memory.store(dst+real_size, b'\0')
        return dst
