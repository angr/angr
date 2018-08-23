import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

from . import io_file_data_for_arch

######################################
# fgets
######################################

class fgets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, file_ptr):
        self.argument_types = {2: SimTypeFd(),
                               0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
                               1: SimTypeLength(self.state.arch)}
        self.return_type = self.argument_types[0]

        # let's get the memory back for the file we're interested in and find the newline
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        data, real_size = simfd.read_data(size-1)

        for i, byte in enumerate(data.chop(8)):
            self.state.solver.add(self.state.solver.If(
                i+1 != real_size, byte != '\n', # if not last byte returned, not newline
                self.state.solver.Or( # otherwise one of the following must be true
                    i+2 == size, # we ran out of space, or
                    byte == '\n' # it is a newline
                )))

        self.state.memory.store(dst, data, size=real_size)
        self.state.memory.store(dst+real_size, '\0')

        return real_size
