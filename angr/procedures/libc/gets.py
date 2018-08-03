import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

from . import io_file_data_for_arch

######################################
# gets
######################################

class gets(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst):       
        # let's get the memory back for the file we're interested in and find the newline
        fd = 0 
        size = 2086 #This is the max size that linux support
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
