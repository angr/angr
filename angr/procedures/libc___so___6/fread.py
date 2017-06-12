import simuvex

from . import io_file_data_for_arch

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        ret = self.state.posix.read(fd, dst, size * nm)
        return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret / size)
