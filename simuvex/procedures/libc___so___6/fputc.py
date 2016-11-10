import simuvex

from . import io_file_data_for_arch

######################################
# fputc
######################################

class fputc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, c, file_ptr):
        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        self.state.posix.write(fileno, c[7:0], 1)

        return c & 0xff
