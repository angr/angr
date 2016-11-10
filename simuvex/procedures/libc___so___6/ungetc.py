import simuvex

from . import io_file_data_for_arch

######################################
# fputc
######################################

class ungetc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, c, file_ptr):
        # TODO handle errors
        # TODO THIS DOESN'T WORK IN ANYTHING BUT THE TYPICAL CASE
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.concrete
        self.state.posix.files[fileno].pos -= 1

        return c & 0xff
