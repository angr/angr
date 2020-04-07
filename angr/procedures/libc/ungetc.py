import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fputc
######################################

class ungetc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, c, file_ptr):
        # TODO handle errors
        # TODO THIS DOESN'T WORK IN ANYTHING BUT THE TYPICAL CASE
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.concrete
        if hasattr(self.state.posix.fd[fileno], '_read_pos'):
            self.state.posix.fd[fileno]._read_pos -= 1
        else:
            self.state.posix.fd[fileno]._pos -= 1

        return c & 0xff
