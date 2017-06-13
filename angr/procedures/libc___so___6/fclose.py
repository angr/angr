import angr

from . import io_file_data_for_arch

######################################
# fclose
######################################

class fclose(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_p):
        # Resolve file descriptor
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[fd_p + fd_offset:].int.resolved

        sys_close = angr.SimProcedures['syscalls']['close']

        # Call system close and return
        retval = self.inline_call(sys_close, fileno).ret_expr

        return retval
