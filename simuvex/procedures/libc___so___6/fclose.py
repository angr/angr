import simuvex

from . import io_file_data_for_arch

######################################
# fclose
######################################

class fclose(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_p):
        
        # Resolve file descriptor
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[fd_p + fd_offset:].int.resolved
        
        sys_close = simuvex.SimProcedures['syscalls']['close']
        
        # Call system close and return
        retval = sys_close(self.state, inline=True, arguments=[self.state.se.any_int(fileno)]).ret_expr
        
        return retval


