import simuvex

from . import _IO_FILE

######################################
# fclose
######################################

class fclose(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd_p):
        
        # Resolve file descriptor
        fd_offset = _IO_FILE[self.state.arch.name]['fd']
        fileno = self.state.mem[fd_p + fd_offset:].int.resolved
        
        sys_close = simuvex.SimProcedures['syscalls']['close']
        
        # Call system close and return
        retval = sys_close(self.state, inline=True, arguments=[self.state.se.any_int(fileno)]).ret_expr
        
        return retval


