import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd):
        if type(fd) == simuvex.s_action_object.SimActionObject:
            fd = self.state.se.any_int(fd)
        
        # Return error if file is already closed
        if self.state.posix.files[fd].closed == True:
            v = self.state.se.BVV(-1, self.state.arch.bits)

        # Otherwise close it and return good
        else:
            self.state.posix.close(fd)
            v = self.state.se.BVV(0, self.state.arch.bits)
        
        return v
