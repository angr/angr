import simuvex

######################################
# __errno_location
######################################

class __errno_location(simuvex.SimProcedure):

    def run(self):  #pylint:disable=arguments-differ

        if self.state.libc._errno_location is None:
            malloc = simuvex.SimProcedures['libc.so.6']['malloc']
            errno_loc = self.inline_call(malloc, self.state.arch.bits / 8).ret_expr

            self.state.libc._errno_location = errno_loc

            # Overwrite it with 0 since this is the first time of use
            self.state.memory.store(errno_loc, self.state.se.BVV(0, self.state.arch.bits))

        else:
            errno_loc = self.state.libc._errno_location

        return errno_loc
