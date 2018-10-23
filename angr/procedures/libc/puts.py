import angr
from angr.sim_type import SimTypeString, SimTypeInt

######################################
# puts
######################################

class puts(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(32, True)

        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        length = self.inline_call(strlen, string).ret_expr
        out = stdout.write(string, length)
        stdout.write_data(self.state.solver.BVV(b'\n'))
        return out + 1
