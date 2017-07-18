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

        write = angr.SIM_PROCEDURES['syscalls']['write']
        strlen = angr.SIM_PROCEDURES['libc.so.6']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, self.state.se.BVV(1, self.state.arch.bits), string, length)
        self.state.posix.write(1, self.state.se.BVV(0x0a, 8), 1)

        # TODO: return values
        return self.state.se.Unconstrained('puts', self.state.arch.bits)
