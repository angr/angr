import angr
from angr.sim_type import SimTypeString

class strdup(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
        malloc = angr.SIM_PROCEDURES['libc']['malloc']

        src_len = self.inline_call(strlen, s).ret_expr
        new_s = self.inline_call(malloc, src_len+1).ret_expr

        self.inline_call(strncpy, new_s, s, src_len+1, src_len=src_len)

        return new_s
