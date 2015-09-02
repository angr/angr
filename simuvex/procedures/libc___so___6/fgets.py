import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# fgets
######################################

class fgets(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, fd):
        self.argument_types = {2: SimTypeFd(),
                               0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
                               1: SimTypeLength(self.state.arch)}
        self.return_type = self.argument_types[0]

        ret = self.inline_call(simuvex.SimProcedures['libc.so.6']['read'], fd, dst, size).ret_expr

        return ret
