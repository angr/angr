import simuvex
from simuvex.s_type import SimTypeFd, SimTypeInt
from claripy import BVV
######################################
# fgetc
######################################


class fgetc(simuvex.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeInt(32, True)
        data = self.inline_call(
            simuvex.SimProcedures['libc.so.6']['_IO_getc'], fd).ret_expr
        return data
