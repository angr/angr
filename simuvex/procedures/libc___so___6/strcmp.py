import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

class strcmp(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(32, True)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        a_strlen = strlen(self.state, inline=True, arguments=[a_addr])
        b_strlen = strlen(self.state, inline=True, arguments=[b_addr])
        maxlen = self.state.se.BitVecVal(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

        strncmp = self.inline_call(simuvex.SimProcedures['libc.so.6']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen)
        return strncmp.ret_expr
