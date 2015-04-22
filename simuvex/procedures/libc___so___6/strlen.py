import simuvex
from simuvex.s_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class strlen(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeLength(self.state.arch)

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len

        r, c, i = self.state.memory.find(s, self.state.BVV(0, 8), max_str_len, max_symbolic_bytes=max_symbolic_bytes)

        self.max_null_index = max(i)
        self.state.add_constraints(*c)
        return r - s
