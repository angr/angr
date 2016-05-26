import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt, SimTypeChar

import logging
l = logging.getLogger("simuvex.procedures.libc.strchr")

class strchr(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s_addr, c_int, s_strlen=None):
        c = c_int[7:0]

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: SimTypeInt(32, True)} # ?
        self.return_type = self.ty_ptr(SimTypeChar()) # ?

        s_strlen = self.inline_call(simuvex.SimProcedures['libc.so.6']['strlen'], s_addr)

        if self.state.se.symbolic(s_strlen.ret_expr):
            l.debug("symbolic strlen")
            # TODO: more constraints here to make sure we don't search too little
            max_sym = min(self.state.se.max_int(s_strlen.ret_expr), self.state.libc.max_symbolic_strchr)
            a, c, i = self.state.memory.find(s_addr, c, s_strlen.max_null_index, max_symbolic_bytes=max_sym, default=0)
        else:
            l.debug("symbolic strlen")
            max_search = self.state.se.any_int(s_strlen.ret_expr)
            a, c, i = self.state.memory.find(s_addr, c, max_search, default=0)

        if len(i) == 0:
            self.symbolic_return = False
        else:
            self.symbolic_return = True
            self.state.add_constraints(*c)

        return a
        #self.state.add_constraints(self.state.se.ULT(a - s_addr, s_strlen.ret_expr))
        #self.max_chr_index = max(i)
        #return a
