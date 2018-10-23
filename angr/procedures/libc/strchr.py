import angr
from angr.state_plugins.symbolic_memory import MultiwriteAnnotation
from angr.sim_type import SimTypeString, SimTypeInt, SimTypeChar

import logging
l = logging.getLogger("angr.procedures.libc.strchr")

class strchr(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s_addr, c_int, s_strlen=None):
        c = c_int[7:0]

        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                       1: SimTypeInt(32, True)} # ?
        self.return_type = self.ty_ptr(SimTypeChar()) # ?

        s_strlen = self.inline_call(angr.SIM_PROCEDURES['libc']['strlen'], s_addr)

        if self.state.solver.symbolic(s_strlen.ret_expr):
            l.debug("symbolic strlen")
            # TODO: more constraints here to make sure we don't search too little
            max_sym = min(self.state.solver.max_int(s_strlen.ret_expr), self.state.libc.max_symbolic_strchr)
            a, c, i = self.state.memory.find(s_addr, c, s_strlen.max_null_index, max_symbolic_bytes=max_sym, default=0)
        else:
            l.debug("concrete strlen")
            max_search = self.state.solver.eval(s_strlen.ret_expr)
            a, c, i = self.state.memory.find(s_addr, c, max_search, default=0)

        if len(i) > 1:
            a = a.annotate(MultiwriteAnnotation())
            self.state.add_constraints(*c)

        return a
        #self.state.add_constraints(self.state.solver.ULT(a - s_addr, s_strlen.ret_expr))
        #self.max_chr_index = max(i)
        #return a
