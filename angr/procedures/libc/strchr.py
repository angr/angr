import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

import logging

l = logging.getLogger(name=__name__)


class strchr(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, s_addr, c_int, s_strlen=None):
        c = c_int[7:0]
        s_strlen = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.solver.symbolic(s_strlen.ret_expr):
            l.debug("symbolic strlen")
            # TODO: more constraints here to make sure we don't search too little
            max_sym = min(self.state.solver.max_int(s_strlen.ret_expr) + 1, self.state.libc.max_symbolic_strchr)
            a, c, i = self.state.memory.find(s_addr, c, s_strlen.max_null_index, max_symbolic_bytes=max_sym, default=0)
        else:
            l.debug("concrete strlen")
            max_search = self.state.solver.eval(s_strlen.ret_expr) + 1
            a, c, i = self.state.memory.find(s_addr, c, max_search, default=0, chunk_size=chunk_size)

        if len(i) > 1:
            a = a.annotate(MultiwriteAnnotation())
            self.state.add_constraints(*c)

        # If we found the character we are looking for, we need to
        # ensure that the string length is long enough to include
        # the character!
        chrpos = a - s_addr
        self.state.add_constraints(self.state.solver.If(a != 0, chrpos <= s_strlen.ret_expr, True))

        return a
        # self.state.add_constraints(self.state.solver.ULT(a - s_addr, s_strlen.ret_expr))
        # self.max_chr_index = max(i)
        # return a
