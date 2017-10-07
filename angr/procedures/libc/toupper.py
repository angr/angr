import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger("angr.procedures.libc.toupper")


class toupper(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {0: SimTypeInt(self.state.arch, True)}
        self.return_type = SimTypeInt(self.state.arch, True)

        if not self.state.solver.symbolic(c):
            try:
                ret_expr = ord(chr(self.state.solver.eval(c)).upper())
            except ValueError:  # not in range(256)
                ret_expr = c
            return ret_expr
        else:
            return self.state.solver.If(
                self.state.solver.And(c >= 97, c <= 122),  # a - z
                c - 32, c)
