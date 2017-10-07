import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger("angr.procedures.libc.tolower")


class tolower(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {0: SimTypeInt(self.state.arch, True)}
        self.return_type = SimTypeInt(self.state.arch, True)

        if not self.state.solver.symbolic(c):
            try:
                ret_expr = chr(self.state.solver.eval(c)).lower()
            except ValueError:  # not in range(256)
                ret_expr = c
            return ret_expr
        else:
            return self.state.solver.If(
                self.state.solver.And(c >= 65, c <= 90),  # A - Z
                c + 32, c)
