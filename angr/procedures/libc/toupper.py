import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger(name=__name__)


class toupper(angr.SimProcedure):
    def run(self, c):
        self.argument_types = {0: SimTypeInt(self.state.arch, True)}
        self.return_type = SimTypeInt(self.state.arch, True)

        return self.state.solver.If(
            self.state.solver.And(c >= 97, c <= 122),  # a - z
            c - 32, c)
