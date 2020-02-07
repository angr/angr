import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger(name=__name__)


class tolower(angr.SimProcedure):
    def run(self, c):

        return self.state.solver.If(
            self.state.solver.And(c >= 65, c <= 90),  # A - Z
            c + 32, c)
