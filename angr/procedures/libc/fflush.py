import angr
from angr.sim_type import SimTypeFd, SimTypeLength

import logging
l = logging.getLogger(name=__name__)

class fflush(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeLength(self.state.arch)

        return self.state.solver.BVV(0, self.state.arch.bits)
