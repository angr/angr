import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger(name=__name__)

class sleep(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, seconds):
        #pylint:disable=attribute-defined-outside-init


        return self.state.solver.BVV(0, self.state.arch.bits)
