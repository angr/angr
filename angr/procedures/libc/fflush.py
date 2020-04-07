import angr

import logging
l = logging.getLogger(name=__name__)

class fflush(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument

    def run(self, fd):
        return self.state.solver.BVV(0, self.state.arch.bits)
