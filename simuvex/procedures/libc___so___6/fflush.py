import simuvex
from simuvex.s_type import SimTypeFd, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.fflush")

class fflush(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeLength(self.state.arch)

        return self.state.BVV(0, self.state.arch.bits)
