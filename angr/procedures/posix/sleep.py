import angr
from angr.sim_type import SimTypeInt

import logging
l = logging.getLogger("angr.procedures.libc___so___6.sleep")

class sleep(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, seconds):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: SimTypeInt(self.state.arch.bits, True)}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        return self.state.se.BVV(0, self.state.arch.bits)
