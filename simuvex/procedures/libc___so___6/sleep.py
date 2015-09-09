import simuvex
from simuvex.s_type import SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.sleep")

class sleep(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, seconds):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: SimTypeInt(self.state.arch.bits, True)}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        return self.state.BVV(0)
