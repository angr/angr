import angr
from angr.sim_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger(name=__name__)


class atoi(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch, True)

        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        return strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
