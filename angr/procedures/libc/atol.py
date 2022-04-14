import angr

import logging
l = logging.getLogger(name=__name__)


class atol(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, s):
        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        return strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
