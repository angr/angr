import angr

import logging
l = logging.getLogger(name=__name__)


class atoi(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, s):
        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        val = strtol.strtol_inner(s, self.state, self.state.memory, 10, True)[1]
        val = val[self.arch.sizeof['int'] - 1:0]
        return val
