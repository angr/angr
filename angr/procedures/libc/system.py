import angr
from angr.sim_type import SimTypeInt, SimTypeTop

import logging
l = logging.getLogger(name=__name__)

class system(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, cmd):
        #pylint:disable=attribute-defined-outside-init


        retcode = self.state.solver.Unconstrained('system_returncode', 8, key=('api', 'system'))
        return retcode.zero_extend(self.state.arch.bits - 8)
