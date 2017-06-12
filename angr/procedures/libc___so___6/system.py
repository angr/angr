import simuvex
from simuvex.s_type import SimTypeInt, SimTypeTop

import logging
l = logging.getLogger("simuvex.procedures.libc.system")

class system(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, cmd):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        retcode = self.state.se.Unconstrained('system_returncode', 8)
        return retcode.zero_extend(self.state.arch.bits - 8)
