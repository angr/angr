import angr
from angr.sim_type import SimTypeInt, SimTypeTop

import logging
l = logging.getLogger("angr.procedures.libc.system")

class system(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, cmd):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)

        retcode = self.state.se.Unconstrained('system_returncode', 8)
        return retcode.zero_extend(self.state.arch.bits - 8)
