import logging

import angr

l = logging.getLogger(name=__name__)


class system(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument
    def run(self, cmd):
        retcode = self.state.solver.Unconstrained("system_returncode", 8, key=("api", "system"))
        return retcode.zero_extend(self.arch.sizeof["int"] - 8)
