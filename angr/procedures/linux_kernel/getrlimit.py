from __future__ import annotations

import logging

import angr

l = logging.getLogger(name=__name__)


# pylint:disable=redefined-builtin,arguments-differ
class getrlimit(angr.SimProcedure):
    def run(self, resource, rlim):
        if self.state.solver.eval(resource) == 3:  # RLIMIT_STACK
            l.debug("running getrlimit(RLIMIT_STACK)")
            # struct rlimit is two unsigned longs
            endness = self.arch.memory_endness
            self.state.memory.store(rlim, 8388608, self.arch.bytes, endness=endness)  # rlim_cur
            self.state.memory.store(
                rlim + self.arch.bytes,
                self.state.solver.Unconstrained("rlim_max", self.arch.bits, key=("api", "rlimit", "stack")),
                endness=endness,
            )
            return 0
        l.debug("running getrlimit(other)")
        return self.state.solver.Unconstrained("rlimit", self.arch.sizeof["int"], key=("api", "rlimit", "other"))


class ugetrlimit(getrlimit):
    pass
