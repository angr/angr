from __future__ import annotations
import angr


class fcntl(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, cmd):
        #  this is a stupid stub that does not do anything besides returning an unconstrained variable.
        return self.state.solver.BVS("sys_fcntl", self.arch.sizeof["int"], key=("api", "fcntl"))
