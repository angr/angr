from __future__ import annotations
import logging

import archinfo

import angr

l = logging.getLogger(name=__name__)


class sigaction(angr.SimProcedure):
    def run(self, signum, act, oldact):
        l.warning("Calling sigaction for signal %s - this is emulated as a nop", signum)
        if not self.state.solver.is_true(oldact == 0):
            if isinstance(self.arch, archinfo.ArchAMD64):
                self.state.memory.store(
                    oldact, self.state.solver.BVS("sigaction_oldact", 152 * 8, key=("api", "sigaction", "oldact"))
                )
            elif isinstance(self.arch, archinfo.ArchX86):
                self.state.memory.store(
                    oldact, self.state.solver.BVS("sigaction_oldact", 140 * 8, key=("api", "sigaction", "oldact"))
                )
        return 0
