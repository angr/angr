from __future__ import annotations
import claripy

import angr


class tgkill(angr.SimProcedure):
    def run(self, tgid, tid, sig):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return claripy.BVV(0, self.arch.sizeof["int"])
