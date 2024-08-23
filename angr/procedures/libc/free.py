from __future__ import annotations
import angr


class free(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, ptr):
        self.state.heap._free(ptr)
