from __future__ import annotations
import angr


class usleep(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument
    def run(self, n):
        return 0
