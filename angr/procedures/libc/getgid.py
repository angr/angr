from __future__ import annotations
import angr


class getgid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
