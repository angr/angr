from __future__ import annotations
import angr


class GetCurrentProcessId(angr.SimProcedure):
    def run(self):
        return 0x1337BEE2
