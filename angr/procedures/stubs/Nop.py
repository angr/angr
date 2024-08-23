from __future__ import annotations
import angr


class Nop(angr.SimProcedure):
    def run(self):
        pass
