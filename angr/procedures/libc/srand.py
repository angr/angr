from __future__ import annotations
import angr


class srand(angr.SimProcedure):
    def run(self, seed):
        self.ret()
