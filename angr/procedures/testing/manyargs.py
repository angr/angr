from __future__ import annotations
import angr


class manyargs(angr.SimProcedure):
    NO_RET = True

    def run(self):
        pass
