from __future__ import annotations
import angr


class PathTerminator(angr.SimProcedure):
    NO_RET = True

    def run(self):
        return
