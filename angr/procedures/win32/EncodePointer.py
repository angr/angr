from __future__ import annotations
import angr


class EncodePointer(angr.SimProcedure):
    def run(self, ptr):
        return ptr
