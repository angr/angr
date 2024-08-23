from __future__ import annotations
import angr


class _dl_initial_error_catch_tsd(angr.SimProcedure):
    def run(self, static_addr=0):
        return static_addr
