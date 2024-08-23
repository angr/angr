from __future__ import annotations
import angr


# pylint:disable=redefined-builtin,arguments-differ
class set_tid_address(angr.SimProcedure):
    def run(self, tidptr):
        return 1  # Assume it's single-threaded, so only tid 1 exists
