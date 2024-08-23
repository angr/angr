from __future__ import annotations
import angr


class abort(angr.SimProcedure):
    NO_RET = True

    def run(self):
        self.exit(1)
