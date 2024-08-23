from __future__ import annotations
import angr


class gettid(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self):
        return self.state.posix.pid
