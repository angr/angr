from __future__ import annotations
import angr


class close(angr.SimProcedure):
    def run(self, fd):  # pylint:disable=arguments-differ
        if self.state.posix.close(fd):
            return 0
        return -1
