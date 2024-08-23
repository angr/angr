from __future__ import annotations
import angr


class openlog(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, ident, option, facility):
        # A stub for openlog that does not do anything yet.
        return
