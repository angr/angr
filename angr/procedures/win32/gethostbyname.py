from __future__ import annotations
import logging


import angr

l = logging.getLogger("angr.procedures.win32.gethostbyname")


class gethostbyname(angr.SimProcedure):
    def run(self, _):  # pylint:disable=arguments-differ
        return self.state.solver.BVS("gethostbyname_retval", 32, key=("api", "gethostbyname_retval"))
