from __future__ import annotations
import angr


class setsockopt(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optmain):
        return 0
