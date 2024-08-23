from __future__ import annotations
import angr


class getsockopt(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, sockfd, level, optname, optval, optlen):
        # TODO: ...

        return 0
