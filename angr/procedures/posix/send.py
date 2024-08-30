from __future__ import annotations
import claripy

import angr
from ...sim_options import ALLOW_SEND_FAILURES


class send(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, fd, src, length, flags):  # pylint:disable=unused-argument
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        send_succeeded = simfd.write(src, length)  # if send succeeds

        if ALLOW_SEND_FAILURES in self.state.options:
            retval = claripy.BVS("send_ret", self.arch.bits)
            send_failed = -1
            self.state.add_constraints(claripy.Or(retval == send_succeeded, retval == send_failed))
            return retval
        return send_succeeded
