import angr

from ...sim_options import ALLOW_SEND_FAILURES

######################################
# send
######################################

class send(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, src, length, flags):  # pylint:disable=unused-argument
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        send_succeeded = simfd.write(src, length)  # if send succeeds

        if ALLOW_SEND_FAILURES in self.state.options:
            retval = self.state.solver.BVS('send_ret', self.arch.bits)
            send_failed = -1
            self.state.add_constraints(self.state.solver.Or(retval == send_succeeded,
                                                            retval == send_failed))
            return retval
        else:
            return send_succeeded
