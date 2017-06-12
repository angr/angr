import simuvex

import logging
l = logging.getLogger('simuvex.procedures.syscalls.lseek')

class lseek(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, fd, seek, whence): #pylint:disable=arguments-differ,unused-argument

        if self.state.se.symbolic(whence):
            err = "Symbolic whence is not supported in lseek syscall."
            l.error(err)
            raise simuvex.s_errors.SimPosixError(err)

        whence = self.state.se.any_int(whence)

        if self.state.se.symbolic(seek):
            err = "Symbolic seek is not supported in lseek syscall."
            l.error(err)
            raise simuvex.s_errors.SimPosixError(err)

        seek = self.state.se.any_int(seek)

        # Symbolic fd case is handled in posix.seek

        # Call posix plugin to actually move us
        ret = self.state.posix.seek(fd, seek, whence)

        # Posix only actually returns 0 or -1. Check for error
        if ret == -1:
            return self.state.se.BVV(-1, self.state.arch.bits)

        # To be compliant, we must return the current position on success
        return self.state.posix.pos(fd)
