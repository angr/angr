import angr

import logging
l = logging.getLogger(name=__name__)

class lseek(angr.SimProcedure):

    def run(self, fd, seek, whence): #pylint:disable=arguments-differ,unused-argument

        if self.state.solver.symbolic(whence):
            err = "Symbolic whence is not supported in lseek syscall."
            l.error(err)
            raise angr.errors.SimPosixError(err)

        whence = self.state.solver.eval(whence)
        if whence == 0:
            whence_str = 'start'
        elif whence == 1:
            whence_str = 'current'
        elif whence == 2:
            whence_str = 'end'
        else:
            return -1

        # let's see what happens...
        #if self.state.solver.symbolic(seek):
        #    err = "Symbolic seek is not supported in lseek syscall."
        #    l.error(err)
        #    raise angr.errors.SimPosixError(err)

        #seek = self.state.solver.eval(seek)

        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        success = simfd.seek(seek, whence_str)
        if self.state.solver.is_false(success):
            return -1
        return self.state.solver.If(success, simfd.tell(), -1)
