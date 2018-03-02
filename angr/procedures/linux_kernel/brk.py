import angr
import logging

l = logging.getLogger('angr.procedures.linux_kernel.brk')

class brk(angr.SimProcedure):
    """
    This implements the brk system call.
    """

    IS_SYSCALL = True

    #pylint:disable=arguments-differ

    def run(self, new_brk):
        r = self.state.posix.set_brk(new_brk)
        l.debug('brk(%s) = %s', new_brk, r)
        return r
