import simuvex

class brk(simuvex.SimProcedure):
    """
    This implements the brk system call.
    """

    IS_SYSCALL = True

    #pylint:disable=arguments-differ

    def run(self, new_brk):
        return self.state.posix.set_brk(new_brk)
