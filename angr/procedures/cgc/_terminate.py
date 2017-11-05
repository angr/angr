import angr

class _terminate(angr.SimProcedure): #pylint:disable=redefined-builtin
    #pylint:disable=arguments-differ

    NO_RET = True
    IS_SYSCALL = True

    def run(self, exit_code): #pylint:disable=unused-argument
        return
