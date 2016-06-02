import simuvex

class getpid(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self):
        return self.state.posix.pid
