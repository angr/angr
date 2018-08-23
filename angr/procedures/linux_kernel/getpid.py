import angr

#pylint:disable=arguments-differ

class getpid(angr.SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.posix.pid


class getppid(angr.SimProcedure):
    IS_SYSCALL = True

    def run(self):
        return self.state.posix.ppid
