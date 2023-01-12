import angr

# pylint:disable=arguments-differ


class getpid(angr.SimProcedure):
    def run(self):
        return self.state.posix.pid


class getppid(angr.SimProcedure):
    def run(self):
        return self.state.posix.ppid
