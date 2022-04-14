import angr

class gettid(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self):
        return self.state.posix.pid
