import simuvex

class gettid(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self):
        return self.state.posix.pid
