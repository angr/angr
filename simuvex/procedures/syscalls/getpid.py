import simuvex

class getpid(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self):
        return self.state.posix.pid
