import simuvex

class sigaction(simuvex.SimProcedure):
    def run(self, addr, length): #pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.se.BVV(0, self.state.arch.bits)
