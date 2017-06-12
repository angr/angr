import simuvex

class tgkill(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length): #pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.se.BVV(0, self.state.arch.bits)
