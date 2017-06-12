import simuvex

class mprotect(simuvex.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length, prot): #pylint:disable=arguments-differ,unused-argument

        # TODO: Actually handle this syscall
        return self.state.se.BVV(0, self.state.arch.bits)
