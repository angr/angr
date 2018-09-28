import angr

class munmap(angr.SimProcedure):

    IS_SYSCALL = True

    def run(self, addr, length): #pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return self.state.solver.BVV(0, self.state.arch.bits)
