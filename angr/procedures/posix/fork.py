import angr

class fork(angr.SimProcedure):
    def run(self):
        return self.state.se.If(self.state.se.BoolS('fork_parent'),
                self.state.se.BVV(1338, self.state.arch.bits),
                self.state.se.BVV(0, self.state.arch.bits))
