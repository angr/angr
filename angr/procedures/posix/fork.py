import angr

class fork(angr.SimProcedure):
    def run(self):
        return self.state.solver.If(self.state.solver.BoolS('fork_parent'),
                self.state.solver.BVV(1338, self.arch.sizeof['int']),
                self.state.solver.BVV(0, self.arch.sizeof['int']))
