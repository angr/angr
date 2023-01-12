import angr


class rand(angr.SimProcedure):
    def run(self):
        rval = self.state.solver.BVS("rand", 31, key=("api", "rand"))
        return rval.zero_extend(self.arch.sizeof["int"] - 31)
