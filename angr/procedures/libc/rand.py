import angr

class rand(angr.SimProcedure):
    def run(self):
        rval = self.state.se.BVS('rand', 31)
        return rval.zero_extend(self.state.arch.bits - 31)
