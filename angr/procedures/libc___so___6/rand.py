import simuvex

class rand(simuvex.SimProcedure):
    IS_FUNCTION = True
    def run(self):
        rval = self.state.se.BVS('rand', 31)
        return rval.zero_extend(self.state.arch.bits - 31)
