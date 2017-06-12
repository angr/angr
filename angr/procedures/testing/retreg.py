import simuvex

class retreg(simuvex.SimProcedure):
    def run(self, reg=None):
        r = self.state.registers.load(reg)
        #print self.state.options
        return r
