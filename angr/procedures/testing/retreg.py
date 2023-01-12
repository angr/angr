import angr


class retreg(angr.SimProcedure):
    def run(self, reg=None):
        r = self.state.registers.load(reg)
        # print self.state.options
        return r
