import simuvex

class srand(simuvex.SimProcedure):
    IS_FUNCTION = True
    def run(self, seed):
        self.ret()
