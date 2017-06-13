import angr

class srand(angr.SimProcedure):
    IS_FUNCTION = True
    def run(self, seed):
        self.ret()
