import angr


class srand(angr.SimProcedure):
    def run(self, seed):
        self.ret()
