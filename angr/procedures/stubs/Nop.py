import angr


class Nop(angr.SimProcedure):
    def run(self):
        pass
