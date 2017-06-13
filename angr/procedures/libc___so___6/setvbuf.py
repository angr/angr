import angr

class setvbuf(angr.SimProcedure):
    def run(self, stream, buf, type_, size):
        return 0
