import angr


class PathTerminator(angr.SimProcedure):
    NO_RET = True

    def run(self):
        return
