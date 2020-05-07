import angr


class setbuf(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, stream, buf):
        return
