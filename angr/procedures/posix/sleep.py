import angr

class sleep(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument
    def run(self, seconds):
        return 0
