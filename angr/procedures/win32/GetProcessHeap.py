import angr

class GetProcessHeap(angr.SimProcedure):
    def run(self):
        return 1 # fake heap handle
