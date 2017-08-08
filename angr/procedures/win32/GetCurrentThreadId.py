import angr

class GetCurrentThreadId(angr.SimProcedure):
    def run(self):
        return 0xbad76ead
