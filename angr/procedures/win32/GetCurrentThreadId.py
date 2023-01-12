import angr


class GetCurrentThreadId(angr.SimProcedure):
    def run(self):
        return 0xBAD76EAD
