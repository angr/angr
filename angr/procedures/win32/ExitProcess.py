import angr

class ExitProcess(angr.SimProcedure):
    NO_RET = True
    def run(self, exit_status):
        self.exit(exit_status)
