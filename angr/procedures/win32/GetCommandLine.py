import angr

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project._simos.acmdln_ptr

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.project._simos.wcmdln_ptr
