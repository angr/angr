import angr

class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project._sim_environment.acmdln_ptr

class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.project._sim_environment.wcmdln_ptr
