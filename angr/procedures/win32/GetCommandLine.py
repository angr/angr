from __future__ import annotations
import angr


class GetCommandLineA(angr.SimProcedure):
    def run(self):
        return self.project.simos.acmdln_ptr


class GetCommandLineW(angr.SimProcedure):
    def run(self):
        return self.project.simos.wcmdln_ptr
