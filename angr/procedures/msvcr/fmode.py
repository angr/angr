from __future__ import annotations
import claripy

import angr


class __p__fmode(angr.SimProcedure):
    def run(self):
        return self.project.simos.fmode_ptr


class _get_fmode(angr.SimProcedure):
    def run(self, outptr):
        if self.state.solver.is_true(outptr == 0):
            return 22
        fmode = self.state.mem[self.project.simos.fmode_ptr].int.resolved
        self.state.mem[outptr].int = fmode
        return 0


class _set_fmode(angr.SimProcedure):
    def run(self, val):
        if not self.state.solver.is_true(claripy.Or(val == 0x4000, val == 0x8000)):
            return 22
        self.state.mem[self.project.simos.fmode_ptr].int = val
        return 0


class __p__commode(angr.SimProcedure):
    def run(self):
        return self.project.simos.commode_ptr
