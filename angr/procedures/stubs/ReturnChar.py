from __future__ import annotations
import claripy

import angr


class ReturnChar(angr.SimProcedure):
    def run(self):
        s_var = self.state.solver.Unconstrained("char_ret", self.state.arch.bits, key=("api", "?", self.display_name))
        self.state.add_constraints(claripy.And(claripy.ULE(s_var, 126), claripy.UGE(s_var, 9)))
        return s_var
