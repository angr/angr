from __future__ import annotations

import angr
from angr import claripy


class strchrnul(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, s_addr, c_int):
        # strchrnul is strchr that returns a pointer to the terminating NUL rather than NULL when the character is
        # not found. strchr(s, 0) already returns the terminator.
        strchr = self.inline_call(angr.SIM_PROCEDURES["libc"]["strchr"], s_addr, c_int)
        a = strchr.ret_expr
        if self.state.solver.is_true(a != 0):
            return a

        strlen = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)
        return claripy.If(a == 0, s_addr + strlen.ret_expr, a)
