from __future__ import annotations

import angr
from angr import claripy


class rawmemchr(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, s_addr, c_int):
        # rawmemchr is memchr without a length bound: the caller guarantees the byte is present. Like strlen, the
        # search is bounded by libc.max_str_len.
        c = c_int[7:0]
        if self.state.solver.is_true(c == 0):
            # rawmemchr(s, 0) is the common idiom for finding the end of a string
            strlen = self.inline_call(angr.SIM_PROCEDURES["libc"]["strlen"], s_addr)
            return s_addr + strlen.ret_expr

        n = claripy.BVV(self.state.libc.max_str_len, self.state.arch.bits)
        memchr = self.inline_call(angr.SIM_PROCEDURES["libc"]["memchr"], s_addr, c_int, n)
        return memchr.ret_expr
