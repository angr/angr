from __future__ import annotations

import logging

import angr
from angr import claripy

l = logging.getLogger(name=__name__)


class memrchr(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, s_addr, c_int, n):
        c = c_int[7:0]

        if self.state.solver.is_true(n == 0):
            return claripy.BVV(0, self.state.arch.bits)

        if self.state.solver.symbolic(n):
            max_search = min(self.state.solver.max_int(n), self.state.libc.max_buffer_size)  # type: ignore
        else:
            max_search = self.state.solver.eval(n)

        if max_search == 0:
            return claripy.BVV(0, self.state.arch.bits)

        l.debug("memrchr searching last of %d bytes for byte", max_search)

        # memrchr returns a pointer to the LAST occurrence of c in the first n
        # bytes. Build the result forward so that a later (higher-index) match
        # overrides an earlier one; positions beyond n are never inspected.
        result = claripy.BVV(0, self.state.arch.bits)
        for i in range(max_search):
            b = self.state.memory.load(s_addr + i, 1)
            # Respect the n bound for symbolic n: only positions < n contribute.
            in_bounds = True if not self.state.solver.symbolic(n) else claripy.ULT(i, n)
            result = claripy.If((b == c) & in_bounds, s_addr + i, result)

        return result
