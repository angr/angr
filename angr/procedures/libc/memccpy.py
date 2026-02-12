from __future__ import annotations

import logging

import claripy

import angr

l = logging.getLogger(name=__name__)


class memccpy(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, dst_addr, src_addr, c_int, n):
        c = c_int[7:0]

        if self.state.solver.is_true(n == 0):
            return claripy.BVV(0, self.state.arch.bits)

        if not self.state.solver.symbolic(n):
            max_copy = self.state.solver.eval(n)
        else:
            max_copy = min(self.state.solver.max_int(n), self.state.libc.max_buffer_size)  # type: ignore

        if max_copy == 0:
            return claripy.BVV(0, self.state.arch.bits)

        l.debug("memccpy copying up to %d bytes until char found", max_copy)

        a, constraints, _i = self.state.memory.find(src_addr, c, max_copy, default=0)
        self.state.add_constraints(*constraints)

        c_pos = a - src_addr

        c_found = claripy.And(a != 0, claripy.ULT(c_pos, n)) if self.state.solver.symbolic(n) else a != 0

        copy_len = claripy.If(c_found, c_pos + 1, n)

        src_mem = self.state.memory.load(src_addr, max_copy, endness="Iend_BE")
        self.state.memory.store(dst_addr, src_mem, size=copy_len, endness="Iend_BE")

        return claripy.If(c_found, dst_addr + c_pos + 1, claripy.BVV(0, self.state.arch.bits))
