from __future__ import annotations

import logging

import claripy

import angr
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from angr.sim_options import MEMORY_CHUNK_INDIVIDUAL_READS

l = logging.getLogger(name=__name__)


class memchr(angr.SimProcedure):
    # pylint:disable=arguments-differ, missing-class-docstring

    def run(self, s_addr, c_int, n):
        c = c_int[7:0]

        if self.state.solver.is_true(n == 0):
            return claripy.BVV(0, self.state.arch.bits)

        if not self.state.solver.symbolic(n):
            max_search = self.state.solver.eval(n)
        else:
            max_search = min(self.state.solver.max_int(n), self.state.libc.max_buffer_size)  # type: ignore[reportAttributeAccessIssue]

        if max_search == 0:
            return claripy.BVV(0, self.state.arch.bits)

        l.debug("memchr searching %d bytes for byte", max_search)

        chunk_size = None
        if MEMORY_CHUNK_INDIVIDUAL_READS in self.state.options:
            chunk_size = 1

        if self.state.solver.symbolic(n):
            l.debug("symbolic n")
            max_sym = min(self.state.solver.max_int(n), self.state.libc.max_symbolic_memchr)  # type: ignore[reportAttributeAccessIssue]
            a, constraints, i = self.state.memory.find(s_addr, c, max_search, max_symbolic_bytes=max_sym, default=0)
        else:
            l.debug("concrete n")
            a, constraints, i = self.state.memory.find(s_addr, c, max_search, default=0, chunk_size=chunk_size)

        if len(i) > 1:
            a = a.annotate(MultiwriteAnnotation())
            self.state.add_constraints(*constraints)

        # Ensure the found position is within the n bound
        chrpos = a - s_addr
        self.state.add_constraints(claripy.If(a != 0, claripy.ULT(chrpos, n), True))

        return a
