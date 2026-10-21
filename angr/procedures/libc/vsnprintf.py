from __future__ import annotations

import angr
from angr import claripy

from .vprintf import as_return, unmodeled_format_length


class vsnprintf(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, str_ptr, size, fmt, ap):
        # Like snprintf, returns the length the full output would have, and writes at most size - 1 bytes plus a NUL.
        length = unmodeled_format_length(self, fmt)
        concrete_size = self.state.solver.eval(size)
        self.state.add_constraints(size == concrete_size)
        if concrete_size == 0:
            return as_return(self, length)
        # Copy the format with its NUL when it fits; otherwise copy size - 1 bytes and terminate at the last byte. Both
        # addresses stay concrete when the format's length is symbolic.
        fits = length.ULT(concrete_size)
        count = claripy.If(fits, length + 1, claripy.BVV(concrete_size - 1, length.size()))
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]
        self.inline_call(memcpy, str_ptr, fmt, count)
        self.state.memory.store(str_ptr + concrete_size - 1, claripy.BVV(0, 8), condition=claripy.Not(fits))
        return as_return(self, length)


class __vsnprintf_chk(vsnprintf):
    def run(self, str_ptr, maxlen, flag, slen, fmt, ap):  # type:ignore[reportIncompatibleMethodOverride] # pylint:disable=arguments-differ,unused-argument
        return super().run(str_ptr, maxlen, fmt, ap)
