from __future__ import annotations

import angr
from angr import claripy


class stpncpy(angr.SimProcedure):
    """stpncpy"""

    # pylint:disable=arguments-differ

    def run(self, dst, src, n):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
        src_len = self.inline_call(strlen, src).ret_expr

        # strncpy copies min(strlen(src) + 1, n) bytes but does not NUL-pad the rest of the window. Pad it here when
        # both bounds are concrete; with a symbolic bound the tail is left untouched, as in strncpy.
        self.inline_call(strncpy, dst, src, n, src_len=src_len)
        if not self.state.solver.symbolic(n) and not self.state.solver.symbolic(src_len):
            copied = min(self.state.solver.eval(src_len) + 1, self.state.solver.eval(n))
            pad = self.state.solver.eval(n) - copied
            if pad > 0:
                memset = angr.SIM_PROCEDURES["libc"]["memset"]
                self.inline_call(memset, dst + copied, 0, claripy.BVV(pad, self.state.arch.bits))

        # stpncpy returns a pointer to the written NUL, i.e. dst + min(strlen(src), n);
        # when src has no NUL inside the n-byte window the result is dst + n.
        return dst + claripy.If(claripy.ULE(src_len, n), src_len, n)
