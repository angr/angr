from __future__ import annotations

import logging

import angr
from angr import claripy

l = logging.getLogger(name=__name__)


class strncat(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst, src, limit):
        strncpy = angr.SIM_PROCEDURES["libc"]["strncpy"]
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        dst_len = self.inline_call(strlen, dst).ret_expr
        src_len = self.inline_call(strlen, src).ret_expr

        self.inline_call(strncpy, dst + dst_len, src, limit, src_len=src_len)

        # strncat always NUL-terminates the result. strncpy only writes the NUL when the source fits in the limit, so
        # terminate explicitly after at most `limit` appended bytes.
        n_appended = claripy.If(claripy.ULE(limit, src_len), limit, src_len)
        self.state.memory.store(dst + dst_len + n_appended, claripy.BVV(0, 8))

        return dst


class __strncat_chk(strncat):
    def run(self, dst, src, limit, _destlen):  # type:ignore[reportIncompatibleMethodOverride]
        return super().run(dst, src, limit)
