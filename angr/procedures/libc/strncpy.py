from __future__ import annotations
import logging

import claripy

import angr

l = logging.getLogger(name=__name__)


class strncpy(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit, src_len=None):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]

        src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr).ret_expr
        cpy_size = claripy.If(claripy.ULE(limit, src_len + 1), limit, src_len + 1)

        self.inline_call(memcpy, dst_addr, src_addr, cpy_size)
        return dst_addr
