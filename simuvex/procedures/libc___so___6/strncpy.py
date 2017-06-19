import simuvex
from simuvex.s_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.strcpy")

class strncpy(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit, src_len=None):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

        src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr).ret_expr
        cpy_size = self.state.se.If(self.state.se.ULE(limit, src_len + 1), limit, src_len + 1)

        self.inline_call(memcpy, dst_addr, src_addr, cpy_size)
        return dst_addr
