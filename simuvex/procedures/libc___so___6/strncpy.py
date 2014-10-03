import simuvex
from simuvex.s_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.strcpy")

class strncpy(simuvex.SimProcedure):
    def __init__(self, src_len = None): # pylint: disable=W0231,
        # TODO: better types?
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

        dst_addr = self.arg(0)
        src_addr = self.arg(1)
        src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr)
        limit = self.arg(2)

        cpy_size = self.state.se.If(self.state.se.ULE(limit, src_len.ret_expr + 1), limit, src_len.ret_expr + 1)

        #print "==================="
        #print sorted(self.state.expr_value(src_len.ret_expr).se.any_n(20))
        #print self.state.expr_value(limit.expr).se.any_n(20)
        #print sorted(self.state.expr_value(cpy_size).se.any_n(20))
        #print "-------------------"

        self.inline_call(memcpy, dst_addr, src_addr, cpy_size)
        self.ret(dst_addr)
