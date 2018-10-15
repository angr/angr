import angr
from angr.sim_type import SimTypeString, SimTypeLength

import logging
l = logging.getLogger("angr.procedures.libc.strncpy")

class strncpy(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit, src_len=None):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        memcpy = angr.SIM_PROCEDURES['libc']['memcpy']

        src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr).ret_expr
        cpy_size = self.state.solver.If(self.state.solver.ULE(limit, src_len + 1), limit, src_len + 1)

        self.inline_call(memcpy, dst_addr, src_addr, cpy_size)
        return dst_addr
