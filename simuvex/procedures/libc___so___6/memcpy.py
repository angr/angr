import simuvex
from simuvex.s_type import SimTypePointer, SimTypeTop, SimTypeLength

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.memcpy")

memcpy_counter = itertools.count()

class memcpy(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        # TODO: look into smarter types here
        self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                               1: self.ty_ptr(SimTypeTop()),
                               2: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop())

        dst_addr = self.get_arg_expr(0)
        src_addr = self.get_arg_expr(1)
        limit = self.get_arg_value(2)

        if not limit.is_symbolic():
            conditional_size = limit.any()
        else:
            max_memcpy_size = self.state['libc'].max_buffer_size
            conditional_size = max(limit.min(), min(limit.max(), max_memcpy_size))

        l.debug("Memcpy running with conditional_size %d", conditional_size)

        if conditional_size > 0:
            src_mem = self.state.mem_expr(src_addr, conditional_size, endness='Iend_BE')
            self.state.store_mem(dst_addr, src_mem, symbolic_length=limit, endness='Iend_BE')

            self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(src_addr), self.state.expr_value(src_mem), conditional_size))
            self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), self.state.expr_value(src_mem), conditional_size))

        self.exit_return(dst_addr)
