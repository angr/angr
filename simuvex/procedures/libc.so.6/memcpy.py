import simuvex

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.memcpy")

memcpy_counter = itertools.count()

class memcpy(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        dst_addr = self.get_arg_expr(0)
        src_addr = self.get_arg_expr(1)
        limit = self.get_arg_value(2)

        max_memcpy_size = self.state['libc'].max_buffer_size
        conditional_size = min(limit.max(), max_memcpy_size)
        src_mem = self.state.mem_expr(src_addr, conditional_size, endness='Iend_BE')
        self.state.store_mem(dst_addr, src_mem, symbolic_length=limit, endness='Iend_BE')

        self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(src_addr), self.state.expr_value(src_mem), conditional_size))
        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), self.state.expr_value(src_mem), conditional_size))

        self.exit_return(dst_addr)
