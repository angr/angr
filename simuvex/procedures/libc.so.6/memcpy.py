import simuvex
from simuvex.s_helpers import sim_ite_autoadd
import symexec as se

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

        definite_size = limit.min()
        conditional_read_start = src_addr + definite_size
        conditional_write_start = dst_addr + definite_size
        conditional_size = min(limit.max(), max_memcpy_size) - definite_size

        l.debug("Definite size %d and conditional size: %d", definite_size, conditional_size)

        if definite_size > 0:
            src_mem = self.state.mem_expr(src_addr, definite_size, endness='Iend_BE')
            self.state.store_mem(dst_addr, src_mem, endness='Iend_BE')

            self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(src_addr), self.state.expr_value(src_mem), definite_size))
            self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), self.state.expr_value(src_mem), definite_size))

        if conditional_size > 0:
            dst_mem = self.state.mem_expr(conditional_write_start, conditional_size, endness='Iend_BE')
            src_mem = self.state.mem_expr(conditional_read_start, conditional_size, endness='Iend_BE')
            written_bytes = []
            str_name = "memcpy_%d" % memcpy_counter.next()

            # put the new string together
            for byte, bit in zip(range(conditional_size), range(conditional_size*8, 0, -8)):
                l.debug("... doing byte %d", byte)
                dst_byte = se.Extract(bit-1, bit-8, dst_mem)
                src_byte = se.Extract(bit-1, bit-8, src_mem)

                #print se.simplify_expression(dst_byte), se.simplify_expression(src_byte), se.simplify_expression(limit.expr), byte

                byte_name = "%s_%d" % (str_name, byte)
                written_byte = sim_ite_autoadd(self.state, se.UGT(limit.expr, byte), src_byte, dst_byte, sym_name=byte_name, sym_size=8)
                written_bytes.append(written_byte)

            written = se.Concat(*written_bytes) if len(written_bytes) > 1 else written_bytes[0]
            self.state.store_mem(dst_addr, written, endness='Iend_BE')
            self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(conditional_read_start), self.state.expr_value(src_mem), len(written_bytes)))
            self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(conditional_write_start), self.state.expr_value(written), len(written_bytes)))

        self.exit_return(dst_addr)
