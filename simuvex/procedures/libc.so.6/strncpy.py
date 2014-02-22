import simuvex
from simuvex.s_helpers import sim_ite
import symexec as se

import itertools
import logging
l = logging.getLogger("simuvex.procedures.libc.strcpy")

strncpy_counter = itertools.count()

class strncpy(simuvex.SimProcedure):
	def __init__(self, src_len = None): # pylint: disable=W0231,
		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		dst_addr = self.get_arg_expr(0)
		src_addr = self.get_arg_expr(1)
		limit = self.get_arg_value(2)

		src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr)
		src_len_val = self.state.expr_value(src_len.ret_expr)

		# figure out the maximum size of the read/write, including the null
		if not src_len_val.is_symbolic() and not limit.is_symbolic():
			l.debug("concrete lengths!")
			max_copy_size = min(src_len_val.any(), limit.any()) + 1
		else:
			max_copy_size = src_len.maximum_null + 1

		dst_str = self.state.mem_expr(dst_addr, max_copy_size, endness='Iend_BE')
		src_str = self.state.mem_expr(src_addr, max_copy_size, endness='Iend_BE')

		written_bytes = [ ]

		str_name = "strncpy_%d" % strncpy_counter.next()

		# put the new string together
		for byte, bit in zip(range(max_copy_size), range(max_copy_size*8, 0, -8)):
			dst_byte = se.Extract(bit-1, bit-8, dst_str)
			src_byte = se.Extract(bit-1, bit-8, src_str)

			print se.simplify_expression(dst_byte), se.simplify_expression(src_byte), src_len.ret_expr, se.simplify_expression(limit.expr), byte

			byte_name = "%s_%d" % (str_name, byte)
			written_byte, constraints = sim_ite(se.And(se.UGE(src_len.ret_expr, byte), se.UGT(limit.expr, byte)), src_byte, dst_byte, sym_name=byte_name, sym_size=8)
			written_bytes.append(written_byte)
			self.state.add_constraints(*constraints)

		if len(written_bytes) > 0:
			written = se.Concat(*written_bytes) if len(written_bytes) > 1 else written_bytes[0]
			self.state.store_mem(dst_addr, written, len(written_bytes))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(src_addr), self.state.expr_value(src_str), len(written_bytes)))
			self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), self.state.expr_value(written), len(written_bytes)))

		self.exit_return(dst_addr)

