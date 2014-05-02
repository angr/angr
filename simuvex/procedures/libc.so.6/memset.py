import simuvex
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.memset")

######################################
# memset
######################################

import itertools
memset_counter = itertools.count()
#max_memset = 4096
# for now
max_memset = 128

class memset(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		dst_addr = self.get_arg_expr(0)
		char = se.Extract(7, 0, self.get_arg_expr(1))
		num = self.get_arg_value(2)

		before_bytes = self.state.mem_expr(dst_addr, max_memset, endness='Iend_BE')
		new_bytes = [ ]

		max_size = min(max_memset, num.any() if not num.is_symbolic() else max_memset)
		if max_size == 0:
			self.exit_return(dst_addr)
			return

		for size in range(max_size):
			before_byte = se.Extract(max_memset*8 - size*8 - 1, max_memset*8 - size*8 - 8, before_bytes)
			new_byte, constraints = simuvex.s_helpers.sim_ite(self.state, se.UGT(num.expr, size), char, before_byte, sym_name=("memset_%d" % memset_counter.next()), sym_size=8)

			new_bytes.append(new_byte)
			self.state.add_constraints(*constraints)

		if len(new_bytes) > 1:
			write_bytes = se.Concat(*new_bytes)
		else:
			write_bytes = new_bytes[0]

		self.state.store_mem(dst_addr, write_bytes)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), write_bytes, max_size*8, [], [], [], []))
		self.exit_return(dst_addr)
