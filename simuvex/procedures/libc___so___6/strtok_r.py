import simuvex

import logging
l = logging.getLogger("simuvex.procedures.libc.strtok_r")

class strtok_r(simuvex.SimProcedure):
	def __init__(self, str_strlen=None, delim_strlen=None): # pylint: disable=W0231,
		if self.state['libc'].simple_strtok:
			str_ptr = self.get_arg_expr(0)
			delim_ptr = self.get_arg_expr(1)
			save_ptr = self.get_arg_expr(2)

			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(str_ptr), self.state.mem_expr(str_ptr, 128), 1024))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(delim_ptr), self.state.mem_expr(delim_ptr, 128), 1024))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(save_ptr), self.state.mem_expr(save_ptr, self.state.arch.bits), self.state.arch.bits))

			malloc = simuvex.SimProcedures['libc.so.6']['malloc']
			token_ptr = self.inline_call(malloc, self.state['libc'].strtok_token_size).ret_expr
			r = simuvex.helpers.sim_ite_autoadd(self.state, self.state.BV('strtok_case') == 0, token_ptr, self.state.BVV(0))
			self.state['libc'].strtok_heap.append(token_ptr)
			self.exit_return(r)
		else:
			strstr = simuvex.SimProcedures['libc.so.6']['strstr']
			strlen = simuvex.SimProcedures['libc.so.6']['strlen']

			l.debug("Doin' a strtok_r!")

			str_ptr = self.get_arg_expr(0)
			delim_ptr = self.get_arg_expr(1)
			save_ptr = self.get_arg_expr(2)

			l.debug("... geting the saved state")

			saved_str_ptr = self.state.mem_expr(save_ptr, self.state.arch.bytes, endness=self.state.arch.memory_endness)
			start_ptr = simuvex.helpers.sim_ite_autoadd(self.state, str_ptr == 0, saved_str_ptr, str_ptr, sym_name="strtok_start")

			l.debug("... getting the lengths")
			str_strlen = self.inline_call(strlen, start_ptr) if str_strlen is None else str_strlen
			delim_strlen = self.inline_call(strlen, delim_ptr) if delim_strlen is None else delim_strlen

			l.debug("... STRTOK SLOW PATH (symbolic-length delimiteter and/or string)")
			l.debug("... calling strstr")
			where = self.inline_call(strstr, start_ptr, delim_ptr, haystack_strlen=str_strlen, needle_strlen=delim_strlen)
			write_length = simuvex.helpers.sim_ite_autoadd(self.state, where.ret_expr != 0, delim_strlen.ret_expr, 0, sym_name="strtok_write_length")
			write_content = self.state.claripy.BitVecVal(0, delim_strlen.max_null_index*8)

			# do a symbolic write (we increment the limit because of the possibility that the write target is 0, in which case the length will be 0, anyways)
			l.debug("... doing the symbolic write")
			self.state.store_mem(where.ret_expr, write_content, symbolic_length=self.state.expr_value(write_length), strategy=["symbolic_nonzero", "any"], limit=str_strlen.max_null_index+1)

			l.debug("... creating the return address")
			new_start = write_length + where.ret_expr
			new_state = simuvex.helpers.sim_ite_autoadd(self.state, new_start != 0, new_start, start_ptr)

			l.debug("... saving the state")
			self.state.store_mem(save_ptr, new_state, endness=self.state.arch.memory_endness)

			l.debug("... done")
			self.exit_return(new_start)
