import simuvex
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.libc.memcmp")

class memcmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		s1_addr = self.get_arg_expr(0)
		s2_addr = self.get_arg_expr(1)
		n = self.get_arg_value(2)

		max_memcmp_size = self.state['libc'].max_buffer_size

		definite_size = n.min()
		conditional_s1_start = s1_addr + definite_size
		conditional_s2_start = s2_addr + definite_size
		#conditional_size = max(min(n.max(), max_memcmp_size) - definite_size, 0)
		if n.is_symbolic():
			conditional_size = int(max(max_memcmp_size - definite_size, 0))
		else:
			conditional_size = 0

		l.debug("Definite size %d and conditional size: %d", definite_size, conditional_size)

		if definite_size > 0:
			s1_part = self.state.mem_expr(s1_addr, definite_size, endness='Iend_BE')
			s2_part = self.state.mem_expr(s2_addr, definite_size, endness='Iend_BE')
			cases = [ [s1_part == s2_part, 0], [s1_part < s2_part, -1], [s1_part > s2_part, 1 ] ]
			definite_answer = simuvex.helpers.sim_cases_autoadd(self.state, cases, sym_name="memcpy_def")

			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(s1_addr), self.state.expr_value(s1_part), definite_size))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(s2_addr), self.state.expr_value(s2_part), definite_size))
		else:
			definite_answer = se.BitVecVal(0, self.state.arch.bits)

		if not se.is_symbolic(definite_answer) and se.concretize_constant(definite_answer) != 0:
			self.exit_return(definite_answer)
			return

		if conditional_size > 0:
			s1_all = self.state.mem_expr(conditional_s1_start, conditional_size, endness='Iend_BE')
			s2_all = self.state.mem_expr(conditional_s2_start, conditional_size, endness='Iend_BE')
			conditional_rets = { 0: definite_answer }

			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(conditional_s1_start), self.state.expr_value(s1_all), conditional_size))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(conditional_s2_start), self.state.expr_value(s2_all), conditional_size))

			for byte, bit in zip(range(conditional_size), range(conditional_size*8, 0, -8)):
				s1_part = se.Extract(conditional_size*8-1, bit-8, s1_all)
				s2_part = se.Extract(conditional_size*8-1, bit-8, s2_all)
				cases = [ [s1_part == s2_part, 0], [s1_part < s2_part, -1], [s1_part > s2_part, 1 ] ]
				conditional_rets[byte+1] = simuvex.helpers.sim_cases_autoadd(self.state, cases, sym_name="memcpy_case")

			ret_expr = simuvex.helpers.sim_ite_dict_autoadd(self.state, n.expr - definite_size, conditional_rets, sym_name="memcmp")
			self.exit_return(ret_expr)
		else:
			self.exit_return(definite_answer)

