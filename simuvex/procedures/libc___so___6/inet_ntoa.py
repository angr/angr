import simuvex
from simuvex.s_type import SimTypeString
import logging

l = logging.getLogger("simuvex.procedures.libc.inet_ntoa")


class inet_ntoa(simuvex.SimProcedure):
	def analyze(self):
		# arg types: struct....... :(
		self.return_type = self.ty_ptr(SimTypeString())

		#TODO: return an IP address string
		_ = self.arg(0)
		ret_expr = self.state.BV("inet_ntoa_ret", self.state.arch.bits)
		return ret_expr
