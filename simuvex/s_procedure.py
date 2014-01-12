#!/usr/bin/env python

from .s_run import SimRun
from .s_exception import SimProcedureError
import itertools

import logging
l = logging.getLogger(name = "s_absfunc")

symbolic_count = itertools.count()

class SimProcedure(SimRun):
	# The SimProcedure constructor, when receiving a None mode and options, defaults to mode="static"
	#
	#	calling convention is one of: "systemv_x64", "syscall", "microsoft_x64", "cdecl", "arm", "mips"
	def __init__(self, state, procedure_id=None, options=None, mode=None, convention=None):
		SimRun.__init__(self, options=options, mode=mode)
		self.id = procedure_id
		self.addr_from = -1
		self.convention = None
		self.set_convention(convention)

	def initialize_run(self):
		pass

	def handle_run(self):
		self.handle_procedure()

	def handle_procedure(self):
		raise Exception("SimProcedure.handle_procedure() has been called. This should have been overwritten in class %s.", self.__class__)

	def set_convention(self, convention=None):
		if convention is None:
			if self.state.arch.name == "AMD64":
				convention = "systemv_x64"
			elif self.state.arch.name == "x86":
				convention = "cdecl"
			elif self.state.arch.name == "arm":
				convention = "arm"
			elif self.state.arch.name == "mips":
				convention = "os2_mips"

		self.convention = convention

	# Helper function to get an argument, given a list of register locations it can be and stack information for overflows.
	def arg_reg_stack(self, reg_offsets, stack_skip, stack_step, index):
		if index < len(reg_offsets):
			return self.state.reg_expr(reg_offsets[index])
		else:
			index -= len(reg_offsets)
			return self.state.stack_read(stack_step * (index + stack_skip))

	# Returns a bitvector expression representing the nth argument of a function
	def get_arg_expr(self, index):
		if self.convention == "systemv_x64" and self.state.arch.name == "AMD64":
			reg_offsets = [ 72, 64, 32, 24, 80, 88 ] # rdi, rsi, rdx, rcx, r8, r9
			return self.arg_reg_stack(reg_offsets, 1, -8, index)
		elif self.convention == "syscall" and self.state.arch.name == "AMD64":
			reg_offsets = [ 72, 64, 32, 96, 80, 88 ] # rdi, rsi, rdx, r10, r8, r9
			return self.arg_reg_stack(reg_offsets, 1, -8, index)

		raise SimProcedureError("Unsupported calling convention %s for arguments", self.convention)

	# Sets an expression as the return value. Also updates state.
	def set_return_expr(self, expr):
		if self.state.arch.name == "AMD64":
			self.state.store_reg(16, expr)

		raise SimProcedureError("Unsupported calling convention %s for returns", self.convention)

	# Does a return (pop, etc) and returns an bitvector expression representing the return value. Also updates state.
	def do_return(self):
		if self.state.arch.name == "AMD64":
			return self.state.stack_pop()

		raise SimProcedureError("Unsupported platform %s for return emulation.", self.state.arch.name)
