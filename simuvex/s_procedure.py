#!/usr/bin/env python

from .s_run import SimRun, SimRunMeta
from .s_exception import SimProcedureError
from .s_helpers import get_and_remove, flagged
from .s_exit import SimExit
from .s_ref import SimRegRead, SimMemRead
import itertools

import logging
l = logging.getLogger(name = "s_absfunc")

symbolic_count = itertools.count()

class SimRunProcedureMeta(SimRunMeta):
	def __call__(mcs, *args, **kwargs):
		stmt_from = get_and_remove(kwargs, 'stmt_from')
		convention = get_and_remove(kwargs, 'convention')

		c = super(SimRunProcedureMeta, mcs).make_run(args, kwargs)
		SimProcedure.__init__(c, stmt_from=stmt_from, convention=convention)
		if not hasattr(c.__init__, 'flagged'):
			c.__init__(*args[1:], **kwargs)
		return c

class SimProcedure(SimRun):
	__metaclass__ = SimRunProcedureMeta

	# The SimProcedure constructor, when receiving a None mode and options, defaults to mode="static"
	#
	#	calling convention is one of: "systemv_x64", "syscall", "microsoft_x64", "cdecl", "arm", "mips"
	@flagged
	def __init__(self, stmt_from=None, convention=None): # pylint: disable=W0231
		self.stmt_from = -1 if stmt_from is None else stmt_from
		self.convention = None
		self.set_convention(convention)

	def reanalyze(self, new_state, mode=None, options=None, addr=None, stmt_from=None, convention=None):
		mode = self.mode if mode is None else mode
		options = self.options if options is None else options
		addr = self.addr if addr is None else addr
		stmt_from = self.stmt_from if stmt_from is None else stmt_from
		convention = self.convention if convention is None else convention

		return self.__class__(new_state, mode=mode, options=options, addr=addr, stmt_from=stmt_from, convention=convention)

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
	def arg_reg_stack(self, reg_offsets, stack_skip, stack_step, index, add_refs=False):
		if index < len(reg_offsets):
			expr = self.state.reg_expr(reg_offsets[index])
			ref = SimRegRead(self.addr, self.stmt_from, reg_offsets[index], self.state.expr_value(expr), self.state.arch.bits/8)
		else:
			index -= len(reg_offsets)
			expr = self.state.stack_read(stack_step * (index + stack_skip))

			stack_addr = self.state.reg_expr(self.state.arch.sp_offset) * (index + stack_skip)
			ref = SimMemRead(self.addr, self.stmt_from, self.state.expr_value(stack_addr), self.state.expr_value(expr), self.state.arch.bits/8)

		if add_refs: self.add_refs(ref)
		return expr


	def get_arg_reg_offsets(self):
		if self.convention == "systemv_x64" and self.state.arch.name == "AMD64":
			reg_offsets = [ 72, 64, 32, 24, 80, 88 ] # rdi, rsi, rdx, rcx, r8, r9
		elif self.convention == "syscall" and self.state.arch.name == "AMD64":
			reg_offsets = [ 72, 64, 32, 24, 80, 88 ] # rdi, rsi, rdx, rcx, r8, r9
		else:
			raise SimProcedureError("Unsupported arch %s for getting register offsets", self.convention)
		return reg_offsets

	# Returns a bitvector expression representing the nth argument of a function
	def peek_arg_expr(self, index, add_refs=False):
		if self.convention == "systemv_x64" and self.state.arch.name == "AMD64":
			reg_offsets = self.get_arg_reg_offsets()
			return self.arg_reg_stack(reg_offsets, 1, -8, index, add_refs=add_refs)
		elif self.convention == "syscall" and self.state.arch.name == "AMD64":
			reg_offsets = self.get_arg_reg_offsets()
			return self.arg_reg_stack(reg_offsets, 1, -8, index, add_refs=add_refs)

		raise SimProcedureError("Unsupported calling convention %s for arguments", self.convention)

	def peek_arg_value(self, index):
		return self.state.expr_value(self.peek_arg_expr(index))

	# Returns a bitvector expression representing the nth argument of a function, and add refs
	def get_arg_expr(self, index):
		return self.peek_arg_expr(index, add_refs=True)

	def get_arg_value(self, index):
		return self.state.expr_value(self.get_arg_expr(index))

	# Sets an expression as the return value. Also updates state.
	def set_return_expr(self, expr):
		if self.state.arch.name == "AMD64":
			self.state.store_reg(16, expr)
		else:
			raise SimProcedureError("Unsupported calling convention %s for returns", self.convention)

	# Does a return (pop, etc) and returns an bitvector expression representing the return value. Also updates state.
	def do_return(self):
		if self.state.arch.name == "AMD64":
			return self.state.stack_pop()
		else:
			raise SimProcedureError("Unsupported platform %s for return emulation.", self.state.arch.name)

	# Adds an exit representing the function returning. Modifies the state.
	def exit_return(self, expr=None):
		if expr is not None: self.set_return_expr(expr)
		ret_target = self.do_return()

		self.add_exits(SimExit(expr=ret_target, state=self.state))

	def __repr__(self):
		return "<SimProcedure %s>" % self.__class__.__name__
