#!/usr/bin/env python

from .s_run import SimRun
import itertools

import logging
l = logging.getLogger(name = "s_absfunc")

symbolic_count = itertools.count()

class SimProcedure(SimRun):
	# The SimProcedure constructor, when receiving a None mode and options, defaults to mode="static"
	def __init__(self, state, procedure_id=None, options=None, mode=None, convention="cdecl"):
		SimRun.__init__(self, options=options, mode=mode)
		self.id = procedure_id
		self.initial_state = state.copy_after()
		self.addr_from = -1
		self.convention = convention

	# Returns a bitvector expression representing the nth argument of a function
	def get_function_arg_expr(self, index):
		pass

	# Returns a bitvector expression representing the nth argument of a syscall
	def get_syscall_arg_expr(self, index):
		pass

	# Sets an expression as the return value. Also updates state.
	def set_return_expr(self, expr):
		pass

	# Does a return (pop, etc) and returns an bitvector expression representing the return value. Also updates state.
	def do_return(self):
		pass
