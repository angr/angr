#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import symexec
import s_value
from s_irexpr import SimIRExpr
import s_helpers

import logging
l = logging.getLogger("s_exit")

class SimExit:
	# Index of the statement that performs this exit in irsb.statements()
	# src_stmt_index == None for exits pointing to the next code block
	src_stmt_index = None 
	# Address of the instruction that performs this exit
	src_addr = None 

	def __init__(self, empty = False, sirsb_exit = None, sirsb_postcall = None, sexit = None, stmt_index = None, addr=None, addr_state=None, static=True):
		exit_source_stmt_index = None
		if stmt_index != None:
			exit_source_stmt_index = stmt_index

		exit_target = None
		exit_jumpkind = None
		exit_constraints = None
		exit_source_addr = None

		if sirsb_exit is not None:
			l.debug("Making exit out of IRSB.")

			exit_state = sirsb_exit.final_state.copy_after()
			exit_target, exit_constraints = SimIRExpr(sirsb_exit.irsb.next, exit_state).expr_and_constraints()
			exit_jumpkind = sirsb_exit.irsb.jumpkind
			exit_source_addr = sirsb_exit.last_imark.addr
			exit_source_stmt_index = len(sirsb_exit.irsb.statements()) - 1
		elif sirsb_postcall is not None:
			l.debug("Making entry to post-call of IRSB.")

			# first emulate the ret
			exit_state = sirsb_postcall.final_state.copy_after()

			if static:
				exit_state = sirsb_postcall.final_state.copy_after()
				exit_target = symexec.BitVecVal(sirsb_postcall.last_imark.addr + sirsb_postcall.last_imark.len, sirsb_postcall.final_state.arch.bits)
				exit_jumpkind = "Ijk_Ret"
				# TODO: is this correct?
				exit_source_addr = sirsb_postcall.last_imark.addr
				exit_source_stmt_index = len(sirsb_postcall.irsb.statements()) - 1
			else:
				ret_exit = exit_state.arch.emulate_subroutine(sirsb_postcall.last_imark,exit_state)
				exit_target = ret_exit.s_target
				exit_jumpkind = ret_exit.jumpkind
				exit_state = ret_exit.state
				exit_source_stmt_index = ret_exit.src_stmt_index
				exit_source_addr = ret_exit.src_addr

		elif sexit is not None:
			l.debug("Making exit from Exit IRStmt")

			exit_state = sexit.state.copy_after()
			exit_target = s_helpers.translate_irconst(sexit.stmt.dst)
			exit_jumpkind = sexit.stmt.jumpkind
			exit_source_addr = sexit.stmt.offsIP
		elif addr is not None and addr_state is not None:
			exit_state = addr_state.copy_after()
			exit_target = symexec.BitVecVal(addr, addr_state.arch.bits)
			exit_jumpkind = "Ijk_Boring"
		else:
			raise Exception("Invalid SimExit creation.")

		if exit_constraints:
			exit_state.add_constraints(*exit_constraints)
			exit_state.inplace_after()

		# symplify constraints to speed this up
		exit_state.simplify()

		self.s_target = exit_target
		self.jumpkind = exit_jumpkind
		self.state = exit_state
		self.src_stmt_index = exit_source_stmt_index
		self.src_addr = exit_source_addr

		# the simvalue to use
		self.simvalue = s_value.SimValue(self.s_target, self.state.constraints_after())

	# Tries a constraint check to see if this exit is reachable.
	def reachable(self):
		l.debug("Checking reachability with %d constraints" % len(self.state.constraints_after()))
		return self.simvalue.satisfiable()

	def concretize(self):
		if not self.is_unique():
			raise s_value.ConcretizingException("Exit has multiple values")

		return self.simvalue.any()

	def concretize_n(self, n):
		return self.simvalue.any_n(n)

	def is_unique(self):
		return self.simvalue.is_unique()
