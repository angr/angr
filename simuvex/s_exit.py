#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import symexec
import s_value
from s_irexpr import SimIRExpr
import s_helpers

import logging
l = logging.getLogger("s_exit")

class SimExit:
	def set_postcall(self, sirsb_postcall, static):
		l.debug("Making entry to post-call of IRSB.")

		if static:
			self.state = sirsb_postcall.final_state.copy_after()
			self.target = symexec.BitVecVal(sirsb_postcall.last_imark.addr + sirsb_postcall.last_imark.len, sirsb_postcall.final_state.arch.bits)
			self.jumpkind = "Ijk_Ret"
			# TODO: is this correct?
			self.src_addr = sirsb_postcall.last_imark.addr
			self.src_stmt_index = len(sirsb_postcall.irsb.statements()) - 1
		else:
			# first emulate the ret
			exit_state = sirsb_postcall.final_state.copy_after()
			ret_exit = exit_state.arch.emulate_subroutine(sirsb_postcall.last_imark,exit_state)

			self.target = ret_exit.target
			self.jumpkind = ret_exit.jumpkind
			self.state = ret_exit.state
			self.src_stmt_index = ret_exit.src_stmt_index
			self.src_addr = ret_exit.src_addr

	def set_irsb_exit(self, sirsb_exit):
		l.debug("Making exit out of IRSB.")

		self.state = sirsb_exit.final_state.copy_after()
		self.target, exit_constraints = SimIRExpr(sirsb_exit.irsb.next, self.state, sirsb_exit.options).expr_and_constraints()

		# apply extra constraints that might have been introduced by determining the target
		self.state.add_constraints(*exit_constraints)
		self.state.inplace_after()

		self.jumpkind = sirsb_exit.irsb.jumpkind
		self.src_addr = sirsb_exit.last_imark.addr
		self.src_stmt_index = len(sirsb_exit.irsb.statements()) - 1

	def set_stmt_exit(self, sexit):
		l.debug("Making exit from Exit IRStmt")

		self.state = sexit.state.copy_after()
		self.target = s_helpers.translate_irconst(sexit.stmt.dst)
		self.jumpkind = sexit.stmt.jumpkind
		self.src_addr = sexit.stmt.offsIP

	def set_addr_exit(self, addr, addr_state):
		l.debug("Making exit to address 0x%x", addr)

		self.state = addr_state.copy_after()
		self.target = symexec.BitVecVal(addr, addr_state.arch.bits)
		self.jumpkind = "Ijk_Boring"

	def __init__(self, sirsb_exit = None, sirsb_postcall = None, sexit = None, stmt_index = None, addr=None, addr_state=None, static=True):
		# Address of the instruction that performs this exit
		self.src_addr = None 
		# Index of the statement that performs this exit in irsb.statements()
		# src_stmt_index == None for exits pointing to the next code block
		self.src_stmt_index = stmt_index

		# the target of the exit
		self.target = None

		# the state at the exit
		self.state = None

		# the type of jump
		self.jumpkind = None

		# set the right type of exit
		if sirsb_exit is not None:
			self.set_irsb_exit(sirsb_exit)
		elif sirsb_postcall is not None:
			self.set_postcall(sirsb_postcall, static)
		elif sexit is not None:
			self.set_stmt_exit(sexit)
		elif addr is not None and addr_state is not None:
			self.set_addr_exit(addr, addr_state)
		else:
			raise Exception("Invalid SimExit creation.")

		# symplify constraints to speed this up
		self.state.simplify()

		# the simvalue to use
		self.simvalue = s_value.SimValue(self.target, self.state.constraints_after())

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
