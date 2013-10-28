#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import z3
import pyvex
import s_value
import s_irexpr
import s_helpers

import logging
l = logging.getLogger("s_exit")

class SymbolicExit:
	# Index of the statement that performs this exit in irsb.statements()
	# src_stmt_index == None for exits pointing to the next code block
	src_stmt_index = None 
	# Address of the instruction that performs this exit
	src_addr = None 

	def __init__(self, empty = False, sirsb_exit = None, sirsb_entry = None, sirsb_postcall = None, sexit = None, sexit_postcall = None, stmt_index = None):
		if empty:
			l.debug("Making empty exit.")
			self.c_target = None
			return
		
		exit_source_stmt_index = None
		if stmt_index != None:
			exit_source_stmt_index = stmt_index

		exit_target = None
		exit_jumpkind = None
		exit_constraints = None
		exit_constant = None
		exit_source_addr = None

		if sirsb_entry is not None:
			l.debug("Making entry into IRSB.")

			exit_state = sirsb_entry.initial_state.copy_after()
			exit_constant = sirsb_entry.first_imark.addr
			exit_target = z3.BitVecVal(exit_constant, exit_state.arch.bits)
			exit_jumpkind = "Ijk_Boring"
		elif sirsb_exit is not None:
			l.debug("Making exit out of IRSB.")

			exit_state = sirsb_exit.final_state.copy_after()
			exit_target, exit_constraints = s_irexpr.translate(sirsb_exit.irsb.next, exit_state)
			if type(sirsb_exit.irsb.next) == pyvex.IRExpr.Const:
				exit_constant = sirsb_exit.irsb.next.con.value

			exit_jumpkind = sirsb_exit.irsb.jumpkind

			# Scan the statements in a reverse order to check the address of the last instruction
			stmt_imark = ([s for s in sirsb_exit.irsb.statements() if type(s) == pyvex.IRStmt.IMark])[-1]
			exit_source_addr = stmt_imark.addr
			# Always the last statement
			exit_source_stmt_index = len(sirsb_exit.irsb.statements()) - 1
		elif sirsb_postcall is not None:
			l.debug("Making entry to post-call of IRSB.")

			# first emulate the ret
			exit_state = sirsb_postcall.final_state.copy_after()
			ret_exit=exit_state.arch.emulate_subroutine(sirsb_postcall.last_imark,exit_state)

			# now copy the exit
			exit_target = ret_exit.s_target
			exit_jumpkind = ret_exit.jumpkind
			exit_state = ret_exit.state
			exit_constant = ret_exit.c_target
			exit_source_stmt_index = ret_exit.src_stmt_index
			exit_source_addr = ret_exit.src_addr
		elif sexit is not None:
			l.debug("Making exit from Exit IRStmt")

			exit_state = sexit.state.copy_after()
			exit_constant = sexit.stmt.dst.value
			exit_target = s_helpers.translate_irconst(sexit.stmt.dst)
			exit_jumpkind = sexit.stmt.jumpkind
			exit_source_addr = sexit.stmt.offsIP
		elif sexit_postcall is not None:
			l.debug("Making post-call exit from Exit IRStmt")

			exit_state = sexit_postcall.state.copy_after()
			exit_constant = sexit_postcall.imark.addr + sexit_postcall.imark.len
			exit_target = z3.BitVecVal(exit_constant, s_helpers.translate_irconst(sexit_postcall.stmt.dst).size())
			# TODO: platform-specific call emulation
			exit_jumpkind = sexit_postcall.stmt.jumpkind

			# exits always have an IRConst dst
			exit_constant = True

			exit_source_addr = sexit_postcall.stmt.offsIP
		else:
			raise Exception("Invalid SymbolicExit creation.")

		if exit_constraints:
			exit_state.add_constraints(*exit_constraints)
			exit_state.inplace_after()

		# symplify constraints to speed this up
		exit_state.old_constraints = [ z3.simplify(z3.And(*exit_state.old_constraints)) ]

		self.s_target = exit_target
		self.jumpkind = exit_jumpkind
		self.state = exit_state
		self.c_target = exit_constant
		self.src_stmt_index = exit_source_stmt_index
		self.src_addr = exit_source_addr

	# Tries a constraint check to see if this exit is reachable.
	def reachable(self):
		l.debug("Checking reachability with %d constraints" % len(self.state.constraints_after()))
		s = z3.Solver()
		s.add(*self.state.constraints_after())
		return s.check() == z3.sat

	def symbolic_value(self):
		return s_value.Value(self.s_target, self.state.constraints_after())

	def concretize(self):
		if not self.c_target and not self.is_unique():
			raise s_value.ConcretizingException("Exit has multiple values")

		cval = self.symbolic_value()
		return cval.any()

	def concretize_n(self, n):
		cval = self.symbolic_value()
		return cval.any_n(n)

	def is_unique(self):
		return self.symbolic_value().is_unique()
