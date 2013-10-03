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
	def __init__(self, empty = False, sirsb_exit = None, sirsb_entry = None, sirsb_postcall = None, sexit = None, sexit_postcall = None):
		if empty:
			l.debug("Making empty exit.")
			self.c_target = None
			return

		exit_target = None
		exit_jumpkind = None
		exit_constraints = None
		exit_constant = None

		if sirsb_entry is not None:
			l.debug("Making entry into IRSB.")

			exit_state = sirsb_entry.initial_state.copy_after()
			exit_constant = sirsb_entry.first_imark.addr
			exit_target = z3.BitVecVal(exit_constant, sirsb_entry.bits)
			exit_jumpkind = "Ijk_Boring"
		elif sirsb_exit is not None:
			l.debug("Making exit out of IRSB.")

			exit_state = sirsb_exit.final_state.copy_after()
			exit_target, exit_constraints = s_irexpr.translate(sirsb_exit.irsb.next, exit_state)
			if type(sirsb_exit.irsb.next) == pyvex.IRExpr.Const:
				exit_constant = sirsb_exit.irsb.next.con.value

			exit_jumpkind = sirsb_exit.irsb.jumpkind
		elif sirsb_postcall is not None:
			l.debug("Making entry to post-call of IRSB.")

			exit_state = sirsb_postcall.final_state.copy_after()
			# TODO: platform-specific call emulation
			exit_constant = sirsb_postcall.first_imark.addr + sirsb_postcall.first_imark.len
			exit_target = z3.BitVecVal(exit_constant, sirsb_postcall.bits)
			exit_jumpkind = "Ijk_INVALID"
		elif sexit is not None:
			l.debug("Making exit from Exit IRStmt")

			exit_state = sexit.state.copy_after()
			exit_constant = sexit.stmt.dst.value
			exit_target = s_helpers.translate_irconst(sexit.stmt.dst)
			exit_jumpkind = sexit.stmt.jumpkind
		elif sexit_postcall is not None:
			l.debug("Making post-call exit from Exit IRStmt")

			exit_state = sexit_postcall.state.copy_after()
			exit_constant = sexit_postcall.imark.addr + sexit_postcall.imark.len
			exit_target = z3.BitVecVal(exit_constant, s_helpers.translate_irconst(sexit_postcall.stmt.dst).size())
			# TODO: platform-specific call emulation
			exit_jumpkind = sexit_postcall.stmt.jumpkind

			# exits always have an IRConst dst
			exit_constant = True
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

	@s_helpers.ondemand
	def concretize(self):
		if not self.c_target and not self.is_unique():
			raise s_value.ConcretizingException("Exit has multiple values")

		cval = s_value.Value(self.s_target, self.state.constraints_after())
		return cval.any()

	@s_helpers.ondemand
	def is_unique(self):
		return s_value.Value(self.s_target, self.state.constraints_after()).is_unique()
