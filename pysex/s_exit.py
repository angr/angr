#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import z3
import s_value
import s_irexpr
import s_helpers

import logging
l = logging.getLogger("s_exit")

def ondemand(f):
	name = f.__name__
	def func(self, *args, **kwargs):
		if hasattr(self, "_" + name):
			return getattr(self, "_" + name)

		a = f(self, *args, **kwargs)
		setattr(self, "_" + name, a)
		return a
	func.__name__ = f.__name__
	return func

class SymbolicExit:
	def __init__(self, empty = False, sirsb_exit = None, sirsb_entry = None, sirsb_postcall = None, sexit = None, sexit_postcall = None):
		if empty:
			l.debug("Making empty exit.")
			return

		exit_target = None
		exit_jumpkind = None
		exit_constraints = None

		if sirsb_entry is not None:
			l.debug("Making entry into IRSB.")

			exit_state = sirsb_entry.initial_state.copy_after()
			exit_target = z3.BitVecVal(sirsb_entry.first_imark.addr, sirsb_entry.bits)
			exit_jumpkind = "Ijk_Boring"
		elif sirsb_exit is not None:
			l.debug("Making exit out of IRSB.")

			exit_state = sirsb_exit.final_state.copy_after()
			exit_target, exit_constraints = s_irexpr.translate(sirsb_exit.irsb.next, exit_state)
			exit_jumpkind = sirsb_exit.irsb.jumpkind
		elif sirsb_postcall is not None:
			l.debug("Making entry to post-call of IRSB.")

			exit_state = sirsb_postcall.final_state.copy_after()
			# TODO: platform-specific call emulation
			exit_target = z3.BitVecVal(sirsb_postcall.first_imark.addr + sirsb_postcall.first_imark.len, sirsb_postcall.bits)
			exit_jumpkind = "Ijk_INVALID"
		elif sexit is not None:
			l.debug("Making exit from Exit IRStmt")

			exit_state = sexit.state.copy_after()
			exit_target = s_helpers.translate_irconst(sexit.stmt.dst)
			exit_jumpkind = sexit.stmt.jumpkind
		elif sexit_postcall is not None:
			l.debug("Making post-call exit from Exit IRStmt")

			exit_state = sexit_postcall.state.copy_after()
			exit_target = z3.BitVecVal(sexit_postcall.imark.addr + sexit_postcall.imark.len, s_helpers.translate_irconst(sexit_postcall.stmt.dst).size())
			# TODO: platform-specific call emulation
			exit_jumpkind = sexit_postcall.stmt.jumpkind
		else:
			raise Exception("Invalid SymbolicExit creation.")

		if exit_constraints:
			exit_state.add_constraints(*exit_constraints)
			exit_state.inplace_after()

		self.s_target = exit_target
		self.jumpkind = exit_jumpkind
		self.state = exit_state

	@ondemand
	def concretize(self):
		cval = s_value.Value(self.s_target, self.state.constraints_after())
		if cval.min != cval.max:
			raise s_value.ConcretizingException("Exit has multiple values between %x and %x" % (cval.min, cval.max))
		return cval.min
