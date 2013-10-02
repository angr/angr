#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import pyvex
import s_irexpr
import s_helpers
import s_value

import logging
l = logging.getLogger("s_exit")

class SymbolicExit:
	def __init__(self, gah = None, sirsb = None, simark = None, sexit = None, s_target = None, after_ret = None, jumpkind = None, state = None):
		if s_target is not None:
			l.debug("Checking provided exit")
			self.after_ret = after_ret
			self.s_target = s_target
			self.jumpkind = jumpkind
			self.state = state.copy_after()
		elif sirsb is not None:
			l.debug("Checking exit at end of IRSB.")
			if sirsb.irsb.jumpkind == "Ijk_Call":
				self.after_ret = sirsb.last_imark.addr + sirsb.last_imark.len
			else:
				self.after_ret = None

			state = sirsb.state.copy_after()
			self.s_target, next_constraints = s_irexpr.translate(sirsb.irsb.next, state)
			state.add_constraints(*next_constraints)

			self.jumpkind = sirsb.irsb.jumpkind
			self.state = state.copy_after()
		elif sexit is not None:
			l.debug("Checking exit from Exit IRStmt")
			if sexit.stmt.jumpkind == "Ijk_Call":
				self.after_ret = sexit.imark.addr + sexit.imark.len
			else:
				self.after_ret = None

			self.s_target = s_helpers.translate_irconst(sexit.stmt.dst)
			self.jumpkind = sexit.stmt.jumpkind
			self.state = sexit.state.copy_after()
		elif type(simark.stmt) == pyvex.IRStmt.IMark:
			l.debug("Checking entrance to an IMark IRStmt")
			self.after_ret = None
			self.s_target = s_helpers.translate_irconst(simark.stmt.addr)
			self.jumpkind = None
			self.state = simark.state.copy_after()
		else:
			raise Exception("Invalid SymbolicExit creation.")

	def concretize(self):
		cval = s_value.Value(self.s_target, self.state.constraints_after())
		if cval.min != cval.max:
			raise s_value.ConcretizingException("Exit has multiple values between %x and %x" % (cval.min, cval.max))
		return cval.min
