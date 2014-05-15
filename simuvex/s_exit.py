#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import symexec as se
from .s_helpers import ondemand, translate_irconst

import logging
l = logging.getLogger("s_exit")

maximum_exit_split = 255

class SimExit(object):
	'''A SimExit tracks a state, the execution point, and the condition to take a jump.'''

	def __init__(self, sirsb_exit = None, sirsb_postcall = None, sexit = None, addr=None, expr=None, state=None, jumpkind=None, guard=None, simple_postcall=True, simplify=True, state_is_raw=True, default_exit=False):
		'''
		Creates a SimExit. Takes the following groups of parameters:

			@param sirsb_exit: the SimIRSB to exit from
			@param sexit: an exit statement to exit from

			@param sirsb_postcall: the SimIRSB to perform a ret-emulation for, to facilitate static analysis after function calls.
			@param simple_postcall: the the ret-emulation simply (ie, the next instruction after the call) instead of actually emulating a ret

			@param addr: an address to exit to
			@param expr: an address (z3 expression) to exit to
			@param state: the state for the addr and expr options
			@param guard: the guard condition for the addr and expr options. Default True
			@param jumpkind: the jumpind

			@param simplify: simplify the state and various expressions
			@param state_is_raw: a True value signifies that the state has not had the guard instruction added to it, and should have it added.
		'''

		# the state of exit, without accounting for the guard condition
		self.raw_state = None

		# the type of jump
		self.jumpkind = None

		# the target of the exit the guard condition
		self.target = None
		self.guard = None
		self.default_exit = default_exit

		# set the right type of exit
		if sirsb_exit is not None:
			self.set_irsb_exit(sirsb_exit)
		elif sirsb_postcall is not None:
			self.set_postcall(sirsb_postcall, simple_postcall, state=state)
		elif sexit is not None:
			self.set_stmt_exit(sexit)
		elif addr is not None and state is not None:
			self.set_addr_exit(addr, state, guard)
		elif expr is not None and state is not None:
			self.set_expr_exit(expr, state, guard)
		else:
			raise Exception("Invalid SimExit creation.")

		if jumpkind is not None:
			self.jumpkind = jumpkind

		if state_is_raw:
			if o.COW_STATES in self.raw_state.options:
				self.state = self.raw_state.copy()
			elif o.SINGLE_EXIT not in self.raw_state.options:
				raise Exception("COW_STATES *must* be used with SINGLE_EXIT for now.")
			else:
				self.state = self.raw_state

			if se.is_symbolic(self.guard):
				self.state.add_constraints(self.guard)
		else:
			self.state = self.raw_state

		for r in self.state.arch.concretize_unique_registers:
			v = self.state.reg_value(r)
			if v.is_unique() and v.is_symbolic():
				self.state.store_reg(r, v.any())

		# we no longer need the raw state
		del self.raw_state

		# simplify constraints to speed this up
		if simplify:
			self.state.simplify()
			self.target = se.simplify_expression(self.target)
			self.guard = se.simplify_expression(self.guard)

		# the sim_values for the target and guard
		self.target_value = self.state.expr_value(self.target)
		self.guard_value = self.state.expr_value(self.guard)

		self.state._inspect('exit', BP_BEFORE, exit_target=self.target, exit_guard=self.guard)

		if self.target_value.is_symbolic():
			l.debug("Made exit to symbolic expression.")
		else:
			l.debug("Made exit to address 0x%x.", self.target_value.any())

		if o.DOWNSIZE_Z3 in self.state.options:
			self.downsize()

	def downsize(self):
		# precache, so we don't have to upsize
		_ = self.is_unique()
		_ = self.reachable()
		try:
			_ = self.concretize()
		except ConcretizingException:
			pass

		self.state.downsize()

	@property
	def is_error(self):
		return self.jumpkind in ("Ijk_EmFail", "Ijk_NoDecode", "Ijk_MapFail") or "Ijk_Sig" in self.jumpkind

	@property
	def is_syscall(self):
		return "Ijk_Sys" in self.jumpkind

	def set_postcall(self, sirsb_postcall, simple_postcall, state=None):
		l.debug("Making entry to post-call of IRSB.")

		state = sirsb_postcall.state if state is None else state

		# never actually taken
		self.guard = se.BoolVal(False)

		if simple_postcall:
			self.raw_state = state
			self.target = se.BitVecVal(sirsb_postcall.last_imark.addr + sirsb_postcall.last_imark.len, state.arch.bits)
			self.jumpkind = "Ijk_Ret"
		else:
			# first emulate the ret
			exit_state = state.copy()
			ret_irsb = exit_state.arch.get_ret_irsb(sirsb_postcall.last_imark.addr)
			ret_sirsb = SimIRSB(exit_state, ret_irsb, inline=True)
			ret_exit = ret_sirsb.exits()[0]

			self.target = ret_exit.target
			self.jumpkind = ret_exit.jumpkind
			self.raw_state = ret_exit.state

	def set_irsb_exit(self, sirsb):
		self.raw_state = sirsb.state
		self.target = sirsb.next_expr.expr
		self.jumpkind = sirsb.irsb.jumpkind
		self.guard = sirsb.default_exit_guard

	def set_stmt_exit(self, sexit):
		self.raw_state = sexit.state.copy()
		self.target = translate_irconst(sexit.stmt.dst)
		self.jumpkind = sexit.stmt.jumpkind
		self.guard = sexit.guard.expr != 0

		# TODO: update instruction pointer

	def set_addr_exit(self, addr, state, guard):
		self.set_expr_exit(se.BitVecVal(addr, state.arch.bits), state, guard)

	def set_expr_exit(self, expr, state, guard):
		self.raw_state = state
		self.target = expr
		self.jumpkind = "Ijk_Boring"
		self.guard = guard if guard is not None else se.BoolVal(True)

	# Tries a constraint check to see if this exit is reachable.
	@ondemand
	def reachable(self):
		l.debug("Checking reachability of %s.", self.state)
		return self.guard_value.is_solution(True)

	@ondemand
	def is_unique(self):
		return self.target_value.is_unique()

	@ondemand
	def concretize(self):
		if self.jumpkind.startswith("Ijk_Sys"):
			return -1

		if not self.is_unique():
			raise ConcretizingException("Exit is not single-valued!")

		return self.target_value.any()

	# Copies the exit (also copying the state).
	def copy(self):
		return SimExit(expr=self.target, state=self.state.copy(), jumpkind=self.jumpkind, guard=self.guard, simplify=False, state_is_raw=False)

	# Splits a multi-valued exit into multiple exits.
	def split(self, maximum=maximum_exit_split):
		exits = [ ]

		possible_values = self.target_value.any_n(maximum + 1)
		if len(possible_values) > maximum:
			l.warning("SimExit.split() received over %d values. Likely unconstrained, so returning [].", maximum)
			possible_values = [ ]

		for p in possible_values:
			l.debug("Splitting off exit with address 0x%x", p)
			new_state = self.state.copy()
			if self.target_value.is_symbolic():
				new_state.add_constraints(self.target == p)
			exits.append(SimExit(addr=p, state=new_state, jumpkind=self.jumpkind, guard=self.guard, simplify=False, state_is_raw=False))

		return exits

from .s_value import ConcretizingException
from .s_irsb import SimIRSB
from .s_inspect import BP_BEFORE
import simuvex.s_options as o
