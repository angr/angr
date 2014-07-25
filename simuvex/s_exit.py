'''This module handles exits from IRSBs.'''

from .s_helpers import ondemand, translate_irconst
import claripy

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

		# handle setting up the state
		if state_is_raw:
			if o.COW_STATES in self.raw_state.options:
				self.state = self.raw_state.copy()
			elif o.SINGLE_EXIT not in self.raw_state.options:
				raise Exception("COW_STATES *must* be used with SINGLE_EXIT for now.")
			else:
				self.state = self.raw_state
		else:
			self.state = self.raw_state

		# make sure the target is a bitvector
		if type(self.target) in (int, long):
			self.target = self.state.BVV(self.target, self.state.arch.bits)

		for r in self.state.arch.concretize_unique_registers:
			v = self.state.reg_expr(r)
			if self.state.se.unique(v) and self.state.se.symbolic(v):
				self.state.store_reg(r, self.state.se.any(v))

		# we no longer need the raw state
		del self.raw_state

		# simplify constraints to speed this up
		if simplify:
			self.state.simplify()
			self.target = self.state.simplify(self.target)
			self.guard = self.state.simplify(self.guard)

		self.state.add_constraints(self.guard)
		self.state._inspect('exit', BP_BEFORE, exit_target=self.target, exit_guard=self.guard)

		#if self.state.se.symbolic(self.target):
		#	l.debug("Made exit to symbolic expression.")
		#else:
		#	l.debug("Made exit to address 0x%x.", self.state.se.any_int(self.target))

		if o.DOWNSIZE_Z3 in self.state.options:
			self.downsize()

	def downsize(self):
		# precache, so we don't have to upsize
		_ = self.is_unique()
		_ = self.reachable()
		try:
			_ = self.concretize()
		except SimValueError:
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

		if simple_postcall:
			self.raw_state = state
			self.target = state.se.BitVecVal(sirsb_postcall.last_imark.addr + sirsb_postcall.last_imark.len, state.arch.bits)
			self.jumpkind = "Ijk_Ret"
		else:
			# first emulate the ret
			exit_state = state.copy()
			ret_irsb = exit_state.arch.get_ret_irsb(sirsb_postcall.last_imark.addr)
			ret_sirsb = SimIRSB(exit_state, ret_irsb, inline=True) #pylint:disable=E1123
			ret_exit = ret_sirsb.exits()[0]

			self.target = ret_exit.target
			self.jumpkind = ret_exit.jumpkind
			self.raw_state = ret_exit.state

		# never actually taken
		self.guard = self.raw_state.se.BoolVal(False)

	def set_irsb_exit(self, sirsb):
		self.raw_state = sirsb.state
		self.target = sirsb.next_expr.expr
		self.jumpkind = sirsb.irsb.jumpkind
		self.guard = sirsb.default_exit_guard

	def set_stmt_exit(self, sexit):
		self.raw_state = sexit.state.copy()
		self.target = translate_irconst(self.raw_state, sexit.stmt.dst)
		self.jumpkind = sexit.stmt.jumpkind
		self.guard = sexit.guard.expr != 0

		# TODO: update instruction pointer

	def set_addr_exit(self, addr, state, guard):
		self.set_expr_exit(addr, state, guard)

	def set_expr_exit(self, expr, state, guard):
		self.raw_state = state
		self.target = expr
		self.jumpkind = "Ijk_Boring"
		self.guard = guard if guard is not None else state.se.BoolVal(True)

	# Tries a constraint check to see if this exit is reachable.
	@ondemand
	def reachable(self):
		l.debug("Checking reachability of %s.", self.state)
		return self.state.satisfiable()

	@ondemand
	def is_unique(self):
		# TODO: REMOVE THIS GIANT HACK
		if type(self.target._obj) is claripy.BVV: return True
		return self.state.se.unique(self.target)

	@ondemand
	def concretize(self):
		if self.jumpkind.startswith("Ijk_Sys"):
			return -1

		if not self.is_unique():
			raise SimValueError("Exit is not single-valued!")

		# TODO: REMOVE THIS GIANT HACK
		if type(self.target._obj) is claripy.BVV: return self.target._obj.value

		return self.state.se.any_int(self.target)

	# Copies the exit (also copying the state).
	def copy(self):
		return SimExit(expr=self.target, state=self.state.copy(), jumpkind=self.jumpkind, guard=self.guard, simplify=False, state_is_raw=False)

	# Splits a multi-valued exit into multiple exits.
	def split(self, maximum=maximum_exit_split):
		exits = [ ]

		possible_values = self.state.se.any_n(self.target, maximum + 1)
		if len(possible_values) > maximum:
			l.warning("SimExit.split() received over %d values. Likely unconstrained, so returning [].", maximum)
			possible_values = [ ]

		for p in possible_values:
			l.debug("Splitting off exit with address 0x%x", p)
			new_state = self.state.copy()
			if new_state.se.symbolic(self.target):
				new_state.add_constraints(self.target == p)
			exits.append(SimExit(addr=p, state=new_state, jumpkind=self.jumpkind, guard=self.guard, simplify=False, state_is_raw=False))

		return exits

from .s_irsb import SimIRSB
from .s_inspect import BP_BEFORE
from .s_exception import SimValueError
import simuvex.s_options as o
