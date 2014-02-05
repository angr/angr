#!/usr/bin/env python
'''This module handles exits from IRSBs.'''

import symexec
import s_value
import s_helpers
import s_irsb

import logging
l = logging.getLogger("s_exit")

maximum_exit_split = 255

class SimExit:
	def __init__(self, sirsb_exit = None, sirsb_postcall = None, sexit = None, src_addr=None, stmt_index = None, addr=None, expr=None, state=None, jumpkind=None, simple_postcall=True, simplify=True):
		# Address of the instruction that performs this exit
		self.src_addr = src_addr
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
			self.set_postcall(sirsb_postcall, simple_postcall)
		elif sexit is not None:
			self.set_stmt_exit(sexit)
		elif addr is not None and state is not None:
			self.set_addr_exit(addr, state)
		elif expr is not None and state is not None:
			self.set_expr_exit(expr, state)
		else:
			raise Exception("Invalid SimExit creation.")

		if jumpkind is not None:
			self.jumpkind = jumpkind

		# simplify constraints to speed this up
		if simplify:
			self.state.simplify()

		# the sim_value to use
		self.sim_value = s_value.SimValue(self.target, self.state.constraints_after())

		if self.sim_value.is_symbolic():
			l.debug("Made exit to symbolic expression.")
		else:
			l.debug("Made exit to address 0x%x.", self.sim_value.any())


	def set_postcall(self, sirsb_postcall, simple_postcall):
		l.debug("Making entry to post-call of IRSB.")

		if simple_postcall:
			self.state = sirsb_postcall.state.copy_after()
			self.target = symexec.BitVecVal(sirsb_postcall.last_imark.addr + sirsb_postcall.last_imark.len, sirsb_postcall.state.arch.bits)
			self.jumpkind = "Ijk_Ret"
			# TODO: is this correct?
			self.src_addr = sirsb_postcall.last_imark.addr
			self.src_stmt_index = len(sirsb_postcall.irsb.statements()) - 1
		else:
			# first emulate the ret
			exit_state = sirsb_postcall.state.copy_after()
			ret_irsb = exit_state.arch.get_ret_irsb(sirsb_postcall.last_imark.addr)
			ret_sirsb = s_irsb.SimIRSB(exit_state, ret_irsb)
			ret_exit = ret_sirsb.exits()[0]

			self.target = ret_exit.target
			self.jumpkind = ret_exit.jumpkind
			self.state = ret_exit.state
			self.src_stmt_index = ret_exit.src_stmt_index
			self.src_addr = ret_exit.src_addr

	def set_irsb_exit(self, sirsb_exit):
		self.state = sirsb_exit.state.copy_after()
		self.target = sirsb_exit.next_expr.expr

		self.jumpkind = sirsb_exit.irsb.jumpkind
		self.src_addr = sirsb_exit.last_imark.addr
		self.src_stmt_index = len(sirsb_exit.irsb.statements()) - 1

	def set_stmt_exit(self, sexit):
		self.state = sexit.state.copy_after()
		self.target = s_helpers.translate_irconst(sexit.stmt.dst)
		self.jumpkind = sexit.stmt.jumpkind
		self.src_addr = sexit.stmt.offsIP

	def set_addr_exit(self, addr, state):
		self.set_expr_exit(symexec.BitVecVal(addr, state.arch.bits), state)

	def set_expr_exit(self, expr, state):
		self.state = state.copy_after()
		self.target = expr
		self.jumpkind = "Ijk_Boring"

	# Tries a constraint check to see if this exit is reachable.
	@s_helpers.ondemand
	def reachable(self):
		l.debug("Checking reachability with %d constraints" % len(self.state.constraints_after()))
		return self.sim_value.satisfiable()

	@s_helpers.ondemand
	def concretize(self):
		if self.jumpkind.startswith("Ijk_Sys"):
			return -1

		if not self.reachable():
			raise s_value.ConcretizingException("Exit is not reachable/satisfiable")

		if not self.is_unique():
			raise s_value.ConcretizingException("Exit has multiple values")

		return self.sim_value.any()

	@s_helpers.ondemand
	def is_unique(self):
		return self.sim_value.is_unique()

	# Copies the exit (also copying the state).
	def copy(self):
		return SimExit(expr=self.target, state=self.state.copy_exact(), src_addr=self.src_addr, stmt_index=self.src_stmt_index, jumpkind=self.jumpkind, simplify=False)

	# Splits a multi-valued exit into multiple exits.
	def split(self, maximum=maximum_exit_split):
		exits = [ ]

		possible_values = self.sim_value.any_n(maximum + 1)
		if len(possible_values) > maximum:
			l.warning("SimExit.split() received over %d values. Choosing the first one (0x%x)", maximum, possible_values[0])
			possible_values = possible_values[:1]

		for p in possible_values:
			l.debug("Splitting off exit with address 0x%x", p)
			new_state = self.state.copy_exact()
			new_state.add_constraints(self.target == p)
			exits.append(SimExit(addr=p, state=new_state, src_addr=self.src_addr, stmt_index=self.src_stmt_index, jumpkind=self.jumpkind, simplify=False))

		return exits
