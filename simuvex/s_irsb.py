#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

# because pylint can't load pyvex
# pylint: disable=F0401

import itertools

import symexec as se
import pyvex
import s_irstmt
import s_helpers
import s_exit
import s_exception
import s_options as o
from .s_irexpr import SimIRExpr
from .s_ref import SimCodeRef
from .s_run import SimRun
from . import SimProcedures

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SimIRSBError(s_exception.SimError):
	pass

sirsb_count = itertools.count()

# The initialization magic we play in SimRun requires us to disable these warnings, unfortunately
## pylint: disable=W0231

class SimIRSB(SimRun):
	'''Simbolically parses a basic block.
	
		  irsb - the pyvex IRSB to parse
		  provided_state - the symbolic state at the beginning of the block
		  id - the ID of the basic block
		  whitelist - a whitelist of the statements to execute (default: all)
		  last_stmt - the statement to stop execution at
	'''

	# The attribute "index" is used by angr.cdg
	__slots__ = [ 'irsb', 'first_imark', 'last_imark', 'addr', 'id', 'whitelist', 'last_stmt', 'has_default_exit', 'num_stmts', 'next_expr', 'statements', 'conditional_exits', 'default_exit', 'postcall_exit', 'index', 'default_exit_guard' ]

	def __init__(self, irsb, irsb_id=None, whitelist=None, last_stmt=None):
		if irsb.size() == 0:
			raise SimIRSBError("Empty IRSB passed to SimIRSB.")

		self.irsb = irsb
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		self.last_imark = self.first_imark
		self.addr = self.first_imark.addr
		self.id = "%x" % self.first_imark.addr if irsb_id is None else irsb_id
		self.whitelist = whitelist
		self.last_stmt = last_stmt
		self.default_exit_guard = se.BoolVal(last_stmt is None)

		# this stuff will be filled out during the analysis
		self.num_stmts = 0
		self.next_expr = None
		self.statements = [ ]
		self.conditional_exits = [ ]
		self.default_exit = None
		self.postcall_exit = None

		self._handle_irsb()
		# It's for debugging
		# irsb.pp()
		# if whitelist != None:
		#	print "======== whitelisted statements ========"
		#	pos = 0
		#	for s in self.statements:
		#		print "%d: " % whitelist[pos],
		#		s.stmt.pp()
		#		print ""
		#		pos += 1
		#	print "======== end ========"

	def __repr__(self):
		if self.addr is not None:
			fmt = "<SimIRSB at 0x%%0%dx>" % (self.initial_state.arch.bits/4)
			return fmt % self.addr
		else:
			return "<SimIRSB uninitialized>"

	def _handle_irsb(self):
		if o.BREAK_SIRSB_START in self.state.options:
			import ipdb
			ipdb.set_trace()

		# finish the initial setup
		self._prepare_temps(self.state)

		# handle the statements
		try:
			self._handle_statements()
		except s_exception.SimError:
			l.warning("%s hit a SimError when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", self, exc_info=True)

		# some finalization
		self.state.inplace_after()
		self.num_stmts = len(self.irsb.statements())

		# If there was an error, and not all the statements were processed,
		# then this block does not have a default exit. This can happen if
		# the block has an unavoidable "conditional" exit or if there's a legitimate
		# error in the simulation
		self.default_exit = None
		self.postcall_exit = None
		if len(self.statements) == len(self.irsb.statements()):
			self.next_expr = SimIRExpr(self.irsb.next, self.last_imark, self.num_stmts, self.state)
			self.state.inplace_after()

			self.add_refs(*self.next_expr.refs)

			# TODO: in static mode, we probably only want to count one
			#	code ref even when multiple exits are going to the same
			#	place.
			self.add_refs(SimCodeRef(self.last_imark.addr, self.num_stmts, self.next_expr.sim_value, self.next_expr.reg_deps(), self.next_expr.tmp_deps()))

			# the default exit
			if self.irsb.jumpkind == "Ijk_Call" and o.CALLLESS in self.state.options:
				l.debug("GOIN' CALLLESS!")
				ret = SimProcedures['stubs']['ReturnUnconstrained'](inline=True)
				self.copy_refs(ret)
				self.copy_exits(ret)
			else:
				self.default_exit = s_exit.SimExit(sirsb_exit = self)
				l.debug("%s adding default exit.", self)
				self.add_exits(self.default_exit)

			# ret emulation
			if o.DO_RET_EMULATION in self.state.options and self.irsb.jumpkind == "Ijk_Call":
				self.postcall_exit = s_exit.SimExit(sirsb_postcall = self, simple_postcall = (o.SYMBOLIC not in self.state.options))
				l.debug("%s adding postcall exit.", self)
				self.add_exits(self.postcall_exit)
		else:
			l.debug("%s has no default exit", self)

		if o.BREAK_SIRSB_END in self.state.options:
			import ipdb
			ipdb.set_trace()


	# This function receives an initial state and imark and processes a list of pyvex.IRStmts
	# It returns a final state, last imark, and a list of SimIRStmts
	def _handle_statements(self):
		# Translate all statements until something errors out
		for stmt_idx, stmt in enumerate(self.irsb.statements()):
			if self.last_stmt is not None and stmt_idx > self.last_stmt:
				l.debug("%s stopping analysis at statment %d.", self, self.last_stmt)
				break

			l.debug("%s processing statement %s of max %s", self, stmt.__class__.__name__, stmt_idx, self.last_stmt)

			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: 0x%x" % stmt.addr)
				self.last_imark = stmt

			if self.whitelist is not None and stmt_idx not in self.whitelist:
				l.debug("... whitelist says skip it!")
				continue
			elif self.whitelist is not None:
				l.debug("... whitelist says analyze it!")

			# process it!
			s_stmt = s_irstmt.SimIRStmt(stmt, self.last_imark, stmt_idx, self.state)
			self.add_refs(*s_stmt.refs)
			self.statements.append(s_stmt)

			# for the exits, put *not* taking the exit on the list of constraints so
			# that we can continue on. Otherwise, add the constraints
			if type(stmt) == pyvex.IRStmt.Exit:
				e = s_exit.SimExit(sexit = s_stmt)
				self.default_exit_guard = se.And(self.default_exit_guard, se.Not(e.guard))

				l.debug("%s adding conditional exit", self)
				self.conditional_exits.append(e)
				self.add_exits(e)

				if o.SINGLE_EXIT in self.state.options and not e.guard_value.is_symbolic() and e.guard_value.any() != 0:
					l.debug("%s returning after taken exit due to SINGLE_EXIT option.", self)
					return

			self.state.inplace_after()

	def _prepare_temps(self, state):
		state.temps = { }

		# prepare symbolic variables for the statements if we're using SYMBOLIC_TEMPS
		if o.SYMBOLIC_TEMPS in self.state.options:
			sirsb_num = sirsb_count.next()
			for n, t in enumerate(self.irsb.tyenv.types()):
				state.temps[n] = se.BitVec('temp_%s_%d_t%d' % (self.id, sirsb_num, n), s_helpers.size_bits(t))
			l.debug("%s prepared %d symbolic temps.", len(state.temps), self)

	# Returns a list of instructions that are part of this block.
	def imark_addrs(self):
		return [ i.addr for i in self.irsb.statements() if type(i) == pyvex.IRStmt.IMark ]

	def reanalyze(self, mode=None, new_state=None, irsb_id=None, whitelist=None):
		new_state = self.initial_state.copy_exact() if new_state is None else new_state

		if mode is not None:
			new_state.mode = mode
			new_state.options = set(o.default_options[mode])

		irsb_id = self.id if irsb_id is None else irsb_id
		whitelist = self.whitelist if whitelist is None else whitelist
		return SimIRSB(new_state, self.irsb, irsb_id=irsb_id, whitelist=whitelist)
