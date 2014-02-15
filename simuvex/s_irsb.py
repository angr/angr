#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

# because pylint can't load pyvex
# pylint: disable=F0401

import itertools

import symexec
import pyvex
import s_irstmt
import s_helpers
import s_exit
import s_exception
import s_options as o
from .s_irexpr import SimIRExpr
from .s_ref import SimCodeRef
from .s_run import SimRun

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
		  mode - selects a default set of options, depending on the mode
		  options - a set of options governing the analysis. At the moment, most of them only affect concrete analysis. They can be:
	
			"concrete" - carry out a concrete analysis
			"symbolic" - carry out a symbolic analysis
	
			o.DO_PUTS - update the state with the results of put operations
			o.DO_STORES - update the state with the results of store operations
			o.DO_LOADS - carry out load operations
			o.DO_OPS - execute arithmetic UnOps, BinOps, TriOps, QOps
			"determine_exits" - determine which exits will be taken
			"conditions" - evaluate conditions (for the ITE and CAS multiplexing instructions)
			o.DO_CCALLS - evaluate ccalls
			"memory_refs" - check if expressions point to allocated memory
	'''

	'''
		The attribute "index" is used by angr.cdg
	'''
	__slots__ = [ 'irsb', 'first_imark', 'last_imark', 'addr', 'id', 'whitelist', 'last_stmt', 'has_default_exit', 'num_stmts', 'next_expr', 'statements', 'conditional_exits', 'default_exit', 'postcall_exit', 'index' ]

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
		self.has_default_exit = False

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
		fmt = "<SimIRSB at 0x%%0%dx>" % (self.initial_state.arch.bits/4)
		return fmt % self.addr

	def _handle_irsb(self):
		if o.BREAK_SIRSB_START in self.options:
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
		if self.has_default_exit:
			self.next_expr = SimIRExpr(self.irsb.next, self.last_imark, self.num_stmts, self.state, self.options)
			self.state.add_constraints(*self.next_expr.constraints)
			self.state.inplace_after()

			self.add_refs(*self.next_expr.refs)

			# TODO: in static mode, we probably only want to count one
			#	code ref even when multiple exits are going to the same
			#	place.
			self.add_refs(SimCodeRef(self.last_imark.addr, self.num_stmts, self.next_expr.sim_value, self.next_expr.reg_deps(), self.next_expr.tmp_deps()))

			# the default exit
			self.default_exit = s_exit.SimExit(sirsb_exit = self)
			l.debug("%s adding default exit.", self)
			self.add_exits(self.default_exit)

			# ret emulation
			if o.DO_RET_EMULATION in self.options and self.irsb.jumpkind == "Ijk_Call":
				self.postcall_exit = s_exit.SimExit(sirsb_postcall = self, simple_postcall = (o.SYMBOLIC not in self.options))
				l.debug("%s adding postcall exit.", self)
				self.add_exits(self.postcall_exit)
		else:
			l.debug("%s has no default exit", self)

		if o.BREAK_SIRSB_END in self.options:
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

			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: 0x%x" % stmt.addr)
				self.last_imark = stmt

			if self.whitelist is not None and stmt_idx not in self.whitelist:
				l.debug("%s skipping %s (index %d of max %s)", self, stmt.__class__.__name__, stmt_idx, self.last_stmt)
				continue
			elif self.whitelist is not None:
				l.debug("%s analyzing stmt with index %d (max %s)!", self, stmt_idx, self.last_stmt)

			# process it!
			s_stmt = s_irstmt.SimIRStmt(stmt, self.last_imark, stmt_idx, self.state, self.options)
			self.add_refs(*s_stmt.refs)
			self.statements.append(s_stmt)

			# for the exits, put *not* taking the exit on the list of constraints so
			# that we can continue on. Otherwise, add the constraints
			if type(stmt) == pyvex.IRStmt.Exit:
				e = s_exit.SimExit(sexit = s_stmt, stmt_index = stmt_idx)

				# if we're tracking all exits, add it. Otherwise, only add (and stop analysis) if
				# we found an exit that is taken
				# TODO: move this functionality to SimRun
				if o.TAKEN_EXIT not in self.options:
					l.debug("%s adding conditional exit", self)
					self.conditional_exits.append(e)
					self.add_exits(e)
				elif o.TAKEN_EXIT in self.options and s_stmt.exit_taken:
					l.debug("%s returning after taken exit due to TAKEN_EXIT option.", self)
					self.conditional_exits.append(e)
					self.add_exits(e)
					return
				else:
					l.debug("%s not adding conditional exit because the condition is false", self)

				if o.TRACK_CONSTRAINTS in self.options:
					self.state.inplace_avoid()
			else:
				if o.TRACK_CONSTRAINTS in self.options:
					self.state.inplace_after()

		if self.last_stmt is None:
			self.has_default_exit = True
		else:
			self.has_default_exit = False

	def _prepare_temps(self, state):
		state.temps = { }

		# prepare symbolic variables for the statements if we're using SYMBOLIC_TEMPS
		if o.SYMBOLIC_TEMPS in self.options:
			sirsb_num = sirsb_count.next()
			for n, t in enumerate(self.irsb.tyenv.types()):
				state.temps[n] = symexec.BitVec('temp_%s_%d_t%d' % (self.id, sirsb_num, n), s_helpers.get_size(t)*8)
			l.debug("%s prepared %d symbolic temps.", len(state.temps), self)

	# Returns a list of instructions that are part of this block.
	def imark_addrs(self):
		return [ i.addr for i in self.irsb.statements() if type(i) == pyvex.IRStmt.IMark ]

	def reanalyze(self, new_state, mode=None, options=None, irsb_id=None, whitelist=None):
		mode = self.mode if mode is None else mode
		options = self.options if options is None else options
		irsb_id = self.id if irsb_id is None else irsb_id
		whitelist = self.whitelist if whitelist is None else whitelist

		return SimIRSB(new_state, self.irsb, mode=mode, options=options, irsb_id=irsb_id, whitelist=whitelist)
