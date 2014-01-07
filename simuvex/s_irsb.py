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
from .s_ref import SimCodeRef, RefTypes

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SimIRSBError(s_exception.SimError):
	pass

sirsb_count = itertools.count()

analysis_options = { }
all_options = set((o.DO_PUTS, o.DO_LOADS, o.TMP_REFS, o.REGISTER_REFS, o.MEMORY_REFS, o.SIMPLIFY_CONSTANTS))
analysis_options['symbolic'] = all_options | set((o.DO_STORES, o.SYMBOLIC, o.TRACK_CONSTRAINTS))
analysis_options['concrete'] = all_options | set((o.DO_STORES, o.MEMORY_MAPPED_REFS, o.SINGLE_EXIT))
analysis_options['static'] = all_options | set((o.MEMORY_MAPPED_REFS,))

class SimIRSB:
	# Simbolically parses a basic block.
	#
	#	irsb - the pyvex IRSB to parse
	#	initial_state - the symbolic state at the beginning of the block
	#	id - the ID of the basic block
	#	ethereal - whether the basic block is a made-up one (ie, for an emulated ret)
	#	mode - selects a default set of options, depending on the mode
	#	options - a set of options governing the analysis. At the moment, most of them only affect concrete analysis. They can be:
	#
	#		"concrete" - carry out a concrete analysis
	#		"symbolic" - carry out a symbolic analysis
	#
	#		o.DO_PUTS - update the state with the results of put operations
	#		o.DO_STORES - update the state with the results of store operations
	#		o.DO_LOADS - carry out load operations
	#		o.DO_OPS - execute arithmetic UnOps, BinOps, TriOps, QOps
	#		"determine_exits" - determine which exits will be taken
	#		"conditions" - evaluate conditions (for the Mux0X and CAS multiplexing instructions)
	#		o.DO_CCALLS - evaluate ccalls
	#		"memory_refs" - check if expressions point to allocated memory
	def __init__(self, irsb, initial_state, irsb_id=None, ethereal=False, mode="symbolic", options=None):
		if irsb.size() == 0:
			raise SimIRSBError("Empty IRSB passed to SimIRSB.")

		# the options and mode
		if options is None:
			options = analysis_options[mode]
		self.options = options

		# set up the irsb
		self.irsb = irsb
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		self.last_imark = self.first_imark
		self.statements = [ ]
		self.id = irsb_id if irsb_id is not None else "%x" % self.first_imark.addr
		l.debug("Entering block %s with %d constraints." % (self.id, len(initial_state.constraints_after())))

		# these are the code and data references
		self.refs = { }
		for t in RefTypes:
			self.refs[t] = [ ]

		# prepare the initial state
		self.initial_state = initial_state
		self.initial_state.id = self.id
		self.prepare_temps(initial_state)
		if not ethereal: self.initial_state.block_path.append(self.first_imark.addr)

		# start off the final state
		self.final_state = self.initial_state.copy_after()

		# translate the statements
		self.conditional_exits = [ ]
		try:
			self.handle_statements()
		except s_exception.SimError:
			l.warning("A SimError was hit when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", exc_info=True)

		# some finalization
		self.final_state.inplace_after()
		self.num_stmts = len(self.irsb.statements())
		self.next_expr = None

		# If there was an error, and not all the statements were processed,
		# then this block does not have a default exit. This can happen if
		# the block has an unavoidable "conditional" exit or if there's a legitimate
		# error in the simulation
		self.default_exit = None
		self.postcall_exit = None
		if len(self.statements) == self.num_stmts:
			self.next_expr = SimIRExpr(self.irsb.next, self.last_imark, self.num_stmts, self.final_state, self.options)
			self.final_state.add_constraints(*self.next_expr.constraints)
			self.final_state.inplace_after()

			if self.next_expr.expr is not None:
				# TODO: in static mode, we probably only want to count one
				# 	code ref even when multiple exits are going to the same
				#	place.
				self.refs[SimCodeRef].append(SimCodeRef(self.last_imark.addr, self.num_stmts, self.next_expr.sim_value, self.next_expr.reg_deps(), self.next_expr.tmp_deps()))

				# the default exit
				self.default_exit = s_exit.SimExit(sirsb_exit = self)

			# ret emulation
			if o.DO_RET_EMULATION in self.options and self.irsb.jumpkind == "Ijk_Call":
				self.postcall_exit = s_exit.SimExit(sirsb_postcall = self, static = (o.SYMBOLIC not in self.options))
		else:
			l.debug("SimIRSB %s has no default exit", self.id)

		l.debug("%d constraints at end of SimIRSB %s"%(len(self.final_state.old_constraints), self.id))


	# Categorize and add a sequence of refs to this IRSB
	def add_refs(self, refs):
		for r in refs:
			self.refs[type(r)].append(r)

	# return the exits from the IRSB
	def exits(self):
		l.debug("Returning exits of IRSB at 0x%x." % self.first_imark.addr)

		exits = [ c for c in self.conditional_exits ]
		if self.default_exit is not None:
			exits.append(self.default_exit)
		if self.postcall_exit is not None:
			exits.append(self.postcall_exit)

		returned_exits = [ e for e in exits if (o.SYMBOLIC in self.options or not e.sim_value.is_symbolic()) ]
		l.debug("Returning %d of %d exits.", len(returned_exits), len(exits))
		return returned_exits

	# This function receives an initial state and imark and processes a list of pyvex.IRStmts
	# It returns a final state, last imark, and a list of SimIRStmts
	def handle_statements(self):
		# Translate all statements until something errors out
		for stmt_idx, stmt in enumerate(self.irsb.statements()):
			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: 0x%x" % stmt.addr)
				self.last_imark = stmt
	
			# process it!
			s_stmt = s_irstmt.SimIRStmt(stmt, self.last_imark, stmt_idx, self.final_state, self.options)
			self.add_refs(s_stmt.refs)
			self.statements.append(s_stmt)
		
			# for the exits, put *not* taking the exit on the list of constraints so
			# that we can continue on. Otherwise, add the constraints
			if type(stmt) == pyvex.IRStmt.Exit:
				e = s_exit.SimExit(sexit = s_stmt, stmt_index = stmt_idx)
				self.conditional_exits.append(e)

				if o.SINGLE_EXIT in self.options and s_stmt.exit_taken:
					l.debug("Returning after taken exit due to SINGLE_EXIT option.")
					return
				if o.SYMBOLIC in self.options:
					self.final_state.inplace_avoid()
			else:
				self.final_state.inplace_after()

	def prepare_temps(self, state):
		# prepare symbolic variables for the statements
		state.temps = { }
		sirsb_num = sirsb_count.next()
		for n, t in enumerate(self.irsb.tyenv.types()):
			state.temps[n] = symexec.BitVec('%s_%d_t%d' % (state.id, sirsb_num, n), s_helpers.get_size(t))
		# prepare symbolic variables for the statements
		state.temps = { }
		sirsb_num = sirsb_count.next()
		for n, t in enumerate(self.irsb.tyenv.types()):
			state.temps[n] = symexec.BitVec('%s_%d_t%d' % (state.id, sirsb_num, n), s_helpers.get_size(t))

	# This is here to (hopefully) address strange z3 issues.
	def __del__(self):
		l.debug("Deleting statements.")
		del self.statements

		l.debug("Deleting initial state.")
		del self.initial_state

		l.debug("Deleting final state.")
		del self.final_state

		l.debug("Deleting next_expr.")
		del self.next_expr

		l.debug("Deleting refs.")
		del self.refs

		l.debug("All done with deletion!")
