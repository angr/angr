#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import itertools

import symexec
import pyvex
import s_irstmt
import s_helpers
import s_exit
import s_exception
from .s_irexpr import SimIRExpr
from .s_ref import SimCodeRef, RefTypes

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SimIRSBError(s_exception.SimError):
	pass

sirsb_count = itertools.count()

analysis_options = { }
analysis_options['symbolic'] = set(("puts", "stores", "loads", "ops", "conditions", "ccalls", "symbolic"))
analysis_options['concrete'] = set(("puts", "stores", "loads", "ops", "determine_exits", "conditions", "ccalls", "memory_refs", "concrete"))
analysis_options['static'] = set(("puts", "loads", "ops", "memory_refs", "concrete"))

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
	#		"puts" - update the state with the results of put operations
	#		"stores" - update the state with the results of store operations
	#		"loads" - carry out load operations
	#		"ops" - execute arithmetic UnOps, BinOps, TriOps, QOps
	#		"determine_exits" - determine which exits will be taken
	#		"conditions" - evaluate conditions (for the Mux0X and CAS multiplexing instructions)
	#		"ccalls" - evaluate ccalls
	#		"memory_refs" - check if expressions point to allocated memory
	def __init__(self, irsb, initial_state, irsb_id=None, ethereal=False, mode="symbolic", options=None):
		if irsb.size() == 0:
			raise SimIRSBError("Empty IRSB passed to SimIRSB.")

		l.debug("Entering block %s with %d constraints." % (irsb_id, len(initial_state.constraints_after())))

		# the options and mode
		if options is None:
			options = analysis_options[mode]
			if mode == "static": mode = "concrete"
		self.options = options

		# set up the irsb
		self.irsb = irsb
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		self.last_imark = self.first_imark
		self.statements = [ ]

		# these are the code and data references
		self.refs = { }
		for t in RefTypes:
			self.refs[t] = [ ]

		# prepare the initial state
		self.initial_state = initial_state
		self.initial_state.id = irsb_id if irsb_id is not None else "%x" % self.first_imark.addr
		self.prepare_temps(initial_state)
		if not ethereal: self.initial_state.block_path.append(self.first_imark.addr)

		# start off the final state
		self.final_state = self.initial_state.copy_after()

		# translate the statements
		try:
			self.handle_statements()
		except s_exception.SimError:
			l.warning("A SimError was hit when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", exc_info=True)
	
		# If there was an error, and not all the statements were processed,
		# then this block does not have a default exit. This can happen if
		# the block has an unavoidable "conditional" exit or if there's a legitimate
		# error in the simulation
		self.has_normal_exit = len(self.statements) == len(self.irsb.statements())

		# final state
		l.debug("%d constraints at end of SimIRSB %s"%(len(self.final_state.old_constraints), self.final_state.id))

		self.num_stmts = len(self.irsb.statements())
		e = SimIRExpr(self.irsb.next, self.last_imark, self.num_stmts, self.final_state, self.options)
		if "symbolic" in self.options or not e.sim_value.is_symbolic():
			# TODO: in static mode, we probably only want to count one
			# 	code ref even when multiple exits are going to the same
			#	place.
			self.refs[SimCodeRef].append(SimCodeRef(self.last_imark.addr, self.num_stmts, e.sim_value, e.reg_deps(), e.tmp_deps()))

	# Categorize and add a sequence of refs to this IRSB
	def add_refs(self, refs):
		for r in refs:
			self.refs[type(r)].append(r)

	# return the exits from the IRSB
	def exits(self):
		exits = [ ]
		if len(self.irsb.statements()) == 0:
			l.debug("Returning no exits for empty IRSB")
			return [ ]

		l.debug("Generating exits of IRSB at 0x%x." % self.first_imark.addr)

		for s in [ s for s in self.statements if type(s.stmt) == pyvex.IRStmt.Exit ]:
			e = s_exit.SimExit(sexit = s, stmt_index = self.statements.index(s))
			if "determine_exits" in self.options and not s.concrete_exit_taken:
				l.debug("Skipping untaken exit due to 'determine_exits' option.")
				continue
			if "concrete" in self.options and e.simvalue.is_symbolic():
				l.debug("Skipping symbolic exit in concrete mode.")
				continue
			exits.append(e)

		# and add the default one
		if self.has_normal_exit and not ("determine_exits" in self.options and len(exits) > 0):
			e = s_exit.SimExit(sirsb_exit = self)
			if "concrete" not in self.options or not e.simvalue.is_symbolic():
				l.debug("Adding default exit")
				exits.append(e)
			elif "concrete" in self.options:
				l.debug("Skipping symbolic default exit.")

			if "determine_exits" not in self.options and self.irsb.jumpkind == "Ijk_Call":
				e = s_exit.SimExit(sirsb_postcall = self, static = ('concrete' in self.options))
				if "concrete" not in self.options or not e.simvalue.is_symbolic():
					l.debug("Adding post-call")
					exits.append(e)
		else:
			l.debug("... no default exit")

		l.debug("Generated %d exits for 0x%x" % (len(exits), self.first_imark.addr))
		return exits

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
		
			if "symbolic" in self.options:
				# for the exits, put *not* taking the exit on the list of constraints so
				# that we can continue on. Otherwise, add the constraints
				if type(stmt) == pyvex.IRStmt.Exit:
					self.final_state = self.final_state.copy_avoid()
				else:
					self.final_state = self.final_state.copy_after()

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
