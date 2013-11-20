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

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SimIRSBError(s_exception.SimError):
	pass

sirsb_count = itertools.count()

class SimIRSB:
	# Simbolically parses a basic block.
	#
	#	irsb - the pyvex IRSB to parse
	#	initial_state - the symbolic state at the beginning of the block
	#	id - the ID of the basic block
	#	ethereal - whether the basic block is a made-up one (ie, for an emulated ret)
	def __init__(self, irsb, initial_state, id=None, ethereal=False, mode="symbolic"):
		if irsb.size() == 0:
			raise SimIRSBError("Empty IRSB passed to SimIRSB.")

		l.debug("Entering block %s with %d constraints." % (id, len(initial_state.constraints_after())))

		# set up the irsb
		self.mode = mode
		self.irsb = irsb
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		self.last_imark = self.first_imark
		self.statements = [ ]

		# these are the code and data references
		self.code_refs = [ ]
		self.data_reads = [ ]
		self.data_writes = [ ]
		self.memory_refs = [ ]

		# prepare the initial state
		self.initial_state = initial_state
		self.initial_state.id = id if id is not None else "%x" % self.first_imark.addr
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

		exit = SimIRExpr(self.irsb.next, self.final_state, mode=self.mode)
		if self.mode != "static" or not exit.sim_value.is_symbolic():
			self.code_refs.append((self.last_imark.addr, exit.sim_value))

	# return the exits from the IRSB
	def exits(self):
		exits = [ ]
		if len(self.irsb.statements()) == 0:
			l.debug("Returning no exits for empty IRSB")
			return [ ]

		l.debug("Generating exits of IRSB at 0x%x." % self.last_imark.addr)

		for e in [ s for s in self.statements if type(s.stmt) == pyvex.IRStmt.Exit ]:
			exits.append(s_exit.SimExit(sexit = e, stmt_index = self.statements.index(e)))
			if e.stmt.jumpkind == "Ijk_Call":
				raise Exception("Good job, you caught this exception! This was placed here by Yan to find out if this case is possible. Please tell Yan that it is and then remove this line. Apologies for the inconvenience!")

		# and add the default one
		if self.has_normal_exit:
			exits.append(s_exit.SimExit(sirsb_exit = self))
			if self.irsb.jumpkind == "Ijk_Call":
				exits.append(s_exit.SimExit(sirsb_postcall = self))
		else:
			l.debug("... no default exit")

		l.debug("Generated %d exits for 0x%x" % (len(exits), self.last_imark.addr))
		return exits

	# This function receives an initial state and imark and processes a list of pyvex.IRStmts
	# It returns a final state, last imark, and a list of SimIRStmts
	def handle_statements(self):
		# Translate all statements until something errors out
		for stmt in self.irsb.statements():
			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: 0x%x" % stmt.addr)
				self.last_imark = stmt
	
			# process it!
			s_stmt = s_irstmt.SimIRStmt(stmt, self.last_imark, self.final_state, mode=self.mode)

			for r in s_stmt.data_reads:
				self.data_reads.append((self.last_imark.addr,) + r)

			for r in s_stmt.data_writes:
				self.data_writes.append((self.last_imark.addr,) + r)

			for r in s_stmt.code_refs:
				self.code_refs.append((self.last_imark.addr, r))

			for r in s_stmt.memory_refs:
				self.memory_refs.append((self.last_imark.addr, r))

			self.statements.append(s_stmt)
		
			if self.mode != "static":
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
