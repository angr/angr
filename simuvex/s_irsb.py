#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import z3
import pyvex
import s_irstmt
import s_helpers
import s_exit
import s_exception

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SimIRSBError(s_exception.SimError):
	pass

sirsb_count = 0

class SimIRSB:
	# Simbolically parses a basic block.
	#
	#	irsb - the pyvex IRSB to parse
	#	initial_state - the symbolic state at the beginning of the block
	#	id - the ID of the basic block
	#	ethereal - whether the basic block is a made-up one (ie, for an emulated ret)
	def __init__(self, irsb, initial_state, id=None, ethereal=False):
		global sirsb_count

		if irsb.size() == 0:
			raise SimIRSBError("Empty IRSB passed to SimIRSB.")

		self.irsb = irsb
		l.debug("Entering block %s with %d constraints." % (id, len(initial_state.constraints_after())))

		# set the ID and copy the initial state
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		state = initial_state
		if not ethereal:
			state.block_path.append(self.first_imark.addr)

		if id is None:
			state.id = "%x" % self.first_imark.addr
		else:
			state.id = id
		self.initial_state = initial_state.copy_after()

		#l.debug("Blockstack is now: %s" % " ".join(["%x" % x for x in self.initial_state.block_path ]))

		#
		# Now translate!
		#

		# first, prepare symbolic variables for the statements
		state.temps = { }
		for n, t in enumerate(self.irsb.tyenv.types()):
			state.temps[n] = z3.BitVec('%s_%d_t%d' % (state.id, sirsb_count, n), s_helpers.get_size(t))
		sirsb_count += 1
	
		# now get the constraints
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		state, self.last_imark, self.s_statements = s_irstmt.handle_statements(state, self.first_imark, self.irsb.statements())

		# If there was an error, and not all the statements were processed,
		# then this block does not have a default exit. This can happen if
		# the block has an unavoidable "conditional" exit or if there's a legitimate
		# error in the simulation
		self.has_normal_exit = len(self.s_statements) == len(self.irsb.statements())

		# final state
		l.debug("%d constraints at end of SimIRSB %s"%(len(state.old_constraints),state.id))
		self.final_state = state

	# return the exits from the IRSB
	def exits(self):
		exits = [ ]
		if len(self.irsb.statements()) == 0:
			l.debug("Returning no exits for empty IRSB")
			return [ ]

		l.debug("Generating exits of IRSB at 0x%x." % self.last_imark.addr)

		for e in [ s for s in self.s_statements if type(s.stmt) == pyvex.IRStmt.Exit ]:
			exits.append(s_exit.SimExit(sexit = e, stmt_index = self.s_statements.index(e)))
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
