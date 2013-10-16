#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import z3
import pyvex
import s_irstmt
import s_helpers
import s_exit

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SymbolicIRSB:
	def __init__(self, irsb=None, base=None, bytes=None, byte_start=None, initial_state=None, id=None, arch = "VexArchAMD64"):
		# TODO: turn this into a general platform-specific extension
		if arch == "VexArchAMD64":
			self.bits = 64
		elif arch == "VexArchARM":
			self.bits = 32
		#etc

		#####################
		### IRSB creation ###
		#####################
		self.irsb = irsb
		if self.irsb == None:
			if base is None or bytes is None or byte_start is None:
				raise Exception("Neither an IRSB nor base/bytes/bytes_start to translate were provided.")

			self.irsb = pyvex.IRSB(bytes = bytes[byte_start:], mem_addr = base + byte_start, arch = arch)

		if self.irsb.size() == 0:
			l.warning("Got empty IRSB at start address %x, byte offset %x." % (base + byte_start, byte_start))
			return

		# set the ID and copy the initial state
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		state = initial_state
		if id is None:
			state.id = "%x" % self.first_imark.addr
		else:
			state.id = id
		self.initial_state = initial_state.copy_after()

		self.irsb.pp()

		#
		# Now translate!
		#

		# first, prepare symbolic variables for the statements
		state.temps = { }
		for n, t in enumerate(self.irsb.tyenv.types()):
			state.temps[n] = z3.BitVec('%s_t%d' % (state.id, n), s_helpers.get_size(t))
	
		# now get the constraints
		self.first_imark = [i for i in self.irsb.statements() if type(i)==pyvex.IRStmt.IMark][0]
		state, self.last_imark, self.s_statements = s_irstmt.handle_statements(state, self.first_imark, self.irsb.statements())

		# final state
		l.debug("%d constraints at end of SymbolicIRSB %s"%(len(state.old_constraints),state.id))
		self.final_state = state

	# return the exits from the IRSB
	def exits(self):
		exits = [ ]
		if len(self.irsb.statements()) == 0:
			l.debug("Returning no exits for empty IRSB")
			return [ ]

		l.debug("Generating exits.")

		for e in [ s for s in self.s_statements if type(s.stmt) == pyvex.IRStmt.Exit ]:
			exits.append(s_exit.SymbolicExit(sexit = e, stmt_index = self.s_statements.index(e)))
			if e.stmt.jumpkind == "Ijk_Call":
				raise Exception("Good job, you caught this exception! This was placed here by Yan to find out if this case is possible. Please tell Yan that it is and then remove this line. Apologies for the inconvenience!")
				exits.append(s_exit.SymbolicExit(sexit_postcall = e, stmt_index = self.s_statements.index(e)))

		# and add the default one
		exits.append(s_exit.SymbolicExit(sirsb_exit = self))
		if self.irsb.jumpkind == "Ijk_Call":
			exits.append(s_exit.SymbolicExit(sirsb_postcall = self))

		l.debug("Generated %d exits" % len(exits))
		return exits
