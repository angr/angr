#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import z3
import pyvex
import s_irstmt
import s_irexpr
import s_helpers
import s_memory
import s_value

import logging
l = logging.getLogger("s_irsb")
#l.setLevel(logging.DEBUG)

class SymbolicExit:
	def __init__(self, s_target, registers, memory, constraints, after_ret = None):
		self.s_target = s_target
		self.constraints = constraints
		self.after_ret = after_ret
		self.registers = registers
		self.memory = memory

	def concretize(self):
		cval = s_value.Value(self.s_target, self.constraints)
		if cval.min != cval.max:
			raise s_value.ConcretizingException("Exit has multiple values between %x and %x" % (cval.min, cval.max))
		return cval.min

class SymbolicIRSB:
	def __init__(self, irsb=None, base=None, bytes=None, byte_start=None, memory=None, registers=None, constraints=None, id=None):
		# make sure we have an IRSB to work with
		self.irsb = irsb
		if self.irsb == None:
			if base is None or bytes is None or byte_start is None:
				raise Exception("Neither an IRSB nor base/bytes/bytes_start to translate were provided.")

			self.irsb = pyvex.IRSB(bytes = bytes[byte_start:], mem_addr = base + byte_start)
			if self.irsb.size() == 0:
				raise pyvex.VexException("Got empty IRSB at start address %x, byte offset %x." % (base + byte_start, byte_start))
		
		# get the parameters
		self.temps = { }
		self.registers = { }
                self.memory = s_memory.Memory(memory)
		self.constraints = [ ]
		self.id = id

		if memory:
			self.memory = memory

		if registers:
			self.registers = registers

		if constraints:
			self.constraints = constraints

		if self.id is None:
			self.id = "%x" % ([ i for i in self.irsb.statements() if type(i) == pyvex.IRStmt.IMark ][0].addr)

		self.irsb.pp()

		# Now translate!

		# first, prepare symbolic variables for the statements
		for n, t in enumerate(self.irsb.tyenv.types()):
			self.temps[n] = z3.BitVec('%s_t%d' % (self.id, n), s_helpers.get_size(t))
	
		# now get the constraints
		self.last_imark = [ i for i in self.irsb.statements() if type(i) == pyvex.IRStmt.IMark ][0] #start at first imark
		self.s_statements = [ ]
		for stmt in self.irsb.statements():
			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: %x" % stmt.addr)
				self.last_imark = stmt

			# pass ourselves (temps and memory, registers, and constraints thus far)
			s_stmt = s_irstmt.SymbolicIRStmt(stmt, self.last_imark, self)
			self.s_statements.append(s_stmt)
	
			# for the exits, put *not* taking the exit on the list of constraints so
			# that we can continue on. Otherwise, add the constraints
			if type(stmt) == pyvex.IRStmt.Exit:
				self.constraints = s_stmt.past_constraints + [ z3.Not(z3.And(*s_stmt.new_constraints)) ]
			else:
				self.constraints = s_stmt.past_constraints + s_stmt.new_constraints

			# update our registers and memory
			self.registers = s_stmt.registers
			self.memory = s_stmt.memory

	# return the exits from the IRSB
	def exits(self):
		exits = [ ]
		for e in [ s for s in self.s_statements if type(s.stmt) == pyvex.IRStmt.Exit ]:
			after_ret = None
			if e.stmt.jumpkind == "Ijk_Call":
				after_ret = e.imark.addr + e.imark.len

			s_target = s_helpers.translate_irconst(e.stmt.dst)
			constraints = e.past_constraints + e.new_constraints
			exits.append(SymbolicExit(s_target, e.registers, e.memory, constraints, after_ret))

		# and add the default one
		after_ret = None
		if self.irsb.jumpkind == "Ijk_Call":
			after_ret = self.last_imark.addr + self.last_imark.len
		s_target, s_constraints = s_irexpr.translate(self.irsb.next, self)
		exits.append(SymbolicExit(s_target, self.registers, self.memory, self.constraints + s_constraints, after_ret))

		return exits
