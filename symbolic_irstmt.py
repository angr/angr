#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import sys
import copy
import pyvex
import symbolic_helpers
import symbolic_irexpr

import logging
l = logging.getLogger("symbolic_irstmt")
#l.setLevel(logging.DEBUG)

class SymbolicIRStmt:
	def __init__(self, stmt, imark, irsb):
		self.stmt = stmt
		self.imark = imark

		# copy out stuff from the irsb
		self.temps = irsb.temps
		self.past_constraints = copy.copy(irsb.constraints)
		self.constraints = self.past_constraints
		self.id = "%x" % imark.addr

		self.registers = { }
		for i in irsb.registers:
			self.registers[i] = copy.copy(irsb.registers[i])

		# TODO: copy-on-write memory
		self.memory = irsb.memory

		func_name = "handle_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s" % type(stmt))
			self.new_constraints = getattr(self, func_name)(stmt)
		else:
			raise Exception("Unsupported statement type %s." % type(stmt))

	##########################
	### Statement handlers ###
	##########################
	def handle_NoOp(self, stmt):
		return [ ]
	
	def handle_IMark(self, stmt):
		return [ ]
	
	def handle_WrTmp(self, stmt):
		t = self.temps[stmt.tmp]
		d = symbolic_irexpr.translate(stmt.data, self)
		l.debug("Temp: %s" % stmt.tmp)
		l.debug("Temp size: %d" % t.size())
		l.debug("Data size: %d" % d.size())
		return [ t == d ]
	
	def handle_Put(self, stmt):
		if stmt.offset not in self.registers:
			self.registers[stmt.offset] = [ ]
	
		reg_val = symbolic_irexpr.translate(stmt.data, self)
		reg_id = len(self.registers[stmt.offset])
		reg = z3.BitVec("%s_reg_%d_%d" % (self.id, stmt.offset, reg_id), reg_val.size())
		self.registers[stmt.offset].append(reg)
	
		return [ reg == reg_val ]
	
	def handle_Store(self, stmt):
		# TODO: symbolic memory
		return [ ]
	
	def handle_Exit(self, stmt):
		# TODO: add a constraint for the IP being updated, which is implicit in the Exit instruction
		# exit_put = pyvex.IRStmt.Put(stmt.offsIP, stmt.dst)
		# put_constraint += symbolic_irstmt.translate(exit_put, self)

		# TODO: make sure calls push a return address (in case valgrind does it implicitly)
		guard_expr = symbolic_irexpr.translate(stmt.guard, self)
		return [ guard_expr != 0 ] # + [ put_constraint ]
	
	def handle_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		return [ ]
