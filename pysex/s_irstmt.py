#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import s_exit
import s_irexpr

import logging
l = logging.getLogger("s_irstmt")

class SymbolicIRStmt:
	def __init__(self, stmt, imark, state):
		self.stmt = stmt
		self.imark = imark

		self.state = state
		self.state.id = "%x" % imark.addr

		func_name = "handle_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s" % type(stmt))			
			getattr(self, func_name)(stmt)
		else:
			raise Exception("Unsupported statement type %s." % type(stmt))

	##########################
	### Statement handlers ###
	##########################
	def handle_NoOp(self, stmt):
		pass
	
	def handle_IMark(self, stmt):
		pass
	
	def handle_WrTmp(self, stmt):
		t = self.state.temps[stmt.tmp]
		d, expr_constraints = s_irexpr.translate(stmt.data, self.state)

		self.state.add_constraints(t == d)
		self.state.add_constraints(*expr_constraints)
	
	def handle_Put(self, stmt):
		if stmt.offset not in self.state.registers:
			self.state.registers[stmt.offset] = [ ]
	
		reg_val, data_constraints = s_irexpr.translate(stmt.data, self.state)
		reg_id = len(self.state.registers[stmt.offset])
		reg = z3.BitVec("%s_reg_%d_%d" % (self.state.id, stmt.offset, reg_id), reg_val.size())

		self.state.registers[stmt.offset].append(reg)
		self.state.add_constraints(reg == reg_val)
		self.state.add_constraints(*data_constraints)
	
	def handle_Store(self, stmt):
		# first resolve the address
		addr, addr_constraints = s_irexpr.translate(stmt.addr, self.state)
		self.state.add_constraints(*addr_constraints)

		# now get the value
		val, val_constraints = s_irexpr.translate(stmt.data, self.state)
		self.state.add_constraints(*val_constraints)

		store_constraints = self.state.memory.store(addr, val, self.state.old_constraints)
		self.state.add_constraints(*store_constraints)

	def handle_Exit(self, stmt):
		# TODO: add a constraint for the IP being updated, which is implicit in the Exit instruction
		# exit_put = pyvex.IRStmt.Put(stmt.offsIP, stmt.dst)
		# put_constraint += s_irstmt.translate(exit_put, self)

		# TODO: make sure calls push a return address (in case valgrind does it implicitly)
		guard_expr, guard_constraints = s_irexpr.translate(stmt.guard, self.state)
		self.state.add_branch_constraints(guard_expr != 0)
		self.state.add_constraints(*guard_constraints)
	
	def handle_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass
