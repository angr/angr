#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import pyvex
import s_helpers
from .s_exception import SimError
from .s_value import SimValue
from .s_irexpr import SimIRExpr

import logging
l = logging.getLogger("s_irstmt")

class UnsupportedIRStmtType(Exception):
	pass

class SimIRStmt:
	def __init__(self, stmt, imark, state, mode="symbolic"):
		self.stmt = stmt
		self.imark = imark

		self.mode = mode
		self.state = state
		self.state.id = "%x" % imark.addr

		self.code_refs = [ ]
		self.data_reads = [ ]
		self.data_writes = [ ]

		func_name = mode + "_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s in %s mode" % (type(stmt), mode))
			getattr(self, func_name)(stmt)
		else:
			raise UnsupportedIRStmtType("Unsupported statement type %s in %s mode." % (type(stmt), mode))

	###################################
	### Symbolic statement handlers ###
	###################################
	def symbolic_NoOp(self, stmt):
		pass
	
	def symbolic_IMark(self, stmt):
		pass
	
	def symbolic_WrTmp(self, stmt):
		t = self.state.temps[stmt.tmp]
		d, expr_constraints = SimIRExpr(stmt.data, self.state).expr_and_constraints()

		self.state.add_constraints(t == d)
		self.state.add_constraints(*expr_constraints)
	
	def symbolic_Put(self, stmt):
		# value to put
		data = SimIRExpr(stmt.data, self.state)
		self.state.add_constraints(*data.constraints)

		# where to put it
		offset_vec = symexec.BitVecVal(stmt.offset, self.state.arch.bits)
		offset_val = SimValue(offset_vec)

		store_constraints = self.state.registers.store(offset_val, data.expr)
		self.state.add_constraints(*store_constraints)
	
	def symbolic_Store(self, stmt):
		# first resolve the address
		addr = SimIRExpr(stmt.addr, self.state)
		self.state.add_constraints(*addr.constraints)

		# now get the value
		data = SimIRExpr(stmt.data, self.state)
		data_val = s_helpers.fix_endian(stmt.endness, data.expr)
		self.state.add_constraints(*data.constraints)

		addr.sim_value.push_constraints(*data.constraints)
		store_constraints = self.state.memory.store(addr.sim_value, data_val)
		addr.sim_value.pop_constraints()

		self.state.add_constraints(*store_constraints)

	def symbolic_CAS(self, stmt):
		#
		# figure out if it's a single or double
		#
		double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

		#
		# first, get the expression of the add
		#
		addr_expr = SimIRExpr(stmt.addr, self.state)
		self.state.add_constraints(*addr_expr.constraints)

		#
		# now concretize the address, since this is going to be a write
		#
		addr = self.state.memory.concretize_write_addr(addr_expr.sim_value)[0]
		self.state.add_constraints(addr_expr.expr == addr)

		#
		# translate the expected values
		#
		expd_lo = SimIRExpr(stmt.expdLo, self.state)
		self.state.add_constraints(*expd_lo.constraints)
		if double_element:
			expd_hi = SimIRExpr(stmt.expdHi, self.state)
                        self.state.add_constraints(*expd_hi.constraints)

		# size of the elements
		element_size = expd_lo.expr.size()

		# the two places to write
		addr_first = SimValue(symexec.BitVecVal(addr, self.state.arch.bits))
		addr_second = SimValue(symexec.BitVecVal(addr + element_size, self.state.arch.bits))

		#
		# Get the memory offsets
		#
		if not double_element:
			# single-element case
			addr_lo = addr_first
			addr_hi = None
		elif stmt.endness == "Iend_BE":
			# double-element big endian
			addr_hi = addr_first
			addr_lo = addr_second
		else:
			# double-element little endian
			addr_hi = addr_second
			addr_lo = addr_first

		#
		# save the old value
		#

		# load lo
		old_lo, old_lo_constraints = self.state.memory.load(addr_lo, element_size)
		old_lo = s_helpers.fix_endian(stmt.endness, old_lo)
		self.state.add_constraints(*old_lo_constraints)

		# save it to the tmp
		old_lo_tmp = self.state.temps[stmt.oldLo]
		self.state.add_constraints(old_lo_tmp == old_lo)

		# load hi
		old_hi, old_hi_constraints = None, [ ]
		if double_element:
			old_hi, old_hi_constraints = self.state.memory.load(addr_hi, element_size)
			old_hi = s_helpers.fix_endian(stmt.endness, old_hi)
			self.state.add_constraints(*old_hi_constraints)

			# save it to the tmp
			old_hi_tmp = self.state.temps[stmt.oldHi]
			self.state.add_constraints(old_hi_tmp == old_hi)

		#
		# comparator for compare
		#
		comparator = old_lo.expr == expd_lo.expr
		if old_hi: comparator = symexec.And(comparator, old_hi.expr == expd_hi.expr)

		#
		# the value to write
		#
		data_lo = SimIRExpr(stmt.dataLo, self.state)
		data_lo_val = s_helpers.fix_endian(stmt.endness, data_lo)
		self.state.add_constraints(*data_lo.constraints)

		if double_element:
			data_hi = SimIRExpr(stmt.dataHi, self.state)
			data_hi_val = s_helpers.fix_endian(stmt.endness, data_hi)
			self.state.add_constraints(*data_hi.constraints)

		# combine it to the ITE
		if not double_element:
			write_val = symexec.If(comparator, data_lo_val, old_lo)
		elif stmt.endness == "Iend_BE":
			write_val = symexec.If(comparator, symexec.Concat(data_hi_val, data_lo_val), symexec.Concat(old_hi, old_lo))
		else:
			write_val = symexec.If(comparator, symexec.Concat(data_lo_val, data_hi_val), symexec.Concat(old_lo, old_hi))

		#
		# and now write
		#
		self.state.memory.store(addr_first, write_val)

	def symbolic_Exit(self, stmt):
		guard = SimIRExpr(stmt.guard, self.state)
		self.state.add_branch_constraints(guard.expr != 0)
		self.state.add_constraints(*guard.constraints)

	def symbolic_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass

# This function receives an initial state and imark and processes a list of pyvex.IRStmts
# It returns a final state, last imark, and a list of SimIRStmts
def handle_statements(initial_state, initial_imark, statements):
	last_imark = initial_imark
	state = initial_state
	s_statements = [ ]

	# Translate all statements until something errors out
	try:
		for stmt in statements:
			# we'll pass in the imark to the statements
			if type(stmt) == pyvex.IRStmt.IMark:
				l.debug("IMark: 0x%x" % stmt.addr)
				last_imark = stmt

			# make a copy of the state
			s_stmt = SimIRStmt(stmt, last_imark, state)
			s_statements.append(s_stmt)
		
			# for the exits, put *not* taking the exit on the list of constraints so
			# that we can continue on. Otherwise, add the constraints
			if type(stmt) == pyvex.IRStmt.Exit:
				state = state.copy_avoid()
			else:
				state = state.copy_after()
	except SimError:
		l.warning("A SimError was hit when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", exc_info=True)

	return state, last_imark, s_statements
