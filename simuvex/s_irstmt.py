#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import pyvex
from s_irexpr import SimIRExpr
import s_helpers
import s_exception

import logging
l = logging.getLogger("s_irstmt")

class UnsupportedIRStmtType(Exception):
	pass

class SimIRStmt:
	def __init__(self, stmt, imark, state):
		self.stmt = stmt
		self.imark = imark

		self.state = state
		self.state.id = "%x" % imark.addr

		func_name = "symbolic_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s" % type(stmt))			
			getattr(self, func_name)(stmt)
		else:
			raise UnsupportedIRStmtType("Unsupported statement type %s." % type(stmt))

	##########################
	### Statement handlers ###
	##########################
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
		new_val, data_constraints = SimIRExpr(stmt.data, self.state).expr_and_constraints()
		self.state.add_constraints(*data_constraints)

		offset_vec = symexec.BitVecVal(stmt.offset, self.state.arch.bits)
		store_constraints = self.state.registers.store(offset_vec, new_val, self.state.constraints_after())
		self.state.add_constraints(*store_constraints)
	
	def symbolic_Store(self, stmt):
		# first resolve the address
		addr, addr_constraints = SimIRExpr(stmt.addr, self.state).expr_and_constraints()
		self.state.add_constraints(*addr_constraints)

		# now get the value
		val, val_constraints = SimIRExpr(stmt.data, self.state).expr_and_constraints()
		self.state.add_constraints(*val_constraints)

		# handle endianess
		val = s_helpers.fix_endian(stmt.endness, val)

		store_constraints = self.state.memory.store(addr, val, self.state.old_constraints)
		self.state.add_constraints(*store_constraints)

	def symbolic_CAS(self, stmt):
		#
		# figure out if it's a single or double
		#
		double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

		#
		# first, get the expression of the add
		#
		addr_expr, addr_expr_constraints = SimIRExpr(stmt.addr, self.state).expr_and_constraints()
		self.state.add_constraints(*addr_expr_constraints)

		#
		# now concretize the address, since this is going to be a write
		#
		addr = self.state.memory.concretize_write_addr(addr_expr, self.state.constraints_after())
		self.state.add_constraints(addr_expr == addr)

		#
		# translate the expected values
		#
		expd_lo, expd_lo_constraints = SimIRExpr(stmt.expdLo, self.state).expr_and_constraints()
		self.state.add_constraints(*expd_lo_constraints)
		if double_element:
			expd_hi, expd_hi_constraints = SimIRExpr(stmt.expdHi, self.state).expr_and_constraints()
                        self.state.add_constraints(*expd_hi_constraints) # SHOW Yan this chage

		# size of the elements
		element_size = expd_lo.size()

		# the two places to write
		addr_first = symexec.BitVecVal(addr, self.state.arch.bits)
		addr_second = symexec.BitVecVal(addr + element_size, self.state.arch.bits)

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
		old_lo, old_lo_constraints = self.state.memory.load(addr_lo, element_size, self.state.constraints_after())
		self.state.add_constraints(*old_lo_constraints)
		old_lo = s_helpers.fix_endian(stmt.endness, old_lo)

		# save it to the tmp
		old_lo_tmp = self.state.temps[stmt.oldLo]
		self.state.add_constraints(old_lo_tmp == old_lo)

		# load hi
		old_hi, old_hi_constraints = None, [ ]
		if double_element:
			old_hi, old_hi_constraints = self.state.memory.load(addr_hi, element_size, self.state.constraints_after())
			self.state.add_constraints(*old_hi_constraints)
			old_hi = s_helpers.fix_endian(stmt.endness, old_hi)

			# save it to the tmp
			old_hi_tmp = self.state.temps[stmt.oldHi]
			self.state.add_constraints(old_hi_tmp == old_hi)

		#
		# comparator for compare
		#
		comparator = old_lo == expd_lo
		if old_hi: comparator = symexec.And(comparator, old_hi == expd_hi)

		#
		# the value to write
		#
		data_lo, data_lo_constraints = SimIRExpr(stmt.dataLo, self.state).expr_and_constraints()
		self.state.add_constraints(*data_lo_constraints)
		data_lo = s_helpers.fix_endian(stmt.endness, data_lo)

		if double_element:
			data_hi, data_hi_constraints = SimIRExpr(stmt.dataHi, self.state).expr_and_constraints()
			self.state.add_constraints(*data_hi_constraints)
			data_hi = s_helpers.fix_endian(stmt.endness, data_hi)

		# combine it to the ITE
		if not double_element:
			write_val = symexec.If(comparator, data_lo, old_lo)
		elif stmt.endness == "Iend_BE":
			write_val = symexec.If(comparator, symexec.Concat(data_hi, data_lo), symexec.Concat(old_hi, old_lo))
		else:
			write_val = symexec.If(comparator, symexec.Concat(data_lo, data_hi), symexec.Concat(old_lo, old_hi))

		#
		# and now write
		#
		self.state.memory.store(addr_first, write_val, self.state.constraints_after())

	def symbolic_Exit(self, stmt):
		guard_expr, guard_constraints = SimIRExpr(stmt.guard, self.state).expr_and_constraints()
		self.state.add_branch_constraints(guard_expr != 0)
		self.state.add_constraints(*guard_constraints)

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
	except s_exception.SimError:
		l.warning("A SimError was hit when analyzing statements. This may signify an unavoidable exit (ok) or an actual error (not ok)", exc_info=True)

	return state, last_imark, s_statements
