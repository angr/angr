#!/usr/bin/env python
'''This module handles constraint generation for VEX IRStmt.'''

import symexec
import s_helpers
import s_options as o
from .s_value import SimValue
from .s_irexpr import SimIRExpr
from .s_ref import SimTmpWrite, SimRegWrite, SimMemWrite, SimCodeRef, SimMemRead

import logging
l = logging.getLogger("s_irstmt")

class UnsupportedIRStmtType(Exception):
	pass

# A class for symbolically translating VEX IRStmts.
class SimIRStmt:
	def __init__(self, stmt, imark, stmt_idx, state, options):
		self.stmt = stmt
		self.imark = imark
		self.stmt_idx = stmt_idx

		self.state = state
		self.state.id = "%x" % imark.addr

		# the options and mode
		self.options = options

		# references by the statement
		self.refs = [ ]

		# for concrete mode, whether or not the exit was taken
		self.exit_taken = False

		func_name = "handle_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s" % (type(stmt)))
			getattr(self, func_name)(stmt)
		else:
			raise UnsupportedIRStmtType("Unsupported statement type %s" % (type(stmt)))

	def record_expr_refs(self, expr):
		# first, track various references
		self.refs.extend(expr.refs)

	# translates an IRExpr into a SimIRExpr, honoring the state, mode, and options of this statement
	def translate_expr(self, expr):
		return SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.options)

	##########################
	### statement handlers ###
	##########################
	def handle_NoOp(self, stmt):
		pass
	
	def handle_IMark(self, stmt):
		pass
	
	def handle_WrTmp(self, stmt):
		# get data and track data reads
		data = self.translate_expr(stmt.data)
		self.record_expr_refs(data)

		# get the size, and record the write
		self.refs.append(SimTmpWrite(self.imark.addr, self.stmt_idx, stmt.tmp, data.sim_value, data.size(), data.reg_deps(), data.tmp_deps()))

		# SimIRexpr.expr can be None in concrete mode
		if data.expr is None:
			return

		# A bit hackish. Basically, if we're in symbolic mode, the temps are going to be symbolic values initially, for readability's sake.
		# However, if we're in concrete mode, we store the temps in the list directly.
		if o.SYMBOLIC in self.options:
			self.state.add_constraints(self.state.temps[stmt.tmp] == data.expr)
			self.state.add_constraints(*data.constraints)
		else:
			self.state.temps[stmt.tmp] = data.sim_value.expr

	def handle_Put(self, stmt):
		# value to put
		data = self.translate_expr(stmt.data)
		self.state.add_constraints(*data.constraints)

		# do the put (if we should)
		if o.DO_PUTS in self.options:
			store_constraints = self.state.registers.store(stmt.offset, data.expr)
			self.state.add_constraints(*store_constraints)

		# track the put
		self.record_expr_refs(data)
		if stmt.offset not in (self.state.arch.ip_offset,):
			self.refs.append(SimRegWrite(self.imark.addr, self.stmt_idx, stmt.offset, data.sim_value, data.size(), data.reg_deps(), data.tmp_deps()))

	def handle_Store(self, stmt):
		# first resolve the address and record stuff
		addr = self.translate_expr(stmt.addr)
		self.state.add_constraints(*addr.constraints)
		self.record_expr_refs(addr)

		if o.SYMBOLIC not in self.options and addr.sim_value.is_symbolic():
				return

		# now get the value and track everything
		data = self.translate_expr(stmt.data)
		self.state.add_constraints(*data.constraints)
		self.record_expr_refs(data)

		if data.expr is None:
			self.refs.append(SimMemWrite(self.imark.addr, self.stmt_idx, addr.sim_value, data.sim_value, data.size(), addr.reg_deps(), addr.tmp_deps(), data.reg_deps(), data.tmp_deps()))
			return

		# fix endianness
		data_endianness = s_helpers.fix_endian(stmt.endness, data.expr)
		data_val = SimValue(data_endianness, self.state.constraints_after())

		# Now do the store (if we should)
		if o.DO_STORES in self.options:
			addr.sim_value.push_constraints(*data.constraints)
			store_constraints = self.state.memory.store(addr.sim_value, data_endianness)
			addr.sim_value.pop_constraints()

			self.state.add_constraints(*store_constraints)

		# track/do the write
		self.refs.append(SimMemWrite(self.imark.addr, self.stmt_idx, addr.sim_value, data_val, data.size(), addr.reg_deps(), addr.tmp_deps(), data.reg_deps(), data.tmp_deps()))

	def handle_Exit(self, stmt):
		guard = self.translate_expr(stmt.guard)

		# track memory reads and constraints
		self.record_expr_refs(guard)
		self.state.add_constraints(*guard.constraints)
		self.state.add_branch_constraints(guard.expr != 0)

		# get the destination
		dst = SimValue(s_helpers.translate_irconst(stmt.dst))
		self.refs.append(SimCodeRef(self.imark.addr, self.stmt_idx, dst, set(), set()))

		# TODO: update instruction pointer

		if o.SYMBOLIC not in self.options and guard.sim_value.is_symbolic():
				return

		if o.SINGLE_EXIT in self.options and guard.sim_value.any() != 0:
			self.exit_taken = True

	def handle_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass

	def handle_CAS(self, stmt):
		#
		# figure out if it's a single or double
		#
		double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

		#
		# first, get the expression of the add
		#
		addr_expr = self.translate_expr(stmt.addr)
		self.state.add_constraints(*addr_expr.constraints)

		if o.SYMBOLIC not in self.options and addr_expr.sim_value.is_symbolic():
				return

		#
		# now concretize the address, since this is going to be a write
		#
		addr = self.state.memory.concretize_write_addr(addr_expr.sim_value)[0]
		self.state.add_constraints(addr_expr.expr == addr)

		#
		# translate the expected values
		#
		expd_lo = self.translate_expr(stmt.expdLo)
		self.state.add_constraints(*expd_lo.constraints)
		self.record_expr_refs(expd_lo)
		if double_element:
			expd_hi = self.translate_expr(stmt.expdHi)
			self.state.add_constraints(*expd_hi.constraints)
			self.record_expr_refs(expd_hi)

		# size of the elements
		element_size = expd_lo.expr.size()
		write_size = element_size if not double_element else element_size * 2

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

		# track the write
		old_lo_val = SimValue(old_lo, self.state.constraints_after())
		self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr_lo, old_lo_val, element_size, addr_expr.reg_deps(), addr_expr.tmp_deps()))
		self.refs.append(SimTmpWrite(self.imark.addr, self.stmt_idx, stmt.oldLo, old_lo_val, element_size, set(), set()))

		# load hi
		old_hi, old_hi_constraints = None, [ ]
		if double_element:
			old_hi, old_hi_constraints = self.state.memory.load(addr_hi, element_size)
			old_hi = s_helpers.fix_endian(stmt.endness, old_hi)
			self.state.add_constraints(*old_hi_constraints)

			# save it to the tmp
			old_hi_tmp = self.state.temps[stmt.oldHi]
			self.state.add_constraints(old_hi_tmp == old_hi)

			# track the write
			old_hi_val = SimValue(old_hi, self.state.constraints_after())
			self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr_hi, old_hi_val, element_size, addr_expr.reg_deps(), addr_expr.tmp_deps()))
			self.refs.append(SimTmpWrite(self.imark.addr, self.stmt_idx, stmt.oldHi, old_hi_val, element_size, set(), set()))

		#
		# comparator for compare
		#
		comparator = old_lo == expd_lo.expr
		if old_hi: comparator = symexec.And(comparator, old_hi.expr == expd_hi.expr)

		#
		# the value to write
		#
		data_lo = self.translate_expr(stmt.dataLo)
		self.state.add_constraints(*data_lo.constraints)
		self.record_expr_refs(data_lo)
		data_reg_deps = data_lo.reg_deps()
		data_tmp_deps = data_lo.tmp_deps()

		if data_lo.expr == None:
			return

		data_lo_val = s_helpers.fix_endian(stmt.endness, data_lo.expr)

		if double_element:
			data_hi = self.translate_expr(stmt.dataHi)
			self.state.add_constraints(*data_hi.constraints)
			self.record_expr_refs(data_hi)
			data_reg_deps |= data_hi.reg_deps()
			data_tmp_deps |= data_hi.tmp_deps()

			data_hi_val = s_helpers.fix_endian(stmt.endness, data_hi.expr)

			if data_hi.expr == None:
				return

		# combine it to the ITE
		if not double_element:
			write_val = symexec.If(comparator, data_lo_val, old_lo)
		elif stmt.endness == "Iend_BE":
			write_val = symexec.If(comparator, symexec.Concat(data_hi_val, data_lo_val), symexec.Concat(old_hi, old_lo))
		else:
			write_val = symexec.If(comparator, symexec.Concat(data_lo_val, data_hi_val), symexec.Concat(old_lo, old_hi))

		# record the write
		write_simval = SimValue(write_val, self.state.constraints_after())
		self.refs.append(SimMemWrite(self.imark.addr, self.stmt_idx, addr_first, write_simval, write_size, addr_expr.reg_deps(), addr_expr.tmp_deps(), data_reg_deps, data_tmp_deps))

		if o.SYMBOLIC not in self.options and symexec.is_symbolic(comparator):
				return

		# and now write, if it's enabled
		if o.DO_STORES in self.options:
			self.state.memory.store(addr_first, write_val)
