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
class SimIRStmt(object):
	def __init__(self, stmt, imark, stmt_idx, state, options):
		self.stmt = stmt
		self.imark = imark
		self.stmt_idx = stmt_idx
		self.state = state

		# the options and mode
		self.options = options

		# references by the statement
		self.refs = [ ]

		# for concrete mode, whether or not the exit was taken
		self.exit_taken = False

		if o.BREAK_SIRSTMT_START in self.options:
			import ipdb
			ipdb.set_trace()

		func_name = "handle_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s" % (type(stmt)))
			getattr(self, func_name)(stmt)
		else:
			raise UnsupportedIRStmtType("Unsupported statement type %s" % (type(stmt)))

		if o.BREAK_SIRSTMT_END in self.options:
			import ipdb
			ipdb.set_trace()

	def record_expr_refs(self, expr):
		# first, track various references
		self.refs.extend(expr.refs)

		# now, track the constraints if we're doing so
		self.add_constraints(*expr.constraints)

	# translates an IRExpr into a SimIRExpr, honoring the state, mode, and options of this statement
	def translate_expr(self, expr):
		return SimIRExpr(expr, self.imark, self.stmt_idx, self.state, self.options)

	# checks options and adds constraints if neccessary
	def add_constraints(self, *constraints):
		if o.TRACK_CONSTRAINTS in self.options:
			self.state.add_constraints(*constraints)

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
		if o.TMP_REFS in self.options:
			self.refs.append(SimTmpWrite(self.imark.addr, self.stmt_idx, stmt.tmp, data.sim_value, data.size()/8, data.reg_deps(), data.tmp_deps()))

		# A bit hackish. Basically, if we're in symbolic mode, the temps are going to be symbolic values initially, for readability's sake.
		# However, if we're in concrete mode, we store the temps in the list directly.
		if o.SYMBOLIC_TEMPS in self.options:
			l.debug("Adding temp constraint for temp %d", stmt.tmp)
			self.state.add_constraints(self.state.temps[stmt.tmp] == data.expr)
		else:
			l.debug("Adding temp %d", stmt.tmp)
			self.state.store_tmp(stmt.tmp, data.sim_value.expr)

	def handle_Put(self, stmt):
		# value to put
		data = self.translate_expr(stmt.data)
		self.record_expr_refs(data)

		# do the put (if we should)
		if o.DO_PUTS in self.options:
			self.state.store_reg(stmt.offset, data.expr)

		# track the put
		if stmt.offset not in (self.state.arch.ip_offset,):
			self.refs.append(SimRegWrite(self.imark.addr, self.stmt_idx, stmt.offset, data.sim_value, data.size()/8, data.reg_deps(), data.tmp_deps()))

	def handle_Store(self, stmt):
		# first resolve the address and record stuff
		addr = self.translate_expr(stmt.addr)
		self.record_expr_refs(addr)

		if o.SYMBOLIC not in self.options and addr.sim_value.is_symbolic():
				return

		# now get the value and track everything
		data = self.translate_expr(stmt.data)
		self.record_expr_refs(data)

		# fix endianness
		data_endianness = s_helpers.fix_endian(stmt.endness, data.expr)

		# Now do the store (if we should)
		if o.DO_STORES in self.options and (o.SYMBOLIC in self.options or not addr.sim_value.is_symbolic()):
			self.state.store_mem(addr.expr, data_endianness)

		# track the write
		data_val = self.state.expr_value(data_endianness)
		self.refs.append(SimMemWrite(self.imark.addr, self.stmt_idx, addr.sim_value, data_val, data.size()/8, addr.reg_deps(), addr.tmp_deps(), data.reg_deps(), data.tmp_deps()))

	def handle_Exit(self, stmt):
		guard = self.translate_expr(stmt.guard)
		self.record_expr_refs(guard)

		# track branching constraints
		if o.TRACK_CONSTRAINTS in self.options:
			self.state.add_branch_constraints(guard.expr != 0)

		# get the destination
		dst = SimValue(s_helpers.translate_irconst(stmt.dst))
		self.refs.append(SimCodeRef(self.imark.addr, self.stmt_idx, dst, set(), set()))

		# TODO: update instruction pointer

		if o.SYMBOLIC not in self.options and guard.sim_value.is_symbolic():
				return

		if o.TAKEN_EXIT in self.options and guard.sim_value.any() != 0:
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
		self.record_expr_refs(addr_expr)

		if o.SYMBOLIC not in self.options and addr_expr.sim_value.is_symbolic():
				return

		#
		# now concretize the address, since this is going to be a write
		#
		addr = self.state.memory.concretize_write_addr(addr_expr.sim_value)[0]
		self.add_constraints(addr_expr.expr == addr)

		#
		# translate the expected values
		#
		expd_lo = self.translate_expr(stmt.expdLo)
		self.record_expr_refs(expd_lo)
		if double_element:
			expd_hi = self.translate_expr(stmt.expdHi)
			self.record_expr_refs(expd_hi)

		# size of the elements
		element_size = expd_lo.expr.size()/8
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
		old_lo = s_helpers.fix_endian(stmt.endness, self.state.mem_expr(addr_lo, element_size, fix_endness=False))
		self.state.store_tmp(stmt.oldLo, old_lo)

		# track the write
		old_lo_val = self.state.expr_value(old_lo)
		self.refs.append(SimMemRead(self.imark.addr, self.stmt_idx, addr_lo, old_lo_val, element_size, addr_expr.reg_deps(), addr_expr.tmp_deps()))
		self.refs.append(SimTmpWrite(self.imark.addr, self.stmt_idx, stmt.oldLo, old_lo_val, element_size, set(), set()))

		# load hi
		old_hi = None
		if double_element:
			old_hi = s_helpers.fix_endian(stmt.endness, self.state.mem_expr(addr_hi, element_size, fix_endness=False))
			self.state.store_tmp(stmt.oldHi, old_hi)

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
		self.record_expr_refs(data_lo)
		data_reg_deps = data_lo.reg_deps()
		data_tmp_deps = data_lo.tmp_deps()

		data_lo_end = s_helpers.fix_endian(stmt.endness, data_lo.expr)
		if double_element:
			data_hi = self.translate_expr(stmt.dataHi)
			self.record_expr_refs(data_hi)
			data_reg_deps |= data_hi.reg_deps()
			data_tmp_deps |= data_hi.tmp_deps()

			data_hi_end = s_helpers.fix_endian(stmt.endness, data_hi.expr)

		# combine it to the ITE
		if not double_element:
			write_expr = symexec.If(comparator, data_lo_end, old_lo)
		elif stmt.endness == "Iend_BE":
			write_expr = symexec.If(comparator, symexec.Concat(data_hi_end, data_lo_end), symexec.Concat(old_hi, old_lo))
		else:
			write_expr = symexec.If(comparator, symexec.Concat(data_lo_end, data_hi_end), symexec.Concat(old_lo, old_hi))

		# record the write
		write_simval = self.state.expr_value(write_expr)
		self.refs.append(SimMemWrite(self.imark.addr, self.stmt_idx, addr_first, write_simval, write_size, addr_expr.reg_deps(), addr_expr.tmp_deps(), data_reg_deps, data_tmp_deps))

		if o.SYMBOLIC not in self.options and symexec.is_symbolic(comparator):
				return

		# and now write, if it's enabled
		if o.DO_STORES in self.options:
			self.state.store_mem(addr_first, write_expr)
