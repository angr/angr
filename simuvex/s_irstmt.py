#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import s_helpers
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
		self.memory_refs = [ ]

		func_name = mode + "_" + type(stmt).__name__
		if hasattr(self, func_name):
			l.debug("Handling IRStmt %s in %s mode" % (type(stmt), mode))
			getattr(self, func_name)(stmt)
		else:
			raise UnsupportedIRStmtType("Unsupported statement type %s in %s mode." % (type(stmt), mode))

	#################################
	### Static statement handlers ###
	#################################
	def static_NoOp(self, stmt):
		pass
	
	def static_IMark(self, stmt):
		pass
	
	def static_WrTmp(self, stmt):
		data = SimIRExpr(stmt.data, self.state, mode=self.mode)

		# SimIRexpr.expr can be None in static mode
		if data.expr is not None:
			self.state.temps[stmt.tmp] = data.sim_value.expr

		# track data reads
		self.data_reads.extend(data.data_reads)

	# TODO: make this exclude memory references made in the IP
	def static_Put(self, stmt):
		data = SimIRExpr(stmt.data, self.state, mode=self.mode)
		if data.expr is not None:
			self.state.registers.store(stmt.offset, data.expr)

			# track memory references
			if not data.sim_value.is_symbolic():
				l.debug("Checking potential memory reference 0x%x", data.sim_value.any())
				if data.sim_value in self.state.memory and data.sim_value.any() != self.imark.addr + self.imark.len:
					self.memory_refs.append(data.sim_value)
				else:
					l.debug("... not referencing memory, or referencing .")
			else:
				l.debug("Skipping symbolic put.")

		# track data reads
		self.data_reads.extend(data.data_reads)
	
	def static_Store(self, stmt):
		# resolve the address
		addr = SimIRExpr(stmt.addr, self.state, mode=self.mode)

		# get the value
		data = SimIRExpr(stmt.data, self.state, mode=self.mode)

		# track data reads
		self.data_reads.extend(addr.data_reads)
		self.data_reads.extend(data.data_reads)

		# track the write
		if not addr.sim_value.is_symbolic():
			self.data_writes.append((addr.sim_value, data.sim_value.size()))

	def static_CAS(self, stmt):
		# TODO: implement static CAS
		pass

	def static_Exit(self, stmt):
		dst = SimValue(s_helpers.translate_irconst(stmt.dst))
		self.code_refs.append(dst)

	def static_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass

	###################################
	### Concrete statement handlers ###
	###################################
	def concrete_NoOp(self, stmt):
		pass
	
	def concrete_IMark(self, stmt):
		pass
	
	def concrete_WrTmp(self, stmt):
		data = SimIRExpr(stmt.data, self.state, mode="concrete")
		self.state.temps[stmt.tmp] = data.sim_value.any()

	def concrete_Put(self, stmt):
		data = SimIRExpr(stmt.data, self.state, mode="concrete").sym_value.bitvecval()
		self.state.registers.store(stmt.offset, data)
	
	def concrete_Store(self, stmt):
		# first resolve the address
		addr = SimIRExpr(stmt.addr, self.state, mode="concrete").sim_value.bitvecval()

		# now get the value and fix endianness
		data = SimIRExpr(stmt.data, self.state, mode="concrete").sim_value.bitvecval()
		data_val = s_helpers.fix_endian(stmt.endness, data.val)

		self.state.memory.store(addr, data_val)

	def concrete_CAS(self, stmt):
		#
		# figure out if it's a single or double
		#
		double_element = (stmt.oldHi != 0xFFFFFFFF) and (stmt.expdHi is not None)

		#
		# first, get the address
		#
		addr = SimIRExpr(stmt.addr, self.state, mode="concrete").sim_value.bitvecval()

		#
		# translate the expected values
		#
		expd_lo = SimIRExpr(stmt.expdLo, self.state, mode="concrete").sim_value.bitvecval()
		if double_element:
			expd_hi = SimIRExpr(stmt.expdHi, self.state, mode="concrete").sim_value.bitvecval()

		# size of the elements
		element_size = expd_lo.size()

		# the two places to write
		addr_first = addr
		addr_second = addr + element_size

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

		# save old lo
		old_lo = self.state.memory.load(addr_lo, element_size)
		old_lo = s_helpers.fix_endian(stmt.endness, old_lo)
		self.state.temps[stmt.oldLo] = old_lo

		# save old hi
		if double_element:
			old_hi = self.state.memory.load(addr_hi, element_size)
			old_hi = s_helpers.fix_endian(stmt.endness, old_hi)
			self.state.temps[stmt.oldHi] = old_hi

		#
		# comparator for compare
		#
		comparator = old_lo == expd_lo
		if double_element: comparator = comparator and old_hi == expd_hi

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

	def concrete_Exit(self, stmt):
		guard_expr, guard_constraints = SimIRExpr(stmt.guard, self.state).expr_and_constraints()
		self.state.add_branch_constraints(guard_expr != 0)
		self.state.add_constraints(*guard_constraints)

	def concrete_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass

	###################################
	### Symbolic statement handlers ###
	###################################
	def symbolic_NoOp(self, stmt):
		pass
	
	def symbolic_IMark(self, stmt):
		pass
	
	def symbolic_WrTmp(self, stmt):
		t = self.state.temps[stmt.tmp]
		data = SimIRExpr(stmt.data, self.state)

		# track constraints
		self.state.add_constraints(t == data.expr)
		self.state.add_constraints(*data.constraints)

		# track memory reads
		self.data_reads.extend(data.data_reads)
	
	def symbolic_Put(self, stmt):
		# value to put
		data = SimIRExpr(stmt.data, self.state)
		self.state.add_constraints(*data.constraints)

		# where to put it
		offset_vec = symexec.BitVecVal(stmt.offset, self.state.arch.bits)
		offset_val = SimValue(offset_vec)

		store_constraints = self.state.registers.store(offset_val, data.expr)
		self.state.add_constraints(*store_constraints)

		# track memory reads
		self.data_reads.extend(data.data_reads)
	
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

		# track memory reads and writes
		self.data_reads.extend(addr.data_reads)
		self.data_reads.extend(data.data_reads)
		self.data_writes.append(( addr.sim_value, data_val.size() ))

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
		comparator = old_lo == expd_lo.expr
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

		# track memory reads
		self.data_reads.extend(data_lo.data_reads)
		if double_element: self.data_reads.extend(data_hi.data_reads)
		self.data_reads.extend(expd_lo.data_reads)
		if double_element: self.data_reads.extend(expd_hi.data_reads)

		# TODO: track the CAS memory write (how?)

	def symbolic_Exit(self, stmt):
		guard = SimIRExpr(stmt.guard, self.state)
		self.state.add_branch_constraints(guard.expr != 0)
		self.state.add_constraints(*guard.constraints)

		# track memory reads
		self.data_reads.extend(guard.data_reads)

		# TODO: update instruction pointer

	def symbolic_AbiHint(self, stmt):
		# TODO: determine if this needs to do something
		pass
