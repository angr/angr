#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import s_irop
import s_ccall
import s_value
import s_helpers

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
	pass

class SimIRExpr:
	def __init__(self, expr, state, options, other_constraints = None):
		self.options = options
		self.state = state
		self.other_constraints = other_constraints if other_constraints else [ ]
		self.constraints = [ ]
		self.data_reads = [ ]

		self.sim_value = None
		self.expr = None

		if "concrete" in self.options: mode = "concrete"
		elif "symbolic" in self.options: mode = "symbolic"

		func_name = mode + "_" + type(expr).__name__
		l.debug("Looking for handler for IRExpr %s in mode %s" % (type(expr), mode))
		if hasattr(self, func_name):
			getattr(self, func_name)(expr)
		else:
			raise UnsupportedIRExprType("Unsupported expression type %s in mode %s." % (type(expr), mode))

		self.sim_value = s_value.SimValue(self.expr, self.constraints + self.other_constraints + self.state.constraints_after())

	def expr_and_constraints(self):
		return self.expr, self.constraints

	# translates several IRExprs, honoring mode and options and taking into account generated constraints along the way
	def translate_exprs(self, exprs):
		constraints = [ ]
		s_exprs = [ ]
	
		for a in exprs:
			e = SimIRExpr(a, self.state, self.options, self.other_constraints + constraints)
			s_exprs.append(e)
			constraints += e.constraints
	
		return s_exprs, constraints

	# translate a signle IRExpr, honoring mode and options and so forth
	def translate_expr(self, expr, extra_constraints = None):
		if extra_constraints is None: extra_constraints = [ ]
		return SimIRExpr(expr, self.state, self.options, other_constraints = (self.other_constraints + extra_constraints))

	##################################
	### Static expression handlers ###
	##################################
	def concrete_Get(self, expr):
		size = s_helpers.get_size(expr.type)

		# the offset of the register
		offset_vec = symexec.BitVecVal(expr.offset, self.state.arch.bits)
		offset_val = s_value.SimValue(offset_vec)

		# get it!
		self.expr, _ = self.state.registers.load(offset_val, size)

	def concrete_op(self, expr):
		exprs,_ = self.translate_exprs(expr.args())

		# track memory access
		for e in exprs:
			self.data_reads.extend(e.data_reads)

		# do the op if the option is set
		if "ops" in self.options:
			self.expr = s_irop.translate(expr.op, [ e.expr for e in exprs ])

	concrete_Unop = concrete_op
	concrete_Binop = concrete_op
	concrete_Triop = concrete_op
	concrete_Qop = concrete_op
	
	def concrete_RdTmp(self, expr):
		self.expr = self.state.temps[expr.tmp]
	
	def concrete_Const(self, expr):
		self.expr = s_helpers.translate_irconst(expr.con)
	
	def concrete_Load(self, expr):
		# size of the load
		size = s_helpers.get_size(expr.type)

		# get the address
		addr = self.translate_expr(expr.addr)
		if not addr.sim_value.is_symbolic():
			self.data_reads.append((addr.sim_value, size))
			if "loads" in self.options:
				mem_expr,_ = self.state.memory.load(addr.sim_value.any(), size)
				self.expr = s_helpers.fix_endian(expr.endness, mem_expr)

	def concrete_CCall(self, expr):
		exprs,_ = self.translate_exprs(expr.args())
		for e in exprs:
			self.data_reads.extend(e.data_reads)

		# TODO: do the call? -- probably not

	def concrete_Mux0X(self, expr):
		cond = self.translate_expr(expr.cond)
		expr0 = self.translate_expr(expr.expr0)
		exprX = self.translate_expr(expr.exprX)

		self.data_reads.extend(expr0.data_reads)
		self.data_reads.extend(exprX.data_reads)

		if "conditions" in self.options and not cond.sim_value.is_symbolic():
			if cond.sim_value.any():
				self.expr, self.constraints = exprX.expr_and_constraints()
			else:
				self.expr, self.constraints = expr0.expr_and_constraints()

	####################################
	### Symbolic expression handlers ###
	####################################
	def symbolic_Get(self, expr):
		size = s_helpers.get_size(expr.type)

		# the offset of the register
		offset_vec = symexec.BitVecVal(expr.offset, self.state.arch.bits)
		offset_val = s_value.SimValue(offset_vec)

		# get it!
		reg_expr, get_constraints = self.state.registers.load(offset_val, size)
		self.expr = reg_expr
		self.constraints.extend(get_constraints)
	
	def symbolic_op(self, expr):
		exprs,constraints = self.translate_exprs(expr.args())
		self.expr = s_irop.translate(expr.op, [ e.expr for e in exprs ])
		self.constraints.extend(constraints)

		# track memory access
		for e in exprs: self.data_reads.extend(e.data_reads)

	symbolic_Unop = symbolic_op
	symbolic_Binop = symbolic_op
	symbolic_Triop = symbolic_op
	symbolic_Qop = symbolic_op
	
	def symbolic_RdTmp(self, expr):
		self.expr = self.state.temps[expr.tmp]
	
	def symbolic_Const(self, expr):
		self.expr = s_helpers.translate_irconst(expr.con)
	
	def symbolic_Load(self, expr):
		# size of the load
		size = s_helpers.get_size(expr.type)

		# get the address expression and constraints
		addr = self.translate_expr(expr.addr)

		# load from memory and fix endianness
		mem_expr, load_constraints = self.state.memory.load(addr.sim_value, size)
		mem_expr = s_helpers.fix_endian(expr.endness, mem_expr)
	
		l.debug("Load of size %d got size %d" % (size, mem_expr.size()))

		self.expr = mem_expr
		self.constraints.extend(load_constraints)
		self.constraints.extend(addr.constraints)

		# track memory access
		self.data_reads.extend(addr.data_reads)
		self.data_reads.append((addr.sim_value, size))
	
	def symbolic_CCall(self, expr):
		exprs,constraints = self.translate_exprs(expr.args())
		s_args = [ e.expr for e in exprs ]

		if hasattr(s_ccall, expr.callee.name):
			func = getattr(s_ccall, expr.callee.name)
			retval, retval_constraints = func(self.state, *s_args)

			self.expr = retval
			self.constraints.extend(constraints)
			self.constraints.extend(retval_constraints)
		else:
			raise Exception("Unsupported callee %s" % expr.callee.name)
	
	def symbolic_Mux0X(self, expr):
		cond = self.translate_expr(expr.cond)
		expr0 = self.translate_expr(expr.expr0, cond.constraints)
		exprX = self.translate_expr(expr.exprX, cond.constraints)

		cond0_constraints = symexec.And(*([ cond.expr == 0 ] + expr0.constraints + cond.constraints ))
		condX_constraints = symexec.And(*([ cond.expr != 0 ] + exprX.constraints + cond.constraints ))

		self.expr = symexec.If(cond.expr == 0, expr0.expr, exprX.expr)
		self.constraints.append(symexec.Or(cond0_constraints, condX_constraints))

		# NOTE: this is an over-approximation of the reads
		self.data_reads.extend(cond.data_reads)
		self.data_reads.extend(expr0.data_reads)
		self.data_reads.extend(exprX.data_reads)
