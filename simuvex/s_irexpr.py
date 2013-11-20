#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import s_irop
import s_ccall
import s_value
import s_helpers
import s_exception

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
	pass

# translates several IRExprs, taking into account generated constraints along the way
def translate_irexprs(exprs, state, other_constraints = [ ], mode = "symbolic"):
	constraints = [ ]
	args = [ ]
	s_exprs = [ ]

	for a in exprs:
		e = SimIRExpr(a, state, other_constraints + constraints, mode=mode)
		s_a, s_c = e.expr_and_constraints()

		s_exprs.append(e)
		args.append(s_a)
		constraints += s_c

	return args, constraints, s_exprs


class SimIRExpr:
	def __init__(self, expr, state, other_constraints = None, mode = "symbolic"):
		self.mode = mode
		self.state = state
		self.state_constraints = state.constraints_after()
		self.other_constraints = other_constraints if other_constraints else [ ]
		self.constraints = [ ]
		self.data_reads = [ ]

		self.sim_value = None
		self.expr = None

		func_name = mode + "_" + type(expr).__name__
		l.debug("Looking for handler for IRExpr %s in mode %s" % (type(expr), mode))
		if hasattr(self, func_name):
			getattr(self, func_name)(expr)
		else:
			raise UnsupportedIRExprType("Unsupported expression type %s in mode %s." % (type(expr), mode))

		self.sim_value = s_value.SimValue(self.expr, self.constraints + self.other_constraints + self.state_constraints)

	def expr_and_constraints(self):
		return self.expr, self.constraints

	##################################
	### Static expression handlers ###
	##################################
	def static_Get(self, expr):
		pass
	
	def static_op(self, expr):
		pass

	static_Unop = static_op
	static_Binop = static_op
	static_Triop = static_op
	static_Qop = static_op
	
	def static_RdTmp(self, expr):
		self.expr = self.state.temps[expr.tmp]
	
	def static_Const(self, expr):
		self.expr = s_helpers.translate_irconst(expr.con)
	
	def static_Load(self, expr):
		# get the address
		addr = SimIRExpr(expr.addr, self.state, self.other_constraints, mode=self.mode)
		if addr.sim_value.is_symbolic():
			raise s_exception.SimModeError("Can't handle symbolic address in static mode.")

		# TODO: this is a hack
		self.expr = addr

		self.data_reads.append(addr.sim_value)
	
	def static_CCall(self, expr):
		_,_,exprs = translate_irexprs(expr.args(), self.state, self.other_constraints, mode="static")
		for e in exprs:
			self.data_reads.extend(e.data_reads)

	def static_Mux0X(self, expr):
		expr0 = SimIRExpr(expr.expr0, self.state, self.other_constraints, mode=self.mode)
		exprX = SimIRExpr(expr.exprX, self.state, self.other_constraints, mode=self.mode)

		self.data_reads.extend(expr0.data_reads)
		self.data_reads.extend(exprX.data_reads)

	####################################
	### Symbolic expression handlers ###
	####################################
	def symbolic_Get(self, expr):
		# TODO: make sure the way we're handling reads of parts of registers is correct
		size = s_helpers.get_size(expr.type)

		# the offset of the register
		offset_vec = symexec.BitVecVal(expr.offset, self.state.arch.bits)
		offset_val = s_value.SimValue(offset_vec)

		# get it!
		reg_expr, get_constraints = self.state.registers.load(offset_val, size)
		self.expr = reg_expr
		self.constraints.extend(get_constraints)
	
	def symbolic_op(self, expr):
		args,constraints,exprs =translate_irexprs(expr.args(), self.state, self.other_constraints)
		self.expr = s_irop.translate(expr.op, args)
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
		addr = SimIRExpr(expr.addr, self.state, self.other_constraints)

		# load from memory and fix endianness
		mem_expr, load_constraints = self.state.memory.load(addr.sim_value, size)
		mem_expr = s_helpers.fix_endian(expr.endness, mem_expr)
	
		l.debug("Load of size %d got size %d" % (size, mem_expr.size()))

		self.expr = mem_expr
		self.constraints.extend(load_constraints)
		self.constraints.extend(addr.constraints)

		# track memory access
		self.data_reads.extend(addr.data_reads)
		self.data_reads.append([addr.sim_value, size])
	
	def symbolic_CCall(self, expr):
		s_args,s_constraints,_ =translate_irexprs(expr.args(), self.state, self.other_constraints)

		if hasattr(s_ccall, expr.callee.name):
			func = getattr(s_ccall, expr.callee.name)
			retval, retval_constraints = func(self.state, *s_args)

			self.expr = retval
			self.constraints.extend(s_constraints)
			self.constraints.extend(retval_constraints)
		else:
			raise Exception("Unsupported callee %s" % expr.callee.name)
	
	def symbolic_Mux0X(self, expr):
		cond, cond_constraints =   SimIRExpr(expr.cond, self.state, self.other_constraints).expr_and_constraints()
		expr0, expr0_constraints = SimIRExpr(expr.expr0, self.state, self.other_constraints).expr_and_constraints()
		exprX, exprX_constraints = SimIRExpr(expr.exprX, self.state, self.other_constraints).expr_and_constraints()
	
		cond0_constraints = symexec.And(*([ cond == 0 ] + expr0_constraints ))
		condX_constraints = symexec.And(*([ cond != 0 ] + exprX_constraints ))
		
		self.expr = symexec.If(cond == 0, expr0, exprX)
		self.constraints.append(symexec.Or(cond0_constraints, condX_constraints))

		# TODO: data reads
