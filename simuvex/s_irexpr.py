#!/usr/bin/env python
'''This module handles constraint generation.'''

import symexec
import s_irop
import s_ccall
import s_helpers

import logging
l = logging.getLogger("s_irexpr")

class UnsupportedIRExprType(Exception):
	pass

# translates several IRExprs, taking into account generated constraints along the way
def translate_irexprs(exprs, state, other_constraints = [ ]):
	constraints = [ ]
	args = [ ]

	for a in exprs:
		s_a, s_c = SimIRExpr(a, state, other_constraints + constraints).expr_and_constraints()
		args.append(s_a)
		constraints += s_c

	return args, constraints


class SimIRExpr:
	def __init__(self, expr, state, other_constraints = None):
		self.state = state
		self.state_constraints = state.constraints_after()
		self.other_constraints = other_constraints if other_constraints else [ ]

		func_name = "symbolic_" + type(expr).__name__
		l.debug("Looking for handler %s for IRExpr %s" % (func_name, type(expr).__name__))
		if hasattr(self, func_name):
			self.expr, self.constraints = getattr(self, func_name)(expr)
		else:
			raise UnsupportedIRExprType("Unsupported expression type %s." % type(expr))

	def expr_and_constraints(self):
		return self.expr, self.constraints

	###########################
	### Expression handlers ###
	###########################

	# TODO: make sure the way we're handling reads of parts of registers is correct
	def symbolic_Get(self, expr):
		size = s_helpers.get_size(expr.type)
		offset_vec = symexec.BitVecVal(expr.offset, self.state.arch.bits)
		reg_expr, get_constraints = self.state.registers.load(offset_vec, size)
		return reg_expr, get_constraints
	
	def symbolic_op(self, expr):
		args, constraints = translate_irexprs(expr.args(), self.state, self.other_constraints)
		return s_irop.translate(expr.op, args), constraints

	symbolic_Unop = symbolic_op
	symbolic_Binop = symbolic_op
	symbolic_Triop = symbolic_op
	symbolic_Qop = symbolic_op
	
	def symbolic_RdTmp(self, expr):
		return self.state.temps[expr.tmp], [ ]
	
	def symbolic_Const(self, expr):
		return s_helpers.translate_irconst(expr.con), [ ]
	
	def symbolic_Load(self, expr):
		size = s_helpers.get_size(expr.type)
		addr, addr_constraints = SimIRExpr(expr.addr, self.state, self.other_constraints).expr_and_constraints()
		mem_expr, load_constraints = self.state.memory.load(addr, size, self.state_constraints + addr_constraints + self.other_constraints)
		mem_expr = s_helpers.fix_endian(expr.endness, mem_expr)
	
		l.debug("Load of size %d got size %d" % (size, mem_expr.size()))
		return mem_expr, load_constraints + addr_constraints
	
	def symbolic_CCall(self, expr):
		s_args, s_constraints = translate_irexprs(expr.args(), self.state, self.other_constraints)

		if hasattr(s_ccall, expr.callee.name):
			func = getattr(s_ccall, expr.callee.name)
			retval, retval_constraints = func(self.state, *s_args)
			return retval, s_constraints + retval_constraints
		raise Exception("Unsupported callee %s" % expr.callee.name)
	
	def symbolic_Mux0X(self, expr):
		cond, cond_constraints =   SimIRExpr(expr.cond, self.state, self.other_constraints).expr_and_constraints()
		expr0, expr0_constraints = SimIRExpr(expr.expr0, self.state, self.other_constraints).expr_and_constraints()
		exprX, exprX_constraints = SimIRExpr(expr.exprX, self.state, self.other_constraints).expr_and_constraints()
	
		cond0_constraints = symexec.And(*([ cond == 0 ] + expr0_constraints ))
		condX_constraints = symexec.And(*([ cond != 0 ] + exprX_constraints ))
		return symexec.If(cond == 0, expr0, exprX), [ symexec.Or(cond0_constraints, condX_constraints) ]
