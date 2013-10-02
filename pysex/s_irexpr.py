#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import s_helpers
import s_irop
import s_ccall
import logging

l = logging.getLogger("s_irexpr")
#l.setLevel(logging.DEBUG)

###########################
### Expression handlers ###
###########################

# TODO: make sure the way we're handling reads of parts of registers is correct
def handle_get(expr, state):
	# TODO: proper SSO registers
	size = s_helpers.get_size(expr.type)

	if expr.offset not in state.registers:
		# TODO: handle register partials (ie, ax) as symbolic pieces of the full register
		state.registers[expr.offset] = [ z3.BitVec("%s_reg_%d_%d" % (state.id, expr.offset, 0), size) ]
	return z3.Extract(size - 1, 0, state.registers[expr.offset][-1]), [ ]

def handle_op(expr, state):
	args = expr.args()
	return s_irop.translate(expr.op, args, state)

def handle_rdtmp(expr, state):
	return state.temps[expr.tmp], [ ]

def handle_const(expr, state):
	return s_helpers.translate_irconst(expr.con), [ ]

def handle_load(expr, state):
	size = s_helpers.get_size(expr.type)
	l.debug("Load of size %d" % size)

	addr, addr_constraints = translate(expr.addr, state)
	expr, load_constraints = state.memory.load(addr, state.old_constraints + addr_constraints)
	#return expr, load_constraints + addr_constraints
	return z3.BitVecVal(100, size), [ ]

def handle_ccall(expr, state):
	s_args, s_constraints = zip(*[ translate(a, state) for a in expr.args() ])
	s_constraints = sum(s_constraints[0], [])
	if hasattr(s_ccall, expr.callee.name):
		func = getattr(s_ccall, expr.callee.name)
		return func(*s_args), s_constraints

	raise Exception("Unsupported callee %s" % expr.callee.name)

def handle_mux0x(expr, state):
	cond, cond_constraints = translate(expr.cond, state)
	expr0, expr0_constraints = translate(expr.expr0, state)
	exprX, exprX_constraints = translate(expr.exprX, state)

	cond0_constraints = z3.And(*[[ cond == 0 ] + expr0_constraints ])
	condX_constraints = z3.And(*[[ cond != 0 ] + exprX_constraints ])
	return z3.If(cond == 0, expr0, exprX), z3.Or(cond0_constraints, condX_constraints)

var_mem_counter = 0
expr_handlers = { }
expr_handlers[pyvex.IRExpr.Get] = handle_get
expr_handlers[pyvex.IRExpr.Unop] = handle_op
expr_handlers[pyvex.IRExpr.Binop] = handle_op
expr_handlers[pyvex.IRExpr.Triop] = handle_op
expr_handlers[pyvex.IRExpr.Qop] = handle_op
expr_handlers[pyvex.IRExpr.RdTmp] = handle_rdtmp
expr_handlers[pyvex.IRExpr.Const] = handle_const
expr_handlers[pyvex.IRExpr.Load] = handle_load
expr_handlers[pyvex.IRExpr.CCall] = handle_ccall
expr_handlers[pyvex.IRExpr.Mux0X] = handle_mux0x

def translate(expr, state):
	t = type(expr)
	if t not in expr_handlers:
		raise Exception("Unsupported expression type %s." % str(t))
	l.debug("Handling IRExpr %s" % t)
	return expr_handlers[t](expr, state)
