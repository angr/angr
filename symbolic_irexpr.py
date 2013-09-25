#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import symbolic
import symbolic_irop

import logging
l = logging.getLogger("symbolic_irexpr")
l.setLevel(logging.DEBUG)

###########################
### Expression handlers ###
###########################
def handle_get(expr, state):
	# TODO: proper SSO registers
	if expr.offset not in state.registers:
		# TODO: handle register partials (ie, ax) as symbolic pieces of the full register
		state.registers[expr.offset] = [ z3.BitVec("reg_%d_%d" % (expr.offset, 0), symbolic.get_size(expr.type)) ]
	return state.registers[expr.offset][-1]

def handle_op(expr, state):
	args = expr.args()
	return symbolic_irop.translate(expr.op, args, state)

def handle_rdtmp(expr, state):
	return state.symbols[expr.tmp]

def handle_const(expr, state):
	size = symbolic.get_size(expr.con.type)
	t = type(expr.con.value)
	if t == int or t == long:
		return z3.BitVecVal(expr.con.value, size)
	raise Exception("Unsupported constant type: %s" % type(expr.con.value))

expr_handlers = { }
expr_handlers[pyvex.IRExpr.Get] = handle_get
expr_handlers[pyvex.IRExpr.Unop] = handle_op
expr_handlers[pyvex.IRExpr.Binop] = handle_op
expr_handlers[pyvex.IRExpr.Triop] = handle_op
expr_handlers[pyvex.IRExpr.Qop] = handle_op
expr_handlers[pyvex.IRExpr.RdTmp] = handle_rdtmp
expr_handlers[pyvex.IRExpr.Const] = handle_const

def translate(expr, state):
	t = type(expr)
	if t not in expr_handlers:
		raise Exception("Unsupported expression type %s." % str(t))
	l.debug("Handling IRExpr %s" % t)
	return expr_handlers[t](expr, state)
