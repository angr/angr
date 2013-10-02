#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import s_helpers
import s_irop
import s_ccall
import random
import logging
import s_memory

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
        return s_irop.translate(expr.op, args, state), [ ]

def handle_rdtmp(expr, state):
        return state.temps[expr.tmp], [ ]

def handle_const(expr, state):
        return s_helpers.translate_irconst(expr.con), [ ]

def handle_load(expr, state):
        size = s_helpers.get_size(expr.type)
        addr = translate(expr.addr, state)
        l.debug("Load of size %d" % size)
        expr, con = state.memory.load(addr, state.past_constraints)
        return expr, con

def handle_ccall(expr, state):
        s_args = [ translate(a, state) for a in expr.args() ]
        if hasattr(s_ccall, expr.callee.name):
                func = getattr(s_ccall, expr.callee.name)
                return func(*s_args), [ ]

        raise Exception("Unsupported callee %s" % expr.callee.name)

def handle_mux0x(expr, state):
        cond = translate(expr.cond, state)
        expr0 = translate(expr.expr0, state)
        exprX = translate(expr.exprX, state)

        return z3.If(cond == 0, expr0, exprX), [ ]

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
