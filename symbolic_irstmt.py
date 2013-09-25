#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import symbolic
import symbolic_irexpr

import logging
l = logging.getLogger("symbolic_irexpr")
l.setLevel(logging.DEBUG)

##########################
### Statement handlers ###
##########################
def handle_noop(stmt, state):
	return [ ]

def handle_imark(stmt, state):
	return [ ]

def handle_wrtmp(stmt, state):
	t = state.symbols[stmt.tmp]
	d = symbolic_irexpr.translate(stmt.data, state)
	print "=-======================================="
	print t
	print d
	print "=======================================-="
	return [ t == d ]

def handle_put(stmt, state):
	if stmt.offset not in state.registers:
		state.registers[stmt.offset] = [ ]

	reg_id = len(state.registers[stmt.offset])
	reg = z3.BitVec("reg_%d_%d" % (stmt.offset, reg_id), symbolic.get_size(state.irsb_stack[-1].tyenv.typeOf(stmt.data)))
	state.registers[stmt.offset].append(reg)
	return [ reg == symbolic_irexpr.translate(stmt.data, state) ]

def handle_store(stmt, state):
	# TODO: symbolic memory
	return [ ]

stmt_handlers = { }
stmt_handlers[pyvex.IRStmt.NoOp] = handle_noop
stmt_handlers[pyvex.IRStmt.IMark] = handle_imark
stmt_handlers[pyvex.IRStmt.WrTmp] = handle_wrtmp
stmt_handlers[pyvex.IRStmt.Put] = handle_put
stmt_handlers[pyvex.IRStmt.Store] = handle_store

def translate(stmt, state):
	t = type(stmt)
	if t not in stmt_handlers:
		raise Exception("Unsupported statement type %s." % str(t))
	l.debug("Handling IRStmt %s" % t)
	return stmt_handlers[t](stmt, state)
