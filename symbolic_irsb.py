#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import z3
import pyvex
import symbolic_irstmt
import symbolic_irexpr
import symbolic_helpers

import logging
l = logging.getLogger("symbolic_irsb")
#l.setLevel(logging.DEBUG)

########################
### IRSB translation ###
########################

def translate(irsb, state):
	exits = [ ]

	# we will use the VEX temps for the symbolic variables
	for n, t in enumerate(irsb.tyenv.types()):
		state.temps[n] = z3.BitVec('%s_t%d' % (state.id, n), symbolic_helpers.get_size(t))

	last_imark = None

	# now get the constraints
	for stmt in irsb.statements():
		constraint = symbolic_irstmt.translate(stmt, state)

		if type(stmt) == pyvex.IRStmt.IMark:
			last_imark = stmt

		if type(stmt) == pyvex.IRStmt.Exit:
			# add a constraint for the IP being updated, which is implicit in the Exit instruction
			exit_put = pyvex.IRStmt.Put(stmt.offsIP, pyvex.IRExpr.Const(stmt.dst))
			constraint += symbolic_irstmt.translate(exit_put, state)

			# record what we need for the exit
			exits.append( [ stmt.jumpkind, last_imark, symbolic_helpers.translate_irconst(stmt.dst), state.constraints + constraint ] )

			# let's not take the exit
			constraint = [ z3.Not(z3.And(*constraint)) ]

		state.constraints.extend(constraint)

	# now calculate constraints for the normal exit
	exits.append( [ irsb.jumpkind, last_imark, symbolic_irexpr.translate(irsb.next, state), state.constraints ] )

	return exits
