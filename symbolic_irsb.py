#!/usr/bin/env python
'''This module handles constraint generation for IRSBs.'''

import z3
import pyvex
import symbolic_irstmt
import symbolic_helpers

import logging
l = logging.getLogger("symbolic_irsb")
l.setLevel(logging.DEBUG)

########################
### IRSB translation ###
########################

def translate(irsb, state):
	# we will use the VEX temps for the symbolic variables
	for n, t in enumerate(irsb.tyenv.types()):
		state.temps[n] = z3.BitVec('t%d' % n, symbolic_helpers.get_size(t))

	# now get the constraints
	for stmt in irsb.statements():
		constraint = symbolic_irstmt.translate(stmt, state)

		if type(stmt) == pyvex.IRStmt.Exit:
			l.info("Simplifying constraint for exit.")
			z3.solve(state.constraints + constraint)

			# let's not take the exit
			constraint = [ z3.Not(z3.And(*constraint)) ]

		state.constraints.extend(constraint)

	# now calculate constraints for the normal exit
	l.info("Simplifying constraints for end of block")
	z3.solve(state.constraints)
