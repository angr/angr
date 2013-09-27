#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import symbolic_irstmt

import logging
l = logging.getLogger("symbolic_irstmt")
l.setLevel(logging.DEBUG)

z3.init("/opt/python/lib/libz3.so")

######################
### Symbolic state ###
######################
import collections
state = collections.namedtuple("State", ("temps", "registers", "memory", "constraints", "irsb_stack"))
state.temps = { }
state.constraints = [ ]
state.registers = { }
state.memory = { }
state.irsb_stack = [ ]

########################
### Helper functions ###
########################

def get_size(t):
	for s in 64, 32, 16, 8, 1:
		if str(s) in t:
			return s
	raise Exception("Unable to determine length of %s." % t)


def translate(irsb):
	state.irsb_stack.append(irsb)

	# we will use the VEX temps for the symbolic variables
	for n, t in enumerate(irsb.tyenv.types()):
		state.temps[n] = z3.BitVec('t%d' % n, get_size(t))

	# now get the constraints
	for stmt in irsb.statements():
		constraint = symbolic_irstmt.translate(stmt, state)

		if type(stmt) == pyvex.IRStmt.Exit:
			l.info("Simplifying constraint for exit.")
			print state.constraints
			z3.solve(state.constraints)

		state.constraints.extend(constraint)
