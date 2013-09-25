#!/usr/bin/env python
'''This module handles constraint generation.'''

import z3
import pyvex
import symbolic_irstmt

z3.init("/opt/python/lib/libz3.so")

######################
### Symbolic state ###
######################
import collections
state = collections.namedtuple("State", ("symbols", "registers", "memory", "constraints", "irsb_stack"))
state.symbols = [ ]
state.constraints = [ ]
state.registers = { }
state.memory = { }
state.irsb_stack = [ ]

########################
### Helper functions ###
########################

def get_size(t):
	for s in 64, 32, 16, 8, 4, 2, 1:
		if str(s) in t:
			return s
	raise Exception("Unable to determine length of %s." % t)


def translate(irsb):
	state.irsb_stack.append(irsb)

	# we will use the VEX temps for the symbolic variables
	for n, t in enumerate(irsb.tyenv.types()):
		state.symbols.append(z3.BitVec('t%d' % n, get_size(t)))

	# now get the constraints
	for stmt in irsb.statements():
		state.constraints.extend(symbolic_irstmt.translate(stmt, state))
