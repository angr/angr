#!/usr/bin/env python
'''This module includes some helper functions to avoid recursive imports.'''

import z3

import logging
l = logging.getLogger("symbolic_helpers")
#l.setLevel(logging.DEBUG)

########################
### Helper functions ###
########################

def get_size(t):
	for s in 256, 128, 64, 32, 16, 8, 1:
		if str(s) in t:
			return s
	raise Exception("Unable to determine length of %s." % t)

def translate_irconst(c):
	size = get_size(c.type)
	t = type(c.value)
	if t == int or t == long:
		return z3.BitVecVal(c.value, size)
	raise Exception("Unsupported constant type: %s" % type(c.value))
