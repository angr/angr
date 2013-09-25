#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import z3
import re
import sys
import symbolic_irexpr

import logging
l = logging.getLogger("symbolic_irop")
l.setLevel(logging.DEBUG)

##########################
### Generic operations ###
##########################

def generic_Sub(args, size, state):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	return args[0] - args[1]

def generic_Add(args, size, state):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	return args[0] + args[1]

def handle_64to32(args, state):
	z3.Extract(63, 32, args[0])

op_handlers = { }
op_handlers["Iop_64to32"] = handle_64to32

##################
### Op Handler ###
##################
def translate(op, args, state):
	symbolic_args = [ symbolic_irexpr.translate(a, state) for a in args ]

	if op in op_handlers:
		l.debug("Calling %s" % op_handlers)
		constraints = op_handlers[op](symbolic_args, state)
		l.debug("Generated constraints: %s" % constraints)
		return constraints

	m = re.match("Iop_(\D*)(\d*)", op)
	name = m.group(1)
	size = int(m.group(2))

	func_name = "generic_" + name
	l.debug("Calling %s" % func_name)
	if hasattr(sys.modules[__name__], func_name):
		constraints = getattr(sys.modules[__name__], func_name)(symbolic_args, size, state)
		l.debug("Generated constraints: %s" % constraints)
		return constraints

	raise Exception("Unsupported operation: %s" % op)
