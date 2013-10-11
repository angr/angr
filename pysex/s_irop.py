#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import z3
import re
import sys
import s_irexpr

import logging
l = logging.getLogger("s_irop")
#l.setLevel(logging.DEBUG)

##########################
### Generic operations ###
##########################

def generic_Sub(args, size, state):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	#l.debug("Sizes: %s, %s = %s", args[0].size(), args[1].size(), (args[0] - args[1]).size())
	return args[0] - args[1]

def generic_Add(args, size, state):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	return args[0] + args[1]

def generic_Xor(args, size, state):
	return args[0] ^ args[1]

def generic_And(args, size, state):
	return args[0] & args[1]

def generic_Shl(args, size, state):
	return args[0] << z3.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_Shr(args, size, state):
	return z3.LShR(args[0], z3.ZeroExt(args[0].size() - args[1].size(), args[1]))

def generic_MullS(args, size, state):
	# TODO: not sure if this should be extended *before* or *after* multiplication
	return z3.SignExt(size, args[0] * args[1])

def generic_Sar(args, size, state):
	return args[0] >> z3.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_narrow(args, from_size, to_size, part, state):
	if part == "":
		to_start = 0
	elif part == "HI":
		to_start = from_size / 2

	n = z3.Extract(to_start + to_size - 1, to_start, args[0])
	l.debug("Narrowed expression: %s" % n)
	return n

def generic_widen(args, from_size, to_size, signed, state):
	if signed == "U":
		return z3.ZeroExt(to_size - from_size, args[0])
	elif signed == "S":
		return z3.SignExt(to_size - from_size, args[0])

def generic_concat(args, state):
	return z3.Concat(args)

###########################
### Specific operations ###
###########################

op_handlers = { }

##################
### Op Handler ###
##################
def translate(op, args, state):
	s_args, s_constraints = zip(*[ s_irexpr.translate(a, state) for a in args ])
	s_constraints = sum(s_constraints[0], [])

	# specific ops
	if op in op_handlers:
		l.debug("Calling %s" % op_handlers)
		e = op_handlers[op](s_args, state)
		l.debug("Generated expression: %s" % e)
		return e, s_constraints

	# widening
	m = re.match("Iop_(\d+)(S|U)to(\d+)", op)
	if m:
		f = m.group(1)
		s = m.group(2)
		t = m.group(3)
		l.debug("Calling generic_widen(args, %s, %s, '%s', state) for %s" % (f, t, s, op))
		return generic_widen(s_args, int(f), int(t), s, state), s_constraints

	# narrowing
	m = re.match("Iop_(\d+)(HI|)to(\d+)", op)
	if m:
		f = m.group(1)
		p = m.group(2)
		t = m.group(3)
		l.debug("Calling generic_narrow(args, %s, %s, '%s', state) for %s" % (f, t, p, op))
		return generic_narrow(s_args, int(f), int(t), p, state), s_constraints

	# concatenation
	m = re.match("Iop_(\d+)HLto(\d+)", op)
	if m:
		l.debug("Calling generic_concat(args, state) for %s" % (op))
		return generic_concat(s_args, state), s_constraints

	# other generic ops
	m = re.match("Iop_(\D+)(\d+)", op)
	if m:
		name = m.group(1)
		size = int(m.group(2))

		func_name = "generic_" + name
		l.debug("Calling %s" % func_name)
		if hasattr(sys.modules[__name__], func_name):
			e = getattr(sys.modules[__name__], func_name)(s_args, size, state)
			l.debug("Generated expression: %s" % e)
			return e, s_constraints

	raise Exception("Unsupported operation: %s" % op)
