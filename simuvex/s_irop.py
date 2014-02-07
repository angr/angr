#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import symexec
import re
import sys

import logging
l = logging.getLogger("s_irop")

class UnsupportedIROpType(Exception):
	pass

##########################
### Generic operations ###
##########################

def generic_Sub(args, size):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	#l.debug("Sizes: %s, %s = %s", args[0].size(), args[1].size(), (args[0] - args[1]).size())
	return args[0] - args[1]

def generic_Add(args, size):
	#l.debug("OP: %s - %s" % (args[0], args[1]))
	return args[0] + args[1]

def generic_Mul(args, size):
	return args[0] * args[1]

def generic_Xor(args, size):
	return args[0] ^ args[1]

def generic_And(args, size):
	return args[0] & args[1]

def generic_Or(args, size):
	return args[0] | args[1]

def generic_Not(args, size):
	return ~args[0]

def generic_Shl(args, size):
	return args[0] << symexec.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_Shr(args, size):
	return symexec.LShR(args[0], symexec.ZeroExt(args[0].size() - args[1].size(), args[1]))

def generic_MullS(args, size):
	# TODO: not sure if this should be extended *before* or *after* multiplication
	return symexec.SignExt(size, args[0] * args[1])

def generic_MullU(args, size):
	# TODO: not sure if this should be extended *before* or *after* multiplication
	return symexec.ZeroExt(size, args[0]) * symexec.ZeroExt(size, args[1])

def generic_DivS(args, size):
	# TODO: not sure if this should be extended *before* or *after* multiplication
	return args[0] / args[1]

# Count the leading zeroes
def generic_Clz(args, size):
	wtf_expr = symexec.BitVecVal(size, size)
	for a in range(size):
		bit = symexec.Extract(a, a, wtf_expr)
		wtf_expr = symexec.If(bit == 1, size - a - 1, wtf_expr)
	return wtf_expr


def generic_Sar(args, size):
	return args[0] >> symexec.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_CmpEQ(args, size):
	return symexec.If(args[0] == args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpNE(args, size):
	return symexec.If(args[0] != args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CasCmpEQ(args, size):
	return generic_CmpEQ(args, size)

def generic_CasCmpNE(args, size):
	return generic_CmpNE(args, size)

##################################
# PowerPC operations
##################################
def generic_CmpORDS(args, size):
	# TODO: Handle signed bit
	if args[0] < args[1]:
		return symexec.BitVecVal(0x8, size)
	elif args[0] > args[1]:
		return symexec.BitVecVal(0x4, size)
	else:
		return symexec.BitVecVal(0x2, size)

def generic_CmpORDU(args, size):
	if args[0] < args[1]:
		return symexec.BitVecVal(0x8, size)
	elif args[0] > args[1]:
		return symexec.BitVecVal(0x4, size)
	else:
		return symexec.BitVecVal(0x2, size)

def generic_CmpLEU(args, size):
	# TODO: Is this correct? I cannot find any documentation about how to implement CmpLE32U
	return symexec.If(args[0] <= args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpLTU(args, size):
	# TODO: Is this correct? I cannot find any documentation about how to implement CmpLT32U
	return symexec.If(args[0] < args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_narrow(args, from_size, to_size, part):
	if part == "":
		to_start = 0
	elif part == "HI":
		to_start = from_size / 2

	n = symexec.Extract(to_start + to_size - 1, to_start, args[0])
	#l.debug("Narrowed expression: %s" % n)
	return n

def generic_widen(args, from_size, to_size, signed):
	if signed == "U":
		return symexec.ZeroExt(to_size - from_size, args[0])
	elif signed == "S":
		return symexec.SignExt(to_size - from_size, args[0])

def generic_concat(args):
	return symexec.Concat(args)

# TODO: Iop_DivModU128to64

###########################
### Specific operations ###
###########################

op_handlers = { }

##################
### Op Handler ###
##################
def translate(op, s_args):
	# specific ops
	if op in op_handlers:
		l.debug("Calling %s" % op_handlers)
		e = op_handlers[op](s_args)
		return e

	# widening
	m = re.match("Iop_(\d+)(S|U)to(\d+)", op)
	if m:
		f = m.group(1)
		s = m.group(2)
		t = m.group(3)
		l.debug("Calling generic_widen(args, %s, %s, '%s', state) for %s" % (f, t, s, op))
		return generic_widen(s_args, int(f), int(t), s)

	# narrowing
	m = re.match("Iop_(\d+)(HI|)to(\d+)", op)
	if m:
		f = m.group(1)
		p = m.group(2)
		t = m.group(3)
		l.debug("Calling generic_narrow(args, %s, %s, '%s', state) for %s" % (f, t, p, op))
		return generic_narrow(s_args, int(f), int(t), p)

	# concatenation
	m = re.match("Iop_(\d+)HLto(\d+)", op)
	if m:
		l.debug("Calling generic_concat(args, state) for %s" % (op))
		return generic_concat(s_args)

	# other generic ops
	m = re.match("Iop_(\D+)(\d+)([SU]{0,1})", op)
	if m:
		name = m.group(1)
		size = int(m.group(2))
		signed = m.group(3) # U - unsigned, S - signed, '' - unspecified

		func_name = "generic_" + name + signed
		if hasattr(sys.modules[__name__], func_name):
			l.debug("Calling %s" % func_name)
			e = getattr(sys.modules[__name__], func_name)(s_args, size)
			return e

	raise UnsupportedIROpType("Unsupported operation: %s" % op)
