#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import symexec
import re
import sys

import logging
l = logging.getLogger("s_irop")

class UnsupportedIROpType(Exception):
	pass

# TODO: FIXME: the following ops need to be rewritten to work properly
#				in symbolic mode (ie, add constraints)
#
#	Clz, Ctz, CmpEQ, CmpNE, CmpORDS, CmpORDU, CmpLEU, CmpLTU, CmpLES, CmpLTS, CmpEQ8x16

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

def generic_DivU(args, size):
	# TODO: not sure if this should be extended *before* or *after* multiplication
	# TODO: Make it unsigned division
	return args[0] / args[1]

# Count the leading zeroes
def generic_Clz(args, size):
	wtf_expr = symexec.BitVecVal(size, size)
	for a in range(size):
		bit = symexec.Extract(a, a, args[0])
		wtf_expr = symexec.If(bit == 1, size - a - 1, wtf_expr)
	return wtf_expr

# Count the trailing zeroes
def generic_Ctz(args, size):
	wtf_expr = symexec.BitVecVal(size, size)
	for a in reversed(range(size)):
		bit = symexec.Extract(a, a, args[0])
		wtf_expr = symexec.If(bit == 1, a, wtf_expr)
	return wtf_expr

def generic_Sar(args, size):
	return args[0] >> symexec.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_CmpEQ(args, size):
	return symexec.If(args[0] == args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpNE(args, size):
	return symexec.If(args[0] != args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))
generic_ExpCmpNE = generic_CmpNE

def generic_CasCmpEQ(args, size):
	return generic_CmpEQ(args, size)

def generic_CasCmpNE(args, size):
	return generic_CmpNE(args, size)

##################################
# PowerPC operations
##################################
def generic_CmpORDS(args, size):
	x = args[0]
	y = args[1]
	return symexec.If(x == y, symexec.BitVecVal(0x2, size), symexec.If(x < y, symexec.BitVecVal(0x8, size), symexec.BitVecVal(0x4, size)))

def generic_CmpORDU(args, size):
	x = args[0]
	y = args[1]
	return symexec.If(x == y, symexec.BitVecVal(0x2, size), symexec.If(symexec.ULT(x, y), symexec.BitVecVal(0x8, size), symexec.BitVecVal(0x4, size)))

def generic_CmpLEU(args, size):
	# This is UNSIGNED, so we use ULE
	return symexec.If(symexec.ULE(args[0], args[1]), symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpLTU(args, size):
	# This is UNSIGNED, so we use ULT
	return symexec.If(symexec.ULT(args[0], args[1]), symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpLES(args, size):
	return symexec.If(args[0] <= args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

def generic_CmpLTS(args, size):
	return symexec.If(args[0] < args[1], symexec.BitVecVal(1, 1), symexec.BitVecVal(0, 1))

############################
# Other generic operations #
############################

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

#########################
### Vector Operations ###
#########################

def generic_UtoV(args, from_size, to_size):
	bytes = [ ]

	if from_size > to_size * 2:
		bytes.append(symexec.BitVecVal(0, from_size - to_size*2))

	for i in range(from_size, 0, -8):
		bytes.append(symexec.BitVecVal(0, 8))
		bytes.append(symexec.Extract(i-1, i-8, args[0]))

	return symexec.Concat(bytes)

# TODO: make sure this is correct
def handler_InterleaveLO8x16(args):
	bytes = [ ]

	for i in range(64, 0, -8):
		bytes.append(symexec.Extract(i-1, i-8, args[1]))
		bytes.append(symexec.Extract(i-1, i-8, args[0]))

	return symexec.Concat(bytes)

def handler_CmpEQ8x16(args):
	bytes = [ ]
	for i in range(128, 0, -8):
		a = symexec.Extract(i-1, i-8, args[0])
		b = symexec.Extract(i-1, i-8, args[1])
		bytes.append(symexec.If(a == b, symexec.BitVecVal(0xff, 8), symexec.BitVecVal(0, 8)))
	return symexec.Concat(bytes)

def handler_GetMSBs8x16(args):
	bits = [ ]
	for i in range(128, 0, -8):
		bits.append(symexec.Extract(i-1, i-1, args[0]))
	return symexec.Concat(bits)

def generic_XorV(args, size):
	return generic_Xor(args, size)

###########################
### Specific operations ###
###########################

op_handlers = { }
op_handlers["Iop_InterleaveLO8x16"] = handler_InterleaveLO8x16
op_handlers["Iop_InterleaveLO8x16"] = handler_InterleaveLO8x16
op_handlers["Iop_CmpEQ8x16"] = handler_CmpEQ8x16
op_handlers["Iop_GetMSBs8x16"] = handler_GetMSBs8x16

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
		f = int(m.group(1))
		s = m.group(2)
		t = int(m.group(3))
		l.debug("Calling generic_widen(args, %s, %s, '%s') for %s" % (f, t, s, op))
		return generic_widen(s_args, int(f), int(t), s)

	# narrowing
	m = re.match("Iop_(V|)(\d+)(HI|)to(\d+)", op)
	if m:
		f = int(m.group(2))
		p = m.group(3)
		t = int(m.group(4))
		l.debug("Calling generic_narrow(args, %s, %s, '%s') for %s" % (f, t, p, op))
		return generic_narrow(s_args, int(f), int(t), p)

	# concatenation
	m = re.match("Iop_(\d+)HLto(V|)(\d+)", op)
	if m:
		l.debug("Calling generic_concat(args) for %s" % (op))
		return generic_concat(s_args)

	# U to V conversions
	m = re.match("Iop_(\d+)UtoV(\d+)", op)
	if m:
		from_size = int(m.group(1))
		to_size = int(m.group(2))

		l.debug("Calling generic_UtoV(args, %d, %d) for %s", op, from_size, to_size)
		return generic_UtoV(s_args, from_size, to_size)

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
