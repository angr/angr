#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import re
import sys

import logging
l = logging.getLogger("s_irop")

##########################
### Generic operations ###
##########################

def generic_Sub(state, args, size): #pylint:disable=W0613
    #l.debug("OP: %s - %s" % (args[0], args[1]))
    #l.debug("Sizes: %s, %s = %s", args[0].size(), args[1].size(), (args[0] - args[1]).size())
    return args[0] - args[1]

def generic_Add(state, args, size): #pylint:disable=W0613
    #l.debug("OP: %s - %s" % (args[0], args[1]))
    return args[0] + args[1]

def generic_Mul(state, args, size): #pylint:disable=W0613
    return args[0] * args[1]

def generic_Xor(state, args, size): #pylint:disable=W0613
    return args[0] ^ args[1]

def generic_And(state, args, size): #pylint:disable=W0613
    return args[0] & args[1]
generic_AndV = generic_And

def generic_Or(state, args, size): #pylint:disable=W0613
    return args[0] | args[1]

def generic_Not(state, args, size): #pylint:disable=W0613
    return ~args[0]

def generic_Shl(state, args, size): #pylint:disable=W0613
    return args[0] << state.se.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_Shr(state, args, size): #pylint:disable=W0613
    return state.se.LShR(args[0], state.se.ZeroExt(args[0].size() - args[1].size(), args[1]))

def generic_MullS(state, args, size): #pylint:disable=W0613
    # TODO: not sure if this should be extended *before* or *after* multiplication
    return state.se.SignExt(size, args[0] * args[1])

def generic_MullU(state, args, size): #pylint:disable=W0613
    # TODO: not sure if this should be extended *before* or *after* multiplication
    return state.se.ZeroExt(size, args[0]) * state.se.ZeroExt(size, args[1])

def generic_DivS(state, args, size): #pylint:disable=W0613
    # TODO: not sure if this should be extended *before* or *after* multiplication
    try:
        return args[0] / args[1]
    except ZeroDivisionError:
        return state.BVV(0, size)

def generic_DivU(state, args, size): #pylint:disable=W0613
    # TODO: not sure if this should be extended *before* or *after* multiplication
    # TODO: Make it unsigned division
    try:
        return args[0] / args[1]
    except ZeroDivisionError:
        return state.BVV(0, size)

# Count the leading zeroes
def generic_Clz(state, args, size):
    wtf_expr = state.se.BitVecVal(size, size)
    for a in range(size):
        bit = state.se.Extract(a, a, args[0])
        wtf_expr = state.se.If(bit == 1, state.BVV(size - a - 1, size), wtf_expr)
    return wtf_expr

# Count the trailing zeroes
def generic_Ctz(state, args, size):
    wtf_expr = state.se.BitVecVal(size, size)
    for a in reversed(range(size)):
        bit = state.se.Extract(a, a, args[0])
        wtf_expr = state.se.If(bit == 1, state.BVV(a, size), wtf_expr)
    return wtf_expr

def generic_Sar(state, args, size): #pylint:disable=W0613
    return args[0] >> state.se.ZeroExt(args[0].size() - args[1].size(), args[1])

def generic_CmpEQ(state, args, size): #pylint:disable=W0613
    return state.se.If(args[0] == args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

def generic_CmpNE(state, args, size): #pylint:disable=W0613
    return state.se.If(args[0] != args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
generic_ExpCmpNE = generic_CmpNE

def generic_CasCmpEQ(state, args, size):
    return generic_CmpEQ(state, args, size)

def generic_CasCmpNE(state, args, size):
    return generic_CmpNE(state, args, size)

##################################
# PowerPC operations
##################################
def generic_CmpORDS(state, args, size):
    x = args[0]
    y = args[1]
    return state.se.If(x == y, state.se.BitVecVal(0x2, size), state.se.If(x < y, state.se.BitVecVal(0x8, size), state.se.BitVecVal(0x4, size)))

def generic_CmpORDU(state, args, size):
    x = args[0]
    y = args[1]
    return state.se.If(x == y, state.se.BitVecVal(0x2, size), state.se.If(state.se.ULT(x, y), state.se.BitVecVal(0x8, size), state.se.BitVecVal(0x4, size)))

def generic_CmpLEU(state, args, size): #pylint:disable=W0613
    # This is UNSIGNED, so we use ULE
    return state.se.If(state.se.ULE(args[0], args[1]), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

def generic_CmpLTU(state, args, size): #pylint:disable=W0613
    # This is UNSIGNED, so we use ULT
    return state.se.If(state.se.ULT(args[0], args[1]), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

def generic_CmpLES(state, args, size): #pylint:disable=W0613
    return state.se.If(args[0] <= args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

def generic_CmpLTS(state, args, size): #pylint:disable=W0613
    return state.se.If(args[0] < args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

############################
# Other generic operations #
############################

def generic_narrow(state, args, from_size, to_size, part):
    if part == "":
        to_start = 0
    elif part == "HI":
        to_start = from_size / 2

    n = state.se.Extract(to_start + to_size - 1, to_start, args[0])
    #l.debug("Narrowed expression: %s" % n)
    return n

def generic_widen(state, args, from_size, to_size, signed):
    if signed == "U":
        return state.se.ZeroExt(to_size - from_size, args[0])
    elif signed == "S":
        return state.se.SignExt(to_size - from_size, args[0])

def generic_concat(state, args):
    return state.se.Concat(*args)

# TODO: Iop_DivModU128to64

#########################
### Vector Operations ###
#########################

def generic_UtoV(state, args, from_size, to_size):
    op_bytes = [ ]

    if from_size > to_size * 2:
        op_bytes.append(state.se.BitVecVal(0, from_size - to_size*2))

    for i in range(from_size, 0, -8):
        op_bytes.append(state.se.BitVecVal(0, 8))
        op_bytes.append(state.se.Extract(i-1, i-8, args[0]))

    return state.se.Concat(*op_bytes)

# TODO: make sure this is correct
def handler_InterleaveLO8x16(state, args):
    op_bytes = [ ]

    for i in range(64, 0, -8):
        op_bytes.append(state.se.Extract(i-1, i-8, args[1]))
        op_bytes.append(state.se.Extract(i-1, i-8, args[0]))

    return state.se.Concat(*op_bytes)

def handler_CmpEQ8x16(state, args):
    cmp_bytes = [ ]
    for i in range(128, 0, -8):
        a = state.se.Extract(i-1, i-8, args[0])
        b = state.se.Extract(i-1, i-8, args[1])
        cmp_bytes.append(state.se.If(a == b, state.se.BitVecVal(0xff, 8), state.se.BitVecVal(0, 8)))
    return state.se.Concat(*cmp_bytes)

def handler_GetMSBs8x16(state, args):
    bits = [ ]
    for i in range(128, 0, -8):
        bits.append(state.se.Extract(i-1, i-1, args[0]))
    return state.se.Concat(*bits)

def generic_XorV(state, args, size):
    return generic_Xor(state, args, size)

##################################
## This might be wrong as fuck ###
##################################
def handler_DivModU128to64(state, args):
    #import ipdb;ipdb.set_trace()
    a = args[0]
    b = args[1]
    b = state.se.ZeroExt(a.size() - b.size(), b)
    try:
        q  =a/b
        r = a%b
        quotient = state.se.Extract(63,0,q)
        remainder = state.se.Extract(63,0,r)
        result = state.se.Concat(remainder, quotient)
        return result
    except ZeroDivisionError:
        return state.BVV(0, 128)
#-----------------------------------------

def handler_DivModS64to32(state, args):
    #import ipdb;ipdb.set_trace()
    a = args[0]
    b = args[1]
    b = state.se.SignExt(a.size() - b.size(), b)
    try:
        q  =a/b
        r = a%b
        quotient = state.se.Extract(31,0,q)
        remainder = state.se.Extract(31,0,r)
        result = state.se.Concat(remainder, quotient)
        return result
    except ZeroDivisionError:
        return state.BVV(0, 64)
#-----------------------------------------

def handler_DivModU64to32(state, args):
    #import ipdb;ipdb.set_trace()
    a = args[0]
    b = args[1]
    b = state.se.ZeroExt(a.size() - b.size(), b)
    try:
        q  =a/b
        r = a%b
        quotient = state.se.Extract(31,0,q)
        remainder = state.se.Extract(31,0,r)
        result = state.se.Concat(remainder, quotient)
        return result
    except ZeroDivisionError:
        return state.BVV(0, 64)
#-----------------------------------------

###########################
### Specific operations ###
###########################

op_handlers = { }
op_handlers["Iop_InterleaveLO8x16"] = handler_InterleaveLO8x16
op_handlers["Iop_InterleaveLO8x16"] = handler_InterleaveLO8x16
op_handlers["Iop_CmpEQ8x16"] = handler_CmpEQ8x16
op_handlers["Iop_GetMSBs8x16"] = handler_GetMSBs8x16
op_handlers["Iop_DivModU128to64"] = handler_DivModU128to64
op_handlers["Iop_DivModS64to32"] = handler_DivModS64to32
op_handlers["Iop_DivModU64to32"] = handler_DivModU64to32

##################
### Op Handler ###
##################
def translate(state, op, s_args):
    # specific ops
    if op in op_handlers:
        l.debug("Calling %s", op_handlers)
        e = op_handlers[op](state, s_args)
        return e

    # widening
    m = re.match(r"Iop_(\d+)(S|U)to(\d+)", op)
    if m:
        f = int(m.group(1))
        s = m.group(2)
        t = int(m.group(3))
        l.debug("Calling generic_widen(args, %s, %s, '%s') for %s", f, t, s, op)
        return generic_widen(state, s_args, int(f), int(t), s)

    # narrowing
    m = re.match(r"Iop_(V|)(\d+)(HI|)to(\d+)", op)
    if m:
        f = int(m.group(2))
        p = m.group(3)
        t = int(m.group(4))
        l.debug("Calling generic_narrow(args, %s, %s, '%s') for %s", f, t, p, op)
        return generic_narrow(state, s_args, int(f), int(t), p)

    # concatenation
    m = re.match(r"Iop_(\d+)HLto(V|)(\d+)", op)
    if m:
        l.debug("Calling generic_concat(args) for %s", op)
        return generic_concat(state, s_args)

    # U to V conversions
    m = re.match(r"Iop_(\d+)UtoV(\d+)", op)
    if m:
        from_size = int(m.group(1))
        to_size = int(m.group(2))

        l.debug("Calling generic_UtoV(args, %d, %d) for %s", op, from_size, to_size)
        return generic_UtoV(state, s_args, from_size, to_size)

    # other generic ops
    m = re.match(r"Iop_(\D+)(\d+)([SU]{0,1})", op)
    if m:
        name = m.group(1)
        size = int(m.group(2))
        signed = m.group(3) # U - unsigned, S - signed, '' - unspecified

        func_name = "generic_" + name + signed
        if hasattr(sys.modules[__name__], func_name):
            l.debug("Calling %s", func_name)
            e = getattr(sys.modules[__name__], func_name)(state, s_args, size)
            return e

    l.error("Unsupported operation: %s", op)
    raise UnsupportedIROpError("Unsupported operation: %s" % op)

from .s_errors import UnsupportedIROpError
