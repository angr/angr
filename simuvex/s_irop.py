#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import re
import sys
import collections

import logging
l = logging.getLogger("simuvex.s_irop")

import pyvex
import claripy

#
# The more sane approach
#

def op_attrs(p):
    m = re.match(r'^Iop_' \
              r'(?P<generic_name>\D+?)??' \
              r'(?P<from_type>I|F|D|V)??' \
              r'(?P<from_signed>U|S)??' \
              r'(?P<from_size>\d+)??' \
              r'(?P<from_signed_back>U|S)??' \
              # this screws up CmpLE: r'(?P<e_flag>E)??' \
              r'('
                r'(?P<from_side>HL|HI|L|LO)??' \
                r'(?P<conversion>to)' \
                r'(?P<to_type>I|F|D|V)??' \
                r'(?P<to_size>\d+)??' \
                r'(?P<to_signed>U|S)??' \
              r')??'
              r'(?P<vector_info>\d+U?S?F?0?x\d+)?$', \
              p)

    if not m:
        l.debug("Unmatched operation: %s", p)
        return None
    else:
        l.debug("Matched operation: %s", p)
        attrs = m.groupdict()

        attrs['from_signed'] = attrs['from_signed_back'] if attrs['from_signed'] is None else attrs['from_signed']
        attrs.pop('from_signed_back', None)

        # fix up vector stuff
        vector_info = attrs.pop('vector_info', None)
        if vector_info:
            vm = re.match(r'^(?P<vector_size>\d+)?' \
                 r'(?P<vector_signed>U|S)?' \
                 r'(?P<vector_type>F|D)?' \
                 r'(?P<vector_zero>0)?' \
     r'x' \
                 r'(?P<vector_count>\d+)?$', \
                 vector_info)
            attrs.update(vm.groupdict())

        for k,v in attrs.items():
            if v is not None and v != "":
                l.debug("... %s: %s", k, v)

        return attrs

all_operations = pyvex.enum_IROp_fromstr.keys()
operations = { }
classified = set()
unclassified = set()
unsupported = set()

def make_operations():
    for p in all_operations:
        if p in ('Iop_INVALID', 'Iop_LAST'):
            continue

        attrs = op_attrs(p)
        if attrs is None:
            unclassified.add(p)
        else:
            classified.add(p)
            try:
                operations[p] = SimIROp(p, **attrs)
            except SimOperationError:
                unsupported.add(p)

    l.debug("%d matched (%d supported) and %d unmatched operations", len(classified), len(operations), len(unclassified))


arithmetic_operation_map = {
    'Add': '__add__',
    'Sub': '__sub__',
    'Mull': '__mul__',
    'Mul': '__mul__',
    'Div': '__div__',
}
shift_operation_map = {
    'Shl': '__lshift__',
    'Shr': '__rlshift__',
    'Sar': '__rshift__',
}
bitwise_operation_map = {
    'Xor': '__xor__',
    'Or': '__or__',
    'And': '__and__',
    'Not': '__invert__',
}

generic_names = set()
conversions = collections.defaultdict(list)
add_operations = [ ]
other_operations = [ ]
vector_operations = [ ]
class SimIROp(object):
    def __init__(self, name, **attrs):
        l.debug("Creating SimIROp(%s)", name)
        self.name = name
        self.op_attrs = attrs

        self._generic_name = None
        self._from_size = None
        self._from_side = None
        self._from_type = None
        self._from_signed = None
        self._to_size = None
        self._to_type = None
        self._to_signed = None
        self._conversion = None
        self._vector_size = None
        self._vector_signed = None
        self._vector_type = None
        self._vector_zero = None
        self._vector_count = None

        for k,v in self.op_attrs.items():
            if v is not None and ('size' in k or 'count' in k):
                v = int(v)
            setattr(self, '_%s'%k, v)

        # determine the output size
        #pylint:disable=no-member
        i = pyvex.IRSB()
        i.tyenv.newTemp("Ity_I8")
        self._output_type = i.tyenv.typeOf(pyvex.IRExpr.Unop(name, pyvex.IRExpr.RdTmp(0)))
        #pylint:enable=no-member
        self._output_size_bits = size_bits(self._output_type)
        self._output_signed = False
        l.debug("... VEX says the output size should be %s", self._output_size_bits)

        size_check = self._to_size is None or (self._to_size*2 if self._generic_name == 'DivMod' else self._to_size) == self._output_size_bits
        if not size_check:
            raise SimOperationError("VEX output size doesn't match detected output size")

        generic_names.add(self._generic_name)
        if self._conversion is not None:
            conversions[(self._from_type, self._from_signed, self._to_type, self._to_signed)].append(self)

        if len({self._vector_type, self._from_type, self._to_type} & {'F', 'D'}) != 0:
            l.debug('... aborting on floating point!')
            raise UnsupportedIROpError('floating point operations are not supported')

        #
        # Now determine the operation
        #

        self._calculate = None

        # if the generic name is None and there's a conversion present, this is a standard
        # widening or narrowing or sign-extension
        if self._generic_name is None and self._conversion:
            # this concatenates the args into the high and low halves of the result
            if self._from_side == 'HL':
                l.debug("... using simple concat")
                self._calculate = self._op_concat

            # this just returns the high half of the first arg
            elif self._from_size > self._to_size and self._from_side == 'HI':
                l.debug("... using hi half")
                self._calculate = self._op_hi_half

            # this just returns the high half of the first arg
            elif self._from_size > self._to_size and self._from_side in ('L', 'LO'):
                l.debug("... using lo half")
                self._calculate = self._op_lo_half

            elif self._from_size > self._to_size and self._from_side is None:
                l.debug("... just extracting")
                self._calculate = self._op_extract

            elif self._from_size < self._to_size and self._from_signed == "S":
                l.debug("... using simple sign-extend")
                self._calculate = self._op_sign_extend

            elif self._from_size < self._to_size and self._from_signed == "U":
                l.debug("... using simple zero-extend")
                self._calculate = self._op_zero_extend

            else:
                l.error("%s is an unexpected conversion operation configuration", self)
                assert False

        # other conversions
        elif self._conversion:
            if self._generic_name == "DivMod":
                l.debug("... using divmod")
                self._calculate = self._op_divmod
            else:
                raise UnsupportedIROpError("complex conversion operations are not yet supported")

        # generic bitwise
        elif self._generic_name in bitwise_operation_map:
            l.debug("... using generic mapping op")
            assert self._from_side is None
            self._calculate = self._op_mapped

        # generic mapping operations
        elif self._generic_name in arithmetic_operation_map or self._generic_name in shift_operation_map and self._vector_count is None:
            l.debug("... using generic mapping op")
            assert self._from_side is None
            self._calculate = self._op_mapped

        # unsupported vector ops
        elif self._vector_size is not None:
            vector_operations.append(name)

        # specifically-implemented generics
        elif hasattr(self, '_op_generic_%s' % self._generic_name):
            l.debug("... using generic method")
            self._calculate = getattr(self, '_op_generic_%s' % self._generic_name)

        else:
            other_operations.append(name)

        if self._calculate is None:
            l.debug("... can't support operations")
            raise UnsupportedIROpError("no calculate function identified for %s" % self.name)

    def __repr__(self):
        return "<SimIROp %s>" % self.name

    #pylint:disable=no-self-use,unused-argument
    def _op_mapped(self, state, args):
        sized_args = [ ]
        for a in args:
            s = a.size()
            if s == self._from_size:
                sized_args.append(a)
            elif s < self._from_size:
                if self._from_signed == "S":
                    sized_args.append(state.se.SignExt(self._from_size - s, a))
                else:
                    sized_args.append(state.se.ZeroExt(self._from_size - s, a))
            elif s > self._from_size:
                raise SimOperationError("operation %s received too large an argument")

        if self._generic_name in bitwise_operation_map:
            o = bitwise_operation_map[self._generic_name]
        elif self._generic_name in arithmetic_operation_map:
            o = arithmetic_operation_map[self._generic_name]
        elif self._generic_name in shift_operation_map:
            o = shift_operation_map[self._generic_name]
        else:
            raise SimOperationError("op_mapped called with invalid mapping, for %s" % self.name)

        return state.se._claripy._do_op(o, sized_args)

    def _op_concat(self, state, args):
        return state.se.Concat(*args)

    def _op_hi_half(self, state, args):
        return state.se.Extract(args[0].size()-1, args[0].size()/2, args[0])

    def _op_lo_half(self, state, args):
        return state.se.Extract(args[0].size()/2 - 1, 0, args[0])

    def _op_extract(self, state, args):
        return state.se.Extract(self._to_size - 1, 0, args[0])

    def _op_sign_extend(self, state, args):
        return state.se.SignExt(self._to_size - args[0].size(), args[0])

    def _op_zero_extend(self, state, args):
        return state.se.ZeroExt(self._to_size - args[0].size(), args[0])

    def _op_generic_Clz(self, state, args):
        '''Count the leading zeroes'''
        wtf_expr = state.se.BitVecVal(self._from_size, self._from_size)
        for a in range(self._from_size):
            bit = state.se.Extract(a, a, args[0])
            wtf_expr = state.se.If(bit==1, state.BVV(self._from_size-a-1, self._from_size), wtf_expr)
        return wtf_expr

    def _op_generic_Ctz(self, state, args):
        '''Count the trailing zeroes'''
        wtf_expr = state.se.BitVecVal(self._from_size, self._from_size)
        for a in reversed(range(self._from_size)):
            bit = state.se.Extract(a, a, args[0])
            wtf_expr = state.se.If(bit == 1, state.BVV(a, self._from_size), wtf_expr)
        return wtf_expr

    def _op_generic_CmpEQ(self, state, args):
        return state.se.If(args[0] == args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
    _op_generic_CasCmpEQ = _op_generic_CmpEQ

    def _op_generic_CmpNE(self, state, args):
        return state.se.If(args[0] != args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))
    _op_generic_ExpCmpNE = _op_generic_CmpNE
    _op_generic_CasCmpNE = _op_generic_CmpNE

    def _op_generic_CmpORDS(self, state, args):
        x = args[0]
        y = args[1]
        return state.se.If(x == y, state.se.BitVecVal(0x2, self._from_size), state.se.If(x < y, state.se.BitVecVal(0x8, self._from_size), state.se.BitVecVal(0x4, self._from_size)))

    def _op_generic_CmpORDU(self, state, args):
        x = args[0]
        y = args[1]
        return state.se.If(x == y, state.se.BitVecVal(0x2, self._from_size), state.se.If(state.se.ULT(x, y), state.se.BitVecVal(0x8, self._from_size), state.se.BitVecVal(0x4, self._from_size)))

    def _op_generic_CmpLEU(self, state, args):
        # This is UNSIGNED, so we use ULE
        return state.se.If(state.se.ULE(args[0], args[1]), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

    def _op_generic_CmpLTU(self, state, args):
        # This is UNSIGNED, so we use ULT
        return state.se.If(state.se.ULT(args[0], args[1]), state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

    def _op_generic_CmpLES(self, state, args):
        return state.se.If(args[0] <= args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

    def _op_generic_CmpLTS(self, state, args):
        return state.se.If(args[0] < args[1], state.se.BitVecVal(1, 1), state.se.BitVecVal(0, 1))

    def _op_divmod(self, state, args):
        # TODO: handle signdness
        try:
            quotient = (args[0] / state.se.ZeroExt(self._from_size - self._to_size, args[1]))
            remainder = (args[0] % state.se.ZeroExt(self._from_size - self._to_size, args[1]))
            quotient_size = self._to_size
            remainder_size = self._to_size
            return state.se.Concat(
                state.se.Extract(remainder_size - 1, 0, remainder),
                state.se.Extract(quotient_size - 1, 0, quotient)
            )
        except ZeroDivisionError:
            return state.BVV(0, self._to_size)
    #pylint:enable=no-self-use,unused-argument



    def _dbg_print_attrs(self):
        print "Operation: %s" % self.name
        for k,v in self.op_attrs.items():
            if v is not None and v != "":
                print "... %s: %s" % (k, v)

    def calculate(self, state, *args):
        if not all(isinstance(a, claripy.E) for a in args):
            raise SimOperationError("IROp needs all args as claripy expressions")

        try:
            return self.extend_size(state, self._calculate(state, args))
        except (TypeError, ValueError):
            e_type, value, traceback = sys.exc_info()
            raise SimOperationError, ("%s._calculate() raised exception" % self.name, e_type, value), traceback
        except ZeroDivisionError:
            return SimOperationError("divide by zero!")

    def extend_size(self, state, o):
        cur_size = o.size()
        if cur_size < self._output_size_bits:
            l.debug("Extending output of %s from %d to %d bits", self.name, cur_size, self._output_size_bits)
            ext_size = self._output_size_bits - cur_size
            if not self._output_signed: return state.se.ZeroExt(ext_size, o)
            else: return state.se.SignExt(ext_size, o)
        elif cur_size > self._output_size_bits:
            __import__('ipdb').set_trace()
        else:
            return o

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

##################
### Op Handler ###
##################
def translate(state, op, s_args):
    if op in operations:
        return operations[op].calculate(state, *s_args)

    l.error("Unsupported operation: %s", op)
    raise UnsupportedIROpError("Unsupported operation: %s" % op)

from .s_errors import UnsupportedIROpError, SimOperationError
from .s_helpers import size_bits

make_operations()
