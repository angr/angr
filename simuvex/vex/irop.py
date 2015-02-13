#!/usr/bin/python env
'''This module contains symbolic implementations of VEX operations.'''

import re
import sys
import collections
import itertools

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
        if attrs['generic_name'] == 'CmpOR':
            assert attrs['from_type'] == 'D'
            attrs['generic_name'] = 'CmpORD'
            attrs['from_type'] = None

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
    'Shr': 'LShR',
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
unsupported_conversions = [ ]
add_operations = [ ]
other_operations = [ ]
vector_operations = [ ]
fp_ops = set()
common_unsupported_generics = collections.Counter()

def supports_vector(f):
    f.supports_vector = True
    return f

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
        self._output_type = pyvex.typeOfIROp(name)
        #pylint:enable=no-member
        self._output_size_bits = size_bits(self._output_type)
        l.debug("... VEX says the output size should be %s", self._output_size_bits)

        size_check = self._to_size is None or (self._to_size*2 if self._generic_name == 'DivMod' else self._to_size) == self._output_size_bits
        if not size_check:
            raise SimOperationError("VEX output size doesn't match detected output size")


        #
        # Some categorization
        #

        generic_names.add(self._generic_name)
        if self._conversion is not None:
            conversions[(self._from_type, self._from_signed, self._to_type, self._to_signed)].append(self)

        #
        # Now determine the operation
        #

        self._calculate = None

        if len({self._vector_type, self._from_type, self._to_type} & {'F', 'D'}) != 0:
            l.debug('... aborting on floating point!')
            fp_ops.add(self.name)
            raise UnsupportedIROpError('floating point operations are not supported')

        # if the generic name is None and there's a conversion present, this is a standard
        # widening or narrowing or sign-extension
        elif self._generic_name is None and self._conversion:
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
                unsupported_conversions.append(self.name)
                common_unsupported_generics[self._generic_name] += 1

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

        # specifically-implemented generics
        elif hasattr(self, '_op_generic_%s' % self._generic_name):
            l.debug("... using generic method")
            calculate = getattr(self, '_op_generic_%s' % self._generic_name)
            if self._vector_size is not None and \
               not hasattr(calculate, 'supports_vector'):
                # unsupported vector ops
                vector_operations.append(name)
            else:
                self._calculate = calculate

        else:
            common_unsupported_generics[self._generic_name] += 1
            other_operations.append(name)


        # if we're here and calculate is None, we don't support this
        if self._calculate is None:
            l.debug("... can't support operations")
            raise UnsupportedIROpError("no calculate function identified for %s" % self.name)

    def __repr__(self):
        return "<SimIROp %s>" % self.name

    def _dbg_print_attrs(self):
        print "Operation: %s" % self.name
        for k,v in self.op_attrs.items():
            if v is not None and v != "":
                print "... %s: %s" % (k, v)

    def calculate(self, state, *args):
        if not all(isinstance(a, claripy.A) for a in args):
            raise SimOperationError("IROp needs all args as claripy expressions")

        try:
            return self.extend_size(state, self._calculate(state, args))
        except (TypeError, ValueError, SimValueError, claripy.ClaripyError):
            e_type, value, traceback = sys.exc_info()
            raise SimOperationError, ("%s._calculate() raised exception" % self.name, e_type, value), traceback
        except ZeroDivisionError:
            raise SimOperationError("divide by zero!")

    def extend_size(self, state, o):
        cur_size = o.size()
        if cur_size < self._output_size_bits:
            l.debug("Extending output of %s from %d to %d bits", self.name, cur_size, self._output_size_bits)
            ext_size = self._output_size_bits - cur_size
            if self._to_signed == 'S' or (self._from_signed == 'S' and self._to_signed == None):
                return state.se.SignExt(ext_size, o)
            else:
                return state.se.ZeroExt(ext_size, o)
        elif cur_size > self._output_size_bits:
            raise SimOperationError('output of %s is too big', self.name)
        else:
            return o

    #
    # The actual operation handlers go here.
    #

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

        return claripy.A(state.se._claripy, o, sized_args).reduced

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
        wtf_expr = state.se.BVV(self._from_size, self._from_size)
        for a in range(self._from_size):
            bit = state.se.Extract(a, a, args[0])
            wtf_expr = state.se.If(bit==1, state.BVV(self._from_size-a-1, self._from_size), wtf_expr)
        return wtf_expr

    def _op_generic_Ctz(self, state, args):
        '''Count the trailing zeroes'''
        wtf_expr = state.se.BVV(self._from_size, self._from_size)
        for a in reversed(range(self._from_size)):
            bit = state.se.Extract(a, a, args[0])
            wtf_expr = state.se.If(bit == 1, state.BVV(a, self._from_size), wtf_expr)
        return wtf_expr

    @supports_vector
    def _op_generic_Min(self, state, args):
        lt = (lambda a, b: a < b) if self._vector_signed == 'S' else (lambda a, b: state.se.ULT(a, b))
        smallest = state.se.Extract(self._vector_size - 1, 0, args[0])
        for i in range(1, self._vector_count):
            val = state.se.Extract((i + 1) * self._vector_size - 1,
                                   i * self._vector_size,
                                   args[0])
            smallest = state.se.If(lt(val, smallest), val, smallest)
        return smallest

    @supports_vector
    def _op_generic_Max(self, state, args):
        gt = (lambda a, b: a > b) if self._vector_signed == 'S' else (lambda a, b: state.se.UGT(a, b))
        largest = state.se.Extract(self._vector_size - 1, 0, args[0])
        for i in range(1, self._vector_count):
            val = state.se.Extract((i + 1) * self._vector_size - 1,
                                   i * self._vector_size,
                                   args[0])
            largest = state.se.If(gt(val, largest), val, largest)
        return largest

    @supports_vector
    def _op_generic_GetMSBs(self, state, args):
        size = self._vector_count * self._vector_size
        bits = [state.se.Extract(i, i, args[0]) for i in range(size - 1, 6, -8)]
        return state.se.Concat(*bits)

    @supports_vector
    def _op_generic_InterleaveLO(self, state, args):
        s = self._vector_size
        c = self._vector_count
        dst_vector = [ args[0][(i+1)*s-1:i*s] for i in xrange(c/2) ]
        src_vector = [ args[1][(i+1)*s-1:i*s] for i in xrange(c/2) ]
        __import__('ipdb').set_trace()
        return state.se.Concat(*itertools.chain.from_iterable(reversed(zip(src_vector, dst_vector))))

    @supports_vector
    def _op_generic_CmpEQ(self, state, args):
        if self._vector_size is not None:
            res_comps = []
            for i in range(self._vector_count):
                a_comp = state.se.Extract((i+1) * self._vector_size - 1,
                                          i * self._vector_size,
                                          args[0])
                b_comp = state.se.Extract((i+1) * self._vector_size - 1,
                                          i * self._vector_size,
                                          args[1])
                res_comps.append(state.se.If(a_comp == b_comp,
                                             state.se.BVV(-1, self._vector_size),
                                             state.se.BVV(0, self._vector_size)))
            return state.se.Concat(*res_comps)
        else:
            return state.se.If(args[0] == args[1], state.se.BVV(1, 1), state.se.BVV(0, 1))
    _op_generic_CasCmpEQ = _op_generic_CmpEQ

    def _op_generic_CmpNE(self, state, args):
        return state.se.If(args[0] != args[1], state.se.BVV(1, 1), state.se.BVV(0, 1))
    _op_generic_ExpCmpNE = _op_generic_CmpNE
    _op_generic_CasCmpNE = _op_generic_CmpNE

    def _op_generic_CmpORD(self, state, args):
        x = args[0]
        y = args[1]
        s = self._from_size
        cond = x < y if self._from_signed == 'S' else state.se.ULT(x, y)
        return state.se.If(x == y, state.se.BVV(0x2, s), state.se.If(cond, state.se.BVV(0x8, s), state.se.BVV(0x4, s)))

    def _op_generic_CmpLE(self, state, args):
        cond = args[0] <= args[1] if self._from_signed == 'S' else state.se.ULE(args[0], args[1])
        return state.se.If(cond, state.se.BVV(1, 1), state.se.BVV(0, 1))

    def _op_generic_CmpLT(self, state, args):
        cond = args[0] < args[1] if self._from_signed == 'S' else state.se.ULT(args[0], args[1])
        return state.se.If(cond, state.se.BVV(1, 1), state.se.BVV(0, 1))

    def _op_divmod(self, state, args):
        # TODO: handle signdness
        #try:
        quotient = (args[0] / state.se.ZeroExt(self._from_size - self._to_size, args[1]))
        remainder = (args[0] % state.se.ZeroExt(self._from_size - self._to_size, args[1]))
        quotient_size = self._to_size
        remainder_size = self._to_size
        return state.se.Concat(
            state.se.Extract(remainder_size - 1, 0, remainder),
            state.se.Extract(quotient_size - 1, 0, quotient)
        )
        #except ZeroDivisionError:
        #   return state.BVV(0, self._to_size)
    #pylint:enable=no-self-use,unused-argument


#
# Op Handler
#
#from . import old_irop
def translate(state, op, s_args):
    if op in operations:
        try:
            return operations[op].calculate(state, *s_args)
        except SimOperationError:
            l.warning("IROp error (for operation %s)", op, exc_info=True)
            if options.BYPASS_ERRORED_IROP in state.options:
                return state.se.Unconstrained("irop_error", operations[op]._output_size_bits)
            else:
                raise

    l.error("Unsupported operation: %s", op)
    raise UnsupportedIROpError("Unsupported operation: %s" % op)

from ..s_errors import UnsupportedIROpError, SimOperationError, SimValueError
from ..s_helpers import size_bits
from .. import s_options as options

make_operations()
