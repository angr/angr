#!/usr/bin/python env
"""
This module contains symbolic implementations of VEX operations.
"""

import re
import sys
import collections
import itertools
import operator

import logging
l = logging.getLogger("simuvex.vex.irop")

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
                r'(?P<conversion>to|as)' \
                r'(?P<to_type>Int|I|F|D|V)??' \
                r'(?P<to_size>\d+)??' \
                r'(?P<to_signed>U|S)??' \
              r')??'
              r'(?P<vector_info>\d+U?S?F?0?x\d+)??' \
              r'(?P<rounding_mode>_R(Z|P|N|M))?$', \
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
explicit_attrs = {
    'Iop_Yl2xF64': {
        '_generic_name': 'Yl2x',
        '_to_size': 64,
    },
    'Iop_Yl2xp1F64': {
        '_generic_name': 'Yl2xp1',
        '_to_size': 64,
    },
}


def make_operations():
    for p in all_operations:
        if p in ('Iop_INVALID', 'Iop_LAST'):
            continue

        if p in explicit_attrs:
            attrs = explicit_attrs[p]
        else:
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
    'Mul': '__mul__',
    'Div': '__div__',
    'Neg': 'Neg',
    'Abs': 'Abs',
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
rm_map = {
    0: claripy.fp.RM_RNE,
    1: claripy.fp.RM_RTN,
    2: claripy.fp.RM_RTP,
    3: claripy.fp.RM_RTZ,
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
    """
    A symbolic version of a Vex IR operation.
    """
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

        self._rounding_mode = None

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

        if len({self._vector_type, self._from_type, self._to_type} & {'F', 'D'}) != 0:
            # print self.op_attrs
            self._float = True

            if len({self._vector_type, self._from_type, self._to_type} & {'D'}) != 0:
                l.debug('... aborting on BCD!')
                # fp_ops.add(self.name)
                raise UnsupportedIROpError("BCD ops aren't supported")
        else:
            self._float = False

        #
        # Now determine the operation
        #

        self._calculate = None

        # is it explicitly implemented?
        if hasattr(self, '_op_' + name):
            self._calculate = getattr(self, '_op_' + name)
        # if the generic name is None and there's a conversion present, this is a standard
        # widening or narrowing or sign-extension
        elif self._generic_name is None and self._conversion:
            # convert int to float
            if self._float and self._from_type == 'I':
                self._calculate = self._op_int_to_fp

            # convert float to differently-sized float
            elif self._from_type == 'F' and self._to_type == 'F':
                self._calculate = self._op_fp_to_fp

            elif self._from_type == 'F' and self._to_type == 'I':
                self._calculate = self._op_fp_to_int

            # this concatenates the args into the high and low halves of the result
            elif self._from_side == 'HL':
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

            elif self._from_size < self._to_size and self.is_signed:
                l.debug("... using simple sign-extend")
                self._calculate = self._op_sign_extend

            elif self._from_size < self._to_size and not self.is_signed:
                l.debug("... using simple zero-extend")
                self._calculate = self._op_zero_extend

            else:
                l.error("%s is an unexpected conversion operation configuration", self)
                assert False

        # other conversions
        elif self._conversion and self._generic_name != 'Round' and self._generic_name != 'Reinterp':
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
        elif self._generic_name in arithmetic_operation_map or self._generic_name in shift_operation_map:
            l.debug("... using generic mapping op")
            assert self._from_side is None

            if self._float and self._vector_zero:
                self._calculate = self._op_float_op_just_low
            elif self._float and self._vector_count is None:
                self._calculate = self._op_float_mapped
            elif not self._float and self._vector_count is not None:
                self._calculate = self._op_vector_mapped
            else:
                self._calculate = self._op_mapped

        # TODO: clean up this mess
        # specifically-implemented generics
        elif self._float and hasattr(self, '_op_fgeneric_%s' % self._generic_name):
            l.debug("... using generic method")
            calculate = getattr(self, '_op_fgeneric_%s' % self._generic_name)
            if self._vector_size is not None and \
               not hasattr(calculate, 'supports_vector'):
                # unsupported vector ops
                vector_operations.append(name)
            else:
                self._calculate = calculate

        elif not self._float and hasattr(self, '_op_generic_%s' % self._generic_name):
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

    def calculate(self, *args):
        if not all(isinstance(a, claripy.ast.Base) for a in args):
            import ipdb; ipdb.set_trace()
            raise SimOperationError("IROp needs all args as claripy expressions")

        if not self._float:
            args = tuple(arg.to_bv() for arg in args)

        try:
            return self.extend_size(self._calculate(args))
        except (TypeError, ValueError, SimValueError, claripy.ClaripyError):
            e_type, value, traceback = sys.exc_info()
            raise SimOperationError, ("%s._calculate() raised exception" % self.name, e_type, value), traceback
        except ZeroDivisionError:
            raise SimOperationError("divide by zero!")

    def extend_size(self, o):
        cur_size = o.size()
        if cur_size < self._output_size_bits:
            l.debug("Extending output of %s from %d to %d bits", self.name, cur_size, self._output_size_bits)
            ext_size = self._output_size_bits - cur_size
            if self._to_signed == 'S' or (self._from_signed == 'S' and self._to_signed is None):
                return claripy.SignExt(ext_size, o)
            else:
                return claripy.ZeroExt(ext_size, o)
        elif cur_size > self._output_size_bits:
            __import__('ipdb').set_trace()
            raise SimOperationError('output of %s is too big', self.name)
        else:
            return o

    @property
    def is_signed(self):
        return self._from_signed == 'S' or self._vector_signed == 'S'

    #
    # The actual operation handlers go here.
    #

    #pylint:disable=no-self-use,unused-argument
    def _op_mapped(self, args):
        if self._from_size is not None:
            sized_args = [ ]
            for a in args:
                s = a.size()
                if s == self._from_size:
                    sized_args.append(a)
                elif s < self._from_size:
                    if self.is_signed:
                        sized_args.append(claripy.SignExt(self._from_size - s, a))
                    else:
                        sized_args.append(claripy.ZeroExt(self._from_size - s, a))
                elif s > self._from_size:
                    raise SimOperationError("operation %s received too large an argument" % self.name)
        else:
            sized_args = args

        if self._generic_name in bitwise_operation_map:
            o = bitwise_operation_map[self._generic_name]
        elif self._generic_name in arithmetic_operation_map:
            o = arithmetic_operation_map[self._generic_name]
        elif self._generic_name in shift_operation_map:
            o = shift_operation_map[self._generic_name]
        else:
            raise SimOperationError("op_mapped called with invalid mapping, for %s" % self.name)

        return getattr(claripy.ast.BV, o)(*sized_args)

    def _translate_rm(self, rm_num):
        if not rm_num.symbolic:
            return rm_map[rm_num._model_concrete.value]
        else:
            l.warning("symbolic rounding mode found, using default")
            return claripy.fp.RM.default()

    def _op_float_mapped(self, args):
        NO_RM = { 'Neg', 'Abs' }
        op = getattr(claripy, 'fp' + self._generic_name)

        if self._generic_name in NO_RM:
            return op(*args)

        rm = self._translate_rm(args[0])
        return op(rm, *args[1:])

    def _op_vector_mapped(self, args):
        chopped_args = ([claripy.Extract((i + 1) * self._vector_size - 1, i * self._vector_size, a) for a in args]
                        for i in reversed(xrange(self._vector_count)))
        return claripy.Concat(*(self._op_mapped(ca) for ca in chopped_args))

    def _op_float_op_just_low(self, args):
        chopped = [arg[(self._vector_size - 1):0].raw_to_fp() for arg in args]
        result = getattr(claripy, 'fp' + self._generic_name)(claripy.fp.RM.default(), *chopped).to_bv()
        return claripy.Concat(args[0][(args[0].length - 1):self._vector_size], result)

    def _op_concat(self, args):
        return claripy.Concat(*args)

    def _op_hi_half(self, args):
        return claripy.Extract(args[0].size()-1, args[0].size()/2, args[0])

    def _op_lo_half(self, args):
        return claripy.Extract(args[0].size()/2 - 1, 0, args[0])

    def _op_extract(self, args):
        return claripy.Extract(self._to_size - 1, 0, args[0])

    def _op_sign_extend(self, args):
        return claripy.SignExt(self._to_size - args[0].size(), args[0])

    def _op_zero_extend(self, args):
        return claripy.ZeroExt(self._to_size - args[0].size(), args[0])

    def vector_args(self, args):
        """
         Yields each of the individual lane pairs from the arguments, in
         order from most significan to least significant
        """
        for i in reversed(range(self._vector_count)):
            pieces = []
            for vec in args:
                pieces.append(vec[(i+1) * self._vector_size - 1 : i * self._vector_size])
            yield pieces

    def _op_generic_Mull(self, args):
        op1, op2 = args
        op1 = self.extend_size(op1)
        op2 = self.extend_size(op2)
        return op1 * op2

    def _op_generic_Clz(self, args):
        """Count the leading zeroes"""
        wtf_expr = claripy.BVV(self._from_size, self._from_size)
        for a in range(self._from_size):
            bit = claripy.Extract(a, a, args[0])
            wtf_expr = claripy.If(bit==1, claripy.BVV(self._from_size-a-1, self._from_size), wtf_expr)
        return wtf_expr

    def _op_generic_Ctz(self, args):
        """Count the trailing zeroes"""
        wtf_expr = claripy.BVV(self._from_size, self._from_size)
        for a in reversed(range(self._from_size)):
            bit = claripy.Extract(a, a, args[0])
            wtf_expr = claripy.If(bit == 1, claripy.BVV(a, self._from_size), wtf_expr)
        return wtf_expr

    def generic_minmax(self, args, cmp_op):
        res_comps = []
        for i in reversed(range(self._vector_count)):
            a_comp = claripy.Extract((i+1) * self._vector_size - 1,
                                      i * self._vector_size,
                                      args[0])
            b_comp = claripy.Extract((i+1) * self._vector_size - 1,
                                      i * self._vector_size,
                                      args[1])
            res_comps.append(claripy.If(cmp_op(a_comp, b_comp),
                                     a_comp, b_comp))
        return claripy.Concat(*res_comps)

    @supports_vector
    def _op_generic_Min(self, args):
        return self.generic_minmax(args, claripy.SLT if self.is_signed else claripy.ULT)

    @supports_vector
    def _op_generic_Max(self, args):
        return self.generic_minmax(args, claripy.SGT if self.is_signed else claripy.UGT)

    @supports_vector
    def _op_generic_GetMSBs(self, args):
        size = self._vector_count * self._vector_size
        bits = [claripy.Extract(i, i, args[0]) for i in range(size - 1, 6, -8)]
        return claripy.Concat(*bits)

    @supports_vector
    def _op_generic_InterleaveLO(self, args):
        s = self._vector_size
        c = self._vector_count
        dst_vector = [ args[0][(i+1)*s-1:i*s] for i in xrange(c/2) ]
        src_vector = [ args[1][(i+1)*s-1:i*s] for i in xrange(c/2) ]
        return claripy.Concat(*itertools.chain.from_iterable(reversed(zip(dst_vector, src_vector))))

    def generic_compare(self, args, comparison):
        if self._vector_size is not None:
            res_comps = []
            for i in reversed(range(self._vector_count)):
                a_comp = claripy.Extract((i+1) * self._vector_size - 1,
                                          i * self._vector_size,
                                          args[0])
                b_comp = claripy.Extract((i+1) * self._vector_size - 1,
                                          i * self._vector_size,
                                          args[1])
                res_comps.append(claripy.If(comparison(a_comp, b_comp),
                                         claripy.BVV(-1, self._vector_size),
                                         claripy.BVV(0, self._vector_size)))
            return claripy.Concat(*res_comps)
        else:
            return claripy.If(comparison(args[0], args[1]), claripy.BVV(1, 1), claripy.BVV(0, 1))

    @supports_vector
    def _op_generic_CmpEQ(self, args):
        return self.generic_compare(args, operator.eq)
    _op_generic_CasCmpEQ = _op_generic_CmpEQ

    def _op_generic_CmpNE(self, args):
        return self.generic_compare(args, operator.ne)
    _op_generic_ExpCmpNE = _op_generic_CmpNE
    _op_generic_CasCmpNE = _op_generic_CmpNE

    @supports_vector
    def _op_generic_CmpNEZ(self, args):
        assert len(args) == 1
        args = [args[0], claripy.BVV(0, args[0].size())]
        return self.generic_compare(args, operator.ne)  # TODO: Is this the correct action for scalars?

    @supports_vector
    def _op_generic_CmpGT(self, args):
        return self.generic_compare(args, claripy.SGT if self.is_signed else claripy.UGT)
    _op_generic_CasCmpGT = _op_generic_CmpGT

    @supports_vector
    def _op_generic_CmpGE(self, args):
        return self.generic_compare(args, claripy.SGE if self.is_signed else claripy.UGE)
    _op_generic_CasCmpGE = _op_generic_CmpGE

    @supports_vector
    def _op_generic_CmpLT(self, args):
        return self.generic_compare(args, claripy.SLT if self.is_signed else claripy.ULT)
    _op_generic_CasCmpLT = _op_generic_CmpLT

    @supports_vector
    def _op_generic_CmpLE(self, args):
        return self.generic_compare(args, claripy.SLE if self.is_signed else claripy.ULE)
    _op_generic_CasCmpLE = _op_generic_CmpLE

    def _op_generic_CmpORD(self, args):
        x = args[0]
        y = args[1]
        s = self._from_size
        cond = x < y if self.is_signed else claripy.ULT(x, y)
        return claripy.If(x == y, claripy.BVV(0x2, s), claripy.If(cond, claripy.BVV(0x8, s), claripy.BVV(0x4, s)))

    def generic_shift_thing(self, args, op):
        if self._vector_size is not None:
            shifted = []
            if args[1].length != self._vector_size:
                shift_by = args[1].zero_extend(self._vector_size - args[1].length)
            else:
                shift_by = args[1]
            for i in reversed(range(self._vector_count)):
                left = claripy.Extract((i+1) * self._vector_size - 1,
                                    i * self._vector_size,
                                    args[0])
                shifted.append(op(left, shift_by))
            return claripy.Concat(*shifted)
        else:
            raise SimOperationError("you done fucked")

    @supports_vector
    def _op_generic_ShlN(self, args):
        return self.generic_shift_thing(args, operator.lshift)

    @supports_vector
    def _op_generic_ShrN(self, args):
        return self.generic_shift_thing(args, claripy.LShR)

    @supports_vector
    def _op_generic_SarN(self, args):
        return self.generic_shift_thing(args, operator.rshift)

    @supports_vector
    def _op_generic_HAdd(self, args):
        """
        Halving add, for some ARM NEON instructions.
        """
        components = []
        for a, b in self.vector_args(args):
            if self.is_signed:
                a = a.sign_extend(self._vector_size)
                b = b.sign_extend(self._vector_size)
            else:
                a = a.zero_extend(self._vector_size)
                b = b.zero_extend(self._vector_size)
            components.append((a + b)[self._vector_size:1])
        return claripy.Concat(*components)

    @supports_vector
    def _op_generic_HSub(self, args):
        """
        Halving subtract, for some ARM NEON instructions.
        """
        components = []
        for a, b in self.vector_args(args):
            if self.is_signed:
                a = a.sign_extend(self._vector_size)
                b = b.sign_extend(self._vector_size)
            else:
                a = a.zero_extend(self._vector_size)
                b = b.zero_extend(self._vector_size)
            components.append((a - b)[self._vector_size:1])
        return claripy.Concat(*components)

    @supports_vector
    def _op_generic_QAdd(self, args):
        """
        Saturating add.
        """
        components = []
        for a, b in self.vector_args(args):
            top_a = a[self._vector_size-1]
            top_b = b[self._vector_size-1]
            res = a + b
            top_r = res[self._vector_size-1]
            if self.is_signed:
                big_top_r = (~top_r).zero_extend(self._vector_size-1)
                cap = (claripy.BVV(-1, self._vector_size)/2) + big_top_r
                cap_cond = ((~(top_a ^ top_b)) & (top_a ^ top_r)) == 1
            else:
                cap = claripy.BVV(-1, self._vector_size)
                cap_cond = claripy.ULT(res, a)
            components.append(claripy.If(cap_cond, cap, res))
        return claripy.Concat(*components)

    @supports_vector
    def _op_generic_QSub(self, args):
        """
        Saturating subtract.
        """
        components = []
        for a, b in self.vector_args(args):
            top_a = a[self._vector_size-1]
            top_b = b[self._vector_size-1]
            res = a - b
            top_r = res[self._vector_size-1]
            if self.is_signed:
                big_top_r = (~top_r).zero_extend(self._vector_size-1)
                cap = (claripy.BVV(-1, self._vector_size)/2) + big_top_r
                cap_cond = ((top_a ^ top_b) & (top_a ^ top_r)) == 1
            else:
                cap = claripy.BVV(0, self._vector_size)
                cap_cond = claripy.UGT(res, a)
            components.append(claripy.If(cap_cond, cap, res))
        return claripy.Concat(*components)

    def _op_divmod(self, args):
        if self.is_signed:
            quotient = (args[0].SDiv(claripy.SignExt(self._from_size - self._to_size, args[1])))
            remainder = (args[0].SMod(claripy.SignExt(self._from_size - self._to_size, args[1])))
            quotient_size = self._to_size
            remainder_size = self._to_size
            return claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder),
                claripy.Extract(quotient_size - 1, 0, quotient)
            )
        else:
            quotient = (args[0] / claripy.ZeroExt(self._from_size - self._to_size, args[1]))
            remainder = (args[0] % claripy.ZeroExt(self._from_size - self._to_size, args[1]))
            quotient_size = self._to_size
            remainder_size = self._to_size
            return claripy.Concat(
                claripy.Extract(remainder_size - 1, 0, remainder),
                claripy.Extract(quotient_size - 1, 0, quotient)
            )

    #pylint:enable=no-self-use,unused-argument

    # FP!
    def _op_int_to_fp(self, args):
        rm_exists = self._from_size != 32 or self._to_size != 64
        rm = self._translate_rm(args[0] if rm_exists else claripy.BVV(0, 32))
        arg = args[1 if rm_exists else 0]

        return arg.signed_to_fp(rm, claripy.fp.FSort.from_size(self._output_size_bits))

    def _op_fp_to_fp(self, args):
        rm_exists = self._from_size != 32 or self._to_size != 64
        rm = self._translate_rm(args[0] if rm_exists else claripy.BVV(0, 32))
        arg = args[1 if rm_exists else 0].raw_to_fp()

        return arg.raw_to_fp().to_fp(rm, claripy.fp.FSort.from_size(self._output_size_bits))

    def _op_fp_to_int(self, args):
        rm = self._translate_rm(args[0])
        arg = args[1].raw_to_fp()

        if self._to_signed == 'S':
            return claripy.fpToSBV(rm, arg, self._to_size)
        else:
            return claripy.fpToUBV(rm, arg, self._to_size)

    def _op_fgeneric_Cmp(self, args): #pylint:disable=no-self-use
        a, b = args[0].raw_to_fp(), args[1].raw_to_fp()
        return claripy.ite_cases((
            (claripy.fpLT(a, b), claripy.BVV(0x01, 32)),
            (claripy.fpGT(a, b), claripy.BVV(0x00, 32)),
            (claripy.fpEQ(a, b), claripy.BVV(0x40, 32)),
            ), claripy.BVV(0x45, 32))

    def _op_fgeneric_Reinterp(self, args):
        if self._to_type == 'I':
            return args[0].to_bv()
        elif self._to_type == 'F':
            return args[0].raw_to_fp()
        else:
            raise SimOperationError("unsupport Reinterp _to_type")

    @supports_vector
    def _op_fgeneric_Round(self, args):
        if self._vector_size is not None:
            rm = {
                'RM': claripy.fp.RM_RTN,
                'RP': claripy.fp.RM_RTP,
                'RN': claripy.fp.RM_RNE,
                'RZ': claripy.fp.RM_RTZ,
            }[self._rounding_mode]

            rounded = []
            for i in reversed(range(self._vector_count)):
                #pylint:disable=no-member
                left = claripy.Extract(
                    (i+1) * self._vector_size - 1, i * self._vector_size, args[0]
                ).raw_to_fp()
                rounded.append(claripy.fpToSBV(rm, left, self._vector_size))
            return claripy.Concat(*rounded)
        else:
            # note: this a bad solution because it will cut off high values
            # TODO: look into fixing this
            rm = self._translate_rm(args[0])
            rounded_bv = claripy.fpToSBV(rm, args[1].raw_to_fp(), args[1].length)
            return claripy.fpToFP(claripy.fp.RM_RNE, rounded_bv, claripy.fp.FSort.from_size(args[1].length))

    #def _op_Iop_Yl2xF64(self, args):
    #   rm = self._translate_rm(args[0])
    #   arg2_bv = args[2].to_bv()
    #   # IEEE754 double looks like this:
    #   # SEEEEEEEEEEEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    #   # thus, we extract the exponent bits, re-bias them, then
    #   # (signed) convert them back into an FP value for the integer
    #   # part of the log. then we make the approximation that log2(x)
    #   # = x - 1 for 1.0 <= x < 2.0 to account for the mantissa.

    #   # the bias for doubles is 1023
    #   arg2_exp = (arg2_bv[62:52] - 1023).signed_to_fp(rm, claripy.fp.FSORT_DOUBLE)
    #   arg2_mantissa = claripy.Concat(claripy.BVV(int('001111111111', 2), 12), arg2_bv[51:0]).raw_to_fp()
    #   # this is the hacky approximation:
    #   log2_arg2_mantissa = claripy.fpSub(rm, arg2_mantissa, claripy.FPV(1.0, claripy.fp.FSORT_DOUBLE))
    #   return claripy.fpMul(rm, args[1].raw_to_fp(), claripy.fpAdd(rm, arg2_exp, log2_arg2_mantissa))

    #def _op_Iop_Yl2xp1F64(self, args):
    #   rm_raw, arg1, arg2 = args
    #   rm = self._translate_rm(rm_raw)
    #   arg2_p1 = claripy.fpAdd(rm, arg2.raw_to_fp(), claripy.FPV(1.0, claripy.fp.FSORT_DOUBLE))
    #   return self._op_Iop_Yl2xF64((rm_raw, arg1, arg2_p1))

    @staticmethod
    def pow(rm, arg, n):
        out = claripy.FPV(1.0, arg.sort)
        for _ in xrange(n):
            out = claripy.fpMul(rm, arg, out)
        return out

    #def _op_Iop_SinF64(self, args):
    #   rm, arg = args
    #   rm = self._translate_rm(rm)
    #   rounds = 15
    #   accumulator = claripy.FPV(0.0, arg.sort)
    #   factorialpart = 1.0
    #   for i in xrange(1, rounds + 1):
    #       term = claripy.fpDiv(rm, self.pow(rm, arg, 2*i - 1), claripy.FPV(float(factorialpart), arg.sort))
    #       factorialpart *= ((i*2) + 1) * (i*2)
    #       if i % 2 == 1:
    #           accumulator = claripy.fpAdd(rm, accumulator, term)
    #       else:
    #           accumulator = claripy.fpSub(rm, accumulator, term)

    #   return accumulator

    #def _op_Iop_CosF64(self, args):
    #   rm, arg = args
    #   rm = self._translate_rm(rm)
    #   rounds = 20
    #   accumulator = claripy.FPV(1.0, arg.sort)
    #   factorialpart = 2.0
    #   for i in xrange(1, rounds + 1):
    #       term = claripy.fpDiv(rm, self.pow(rm, arg, 2*i), claripy.FPV(float(factorialpart), arg.sort))
    #       factorialpart *= (i*2 + 1) * (i*2 + 2)
    #       if i % 2 == 1:
    #           accumulator = claripy.fpSub(rm, accumulator, term)
    #       else:
    #           accumulator = claripy.fpAdd(rm, accumulator, term)

    #   return accumulator


#
# Op Handler
#
#from . import old_irop
def translate(state, op, s_args):
    if op in operations:
        try:
            irop = operations[op]
            if irop._float and not options.SUPPORT_FLOATING_POINT in state.options:
                raise UnsupportedIROpError("floating point support disabled")
            return irop.calculate( *s_args)
        except ZeroDivisionError:
            if state.mode == 'static' and len(s_args) == 2 and state.se.is_true(s_args[1] == 0):
                # Monkeypatch the dividend to another value instead of 0
                s_args[1] = state.se.BVV(1, s_args[1].size())
                return operations[op].calculate( *s_args)
            else:
                raise
        except SimOperationError:
            l.warning("IROp error (for operation %s)", op, exc_info=True)
            if options.BYPASS_ERRORED_IROP in state.options:
                return state.se.Unconstrained("irop_error", operations[op]._output_size_bits)
            else:
                raise

    l.error("Unsupported operation: %s", op)
    raise UnsupportedIROpError("Unsupported operation: %s" % op)

from ..s_errors import UnsupportedIROpError, SimOperationError, SimValueError
from . import size_bits
from .. import s_options as options

make_operations()
