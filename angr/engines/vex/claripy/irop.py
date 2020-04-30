"""
This module contains symbolic implementations of VEX operations.
"""
from functools import partial
import collections
import itertools
import operator
import math
import re

import logging
l = logging.getLogger(name=__name__)

import pyvex
import claripy

#
# The more sane approach
#


def op_attrs(p):
    m = re.match(r'^Iop_'
                 r'(?P<generic_name>\D+?)??'
                 r'(?P<from_type>[IFDV])??'
                 r'(?P<from_signed>[US])??'
                 r'(?P<from_size>\d+)??'
                 r'(?P<from_signed_back>[US])??'
                 # this screws up CmpLE: r'(?P<e_flag>E)??' \
                 r'('
                 r'(?P<from_side>HL|HI|L|LO)??'
                 r'(?P<conversion>to|as)'
                 r'(?P<to_type>Int|I|F|D|V)??'
                 r'(?P<to_size>\d+)??'
                 r'(?P<to_signed>[US])??'
                 r')??'
                 r'(?P<vector_info>\d+U?S?F?0?x\d+)??'
                 r'(?P<rounding_mode>_R([ZPNM]))?$',
                 p
                 )

    if not m:
        return None
    else:
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
            vm = re.match(r'^(?P<vector_size>\d+)?'
                          r'(?P<vector_signed>[US])?'
                          r'(?P<vector_type>[FD])?'
                          r'(?P<vector_zero>0)?'
                          r'x'
                          r'(?P<vector_count>\d+)?$',
                          vector_info
                          )
            attrs.update(vm.groupdict())

        return attrs


all_operations = list(pyvex.irop_enums_to_ints.keys())
operations = { }
classified = set()
unclassified = set()
unsupported = set()
explicit_attrs = {
    'Iop_64x4toV256': {
        'generic_name': '64x4',
        'to_size': 256,
    },
    'Iop_Yl2xF64': {
        'generic_name': 'Yl2x',
        'to_size': 64,
    },
    'Iop_Yl2xp1F64': {
        'generic_name': 'Yl2xp1',
        'to_size': 64,
    },
    'Iop_V256to64_0': { 'generic_name': 'unpack', 'to_size': 64, },
    'Iop_V256to64_1': { 'generic_name': 'unpack', 'to_size': 64, },
    'Iop_V256to64_2': { 'generic_name': 'unpack', 'to_size': 64, },
    'Iop_V256to64_3': { 'generic_name': 'unpack', 'to_size': 64, },
    'Iop_V256toV128_0': { 'generic_name': 'unpack', 'to_size': 128, },
    'Iop_V256toV128_1': { 'generic_name': 'unpack', 'to_size': 128, },
}

for _vec_lanewidth in (8, 16, 32, 64):
    for _vec_width in (64, 128):
        _vec_count = _vec_width // _vec_lanewidth
        if _vec_count <= 1:
            continue

        # the regex thinks the I is an integral descriptor
        explicit_attrs['Iop_InterleaveHI%dx%d' % (_vec_lanewidth, _vec_count)] = {
                'generic_name': 'InterleaveHI',
                'to_size': _vec_width,
                'vector_size': _vec_lanewidth,
                'vector_count': _vec_count,
        }


def make_operations():
    for p in all_operations:
        if p in ('Iop_INVALID', 'Iop_LAST'):
            continue

        try:
            attrs = explicit_attrs[p]
        except KeyError:
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
    'Mod': '__mod__',
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

operation_map = {}
operation_map.update(arithmetic_operation_map)
operation_map.update(shift_operation_map)
operation_map.update(bitwise_operation_map)

rm_map = {
    0: claripy.fp.RM.RM_NearestTiesEven,
    1: claripy.fp.RM.RM_TowardsNegativeInf,
    2: claripy.fp.RM.RM_TowardsPositiveInf,
    3: claripy.fp.RM.RM_TowardsZero,
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


class SimIROp:
    """
    A symbolic version of a Vex IR operation.
    """
    def __init__(self, name, **attrs):
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
        self._output_type = pyvex.get_op_retty(name)
        #pylint:enable=no-member
        self._output_size_bits = pyvex.const.get_type_size(self._output_type)

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
            self._float = True

            if len({self._vector_type, self._from_type, self._to_type} & {'D'}) != 0:
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
                self._calculate = self._op_concat

            # this just returns the high half of the first arg
            elif self._from_size > self._to_size and self._from_side == 'HI':
                self._calculate = self._op_hi_half

            # this just returns the high half of the first arg
            elif self._from_size > self._to_size and self._from_side in ('L', 'LO'):
                self._calculate = self._op_lo_half

            elif self._from_size > self._to_size and self._from_side is None:
                self._calculate = self._op_extract

            elif self._from_size < self._to_size and self.is_signed:
                self._calculate = self._op_sign_extend

            elif self._from_size < self._to_size and not self.is_signed:
                self._calculate = self._op_zero_extend

            else:
                l.error("%s is an unexpected conversion operation configuration", self)
                assert False

        elif self._float and self._vector_zero:
            # /* --- lowest-lane-only scalar FP --- */
            f = getattr(claripy, 'fp' + self._generic_name, None)
            if f is not None:
                f = partial(f, claripy.fp.RM.default()) # always? really?

            f = f if f is not None else getattr(self, '_fgeneric_' + self._generic_name, None)
            if f is None:
                raise SimOperationError("no implementation found for operation {}".format(self._generic_name))

            self._calculate = partial(self._auto_vectorize, f)

        # other conversions
        elif self._conversion and self._generic_name not in {'Round', 'Reinterp'}:
            if self._generic_name == "DivMod":
                self._calculate = self._op_divmod
            else:
                unsupported_conversions.append(self.name)
                common_unsupported_generics[self._generic_name] += 1

        # generic bitwise
        elif self._generic_name in bitwise_operation_map:
            assert self._from_side is None
            self._calculate = self._op_mapped

        # generic mapping operations
        elif    self._generic_name in arithmetic_operation_map or \
                self._generic_name in shift_operation_map:
            assert self._from_side is None

            if self._float and self._vector_count is None:
                self._calculate = self._op_float_mapped
            elif not self._float and self._vector_count is not None:
                self._calculate = self._op_vector_mapped
            elif self._float and self._vector_count is not None:
                self._calculate = self._op_vector_float_mapped
            else:
                self._calculate = self._op_mapped

        # TODO: clean up this mess
        # specifically-implemented generics
        elif self._float and hasattr(self, '_op_fgeneric_%s' % self._generic_name):
            calculate = getattr(self, '_op_fgeneric_%s' % self._generic_name)
            if self._vector_size is not None and \
               not hasattr(calculate, 'supports_vector'):
                # NOTE: originally this branch just marked the op as unsupported but I think we can do better
                # "marking unsupported" seems to include adding the op to the vector_operations list? why
                self._calculate = partial(self._auto_vectorize, calculate)
            else:
                self._calculate = calculate

        elif not self._float and hasattr(self, '_op_generic_%s' % self._generic_name):
            calculate = getattr(self, '_op_generic_%s' % self._generic_name)
            if self._vector_size is not None and \
               not hasattr(calculate, 'supports_vector'):
                # NOTE: same as above
                self._calculate = partial(self._auto_vectorize, calculate)
            else:
                self._calculate = calculate

        else:
            common_unsupported_generics[self._generic_name] += 1
            other_operations.append(name)


        # if we're here and calculate is None, we don't support this
        if self._calculate is None:
            raise UnsupportedIROpError("no calculate function identified for %s" % self.name)

    def __repr__(self):
        return "<SimIROp %s>" % self.name

    def _dbg_print_attrs(self):
        print("Operation: %s" % self.name)
        for k,v in self.op_attrs.items():
            if v is not None and v != "":
                print("... %s: %s" % (k, v))

    def calculate(self, *args):
        if not all(isinstance(a, claripy.ast.Base) for a in args):
            import ipdb; ipdb.set_trace()
            raise SimOperationError("IROp needs all args as claripy expressions")

        if not self._float:
            args = tuple(arg.raw_to_bv() for arg in args)

        try:
            if self._vector_size is None:
                return self.extend_size(self._calculate(args))
            else:
                return self._calculate(args)
        except (ZeroDivisionError, claripy.ClaripyZeroDivisionError) as e:
            raise SimZeroDivisionException("divide by zero!") from e
        except (TypeError, ValueError, SimValueError, claripy.ClaripyError) as e:
            raise SimOperationError("%s._calculate() raised exception" % self.name) from e

    def extend_size(self, o):
        cur_size = o.size()
        target_size = self._output_size_bits
        if self._vector_count is not None:
            # phrased this awkward way to account for vectorized widening multiply
            target_size //= self._vector_count
        if cur_size == target_size:
            return o
        if cur_size < target_size:
            ext_size = target_size - cur_size
            if self._to_signed == 'S' or (self._to_signed is None and self._from_signed == 'S') or (self._to_signed is None and self._vector_signed == 'S'):
                return claripy.SignExt(ext_size, o)
            else:
                return claripy.ZeroExt(ext_size, o)

        # if cur_size > target_size:
        # it should never happen!
        raise SimOperationError('output of %s is too big' % self.name)

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

        if self._generic_name in operation_map:  # bitwise/arithmetic/shift operations
            o = operation_map[self._generic_name]
        else:
            raise SimOperationError("op_mapped called with invalid mapping, for %s" % self.name)

        if o == '__div__' and self.is_signed:
            # yikes!!!!!!!
            return claripy.SDiv(*sized_args)

        return getattr(claripy.ast.BV, o)(*sized_args)

    def _translate_rm(self, rm_num):
        if not rm_num.symbolic:
            return rm_map[rm_num._model_concrete.value]
        else:
            l.warning("symbolic rounding mode found, using default")
            return claripy.fp.RM.default()

    NO_RM = { 'Neg', 'Abs' }

    def _op_float_mapped(self, args):
        op = getattr(claripy, 'fp' + self._generic_name)

        if self._generic_name in self.NO_RM:
            return op(*args)

        rm = self._translate_rm(args[0])
        return op(rm, *args[1:])

    def _op_vector_mapped(self, args):
        chopped_args = ([claripy.Extract((i + 1) * self._vector_size - 1, i * self._vector_size, a) for a in args]
                        for i in reversed(range(self._vector_count)))
        return claripy.Concat(*(self._op_mapped(ca) for ca in chopped_args))

    def _op_vector_float_mapped(self, args):
        rm_part = [] if self._generic_name in self.NO_RM else [args[0]]
        chopped_args = (
                [
                    claripy.Extract((i + 1) * self._vector_size - 1, i * self._vector_size, a).raw_to_fp()
                    for a in (args if self._generic_name in self.NO_RM else args[1:])
                ] for i in reversed(range(self._vector_count))
            )
        return claripy.Concat(*(self._op_float_mapped(rm_part + ca).raw_to_bv() for ca in chopped_args))

    def _op_concat(self, args):
        return claripy.Concat(*args)

    def _op_hi_half(self, args):
        return claripy.Extract(args[0].size()-1, args[0].size()//2, args[0])

    def _op_lo_half(self, args):
        return claripy.Extract(args[0].size()//2 - 1, 0, args[0])

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
                piece = vec[(i+1) * self._vector_size - 1 : i * self._vector_size]
                if self._float:
                    piece = piece.raw_to_fp()
                pieces.append(piece)
            yield pieces

    def _op_generic_Mull(self, args):
        op1, op2 = args
        op1 = self.extend_size(op1)
        op2 = self.extend_size(op2)
        return op1 * op2

    def _op_generic_Clz(self, args):
        """Count the leading zeroes"""
        piece_size = len(args[0])
        wtf_expr = claripy.BVV(piece_size, piece_size)
        for a in range(piece_size):
            bit = claripy.Extract(a, a, args[0])
            wtf_expr = claripy.If(bit==1, claripy.BVV(piece_size-a-1, piece_size), wtf_expr)
        return wtf_expr

    def _op_generic_Ctz(self, args):
        """Count the trailing zeroes"""
        piece_size = len(args[0])
        wtf_expr = claripy.BVV(piece_size, piece_size)
        for a in reversed(range(piece_size)):
            bit = claripy.Extract(a, a, args[0])
            wtf_expr = claripy.If(bit == 1, claripy.BVV(a, piece_size), wtf_expr)
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
        left_vector = [ args[0][(i+1)*s-1:i*s] for i in range(c//2) ]
        right_vector = [ args[1][(i+1)*s-1:i*s] for i in range(c//2) ]
        return claripy.Concat(*itertools.chain.from_iterable(zip(reversed(left_vector), reversed(right_vector))))

    @supports_vector
    def _op_generic_InterleaveHI(self, args):
        s = self._vector_size
        c = self._vector_count
        left_vector = [ args[0][(i+1)*s-1:i*s] for i in range(c//2, c) ]
        right_vector = [ args[1][(i+1)*s-1:i*s] for i in range(c//2, c) ]
        return claripy.Concat(*itertools.chain.from_iterable(zip(reversed(left_vector), reversed(right_vector))))

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
        cond = claripy.SLT(x, y) if self.is_signed else claripy.ULT(x, y)
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
                cap = (claripy.BVV(-1, self._vector_size)//2) + big_top_r
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
                cap = (claripy.BVV(-1, self._vector_size)//2) + big_top_r
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
            quotient = (args[0] // claripy.ZeroExt(self._from_size - self._to_size, args[1]))
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

        return arg.val_to_fp(claripy.fp.FSort.from_size(self._output_size_bits), signed=True, rm=rm)

    def _op_fp_to_fp(self, args):
        rm_exists = self._from_size != 32 or self._to_size != 64
        rm = self._translate_rm(args[0] if rm_exists else claripy.BVV(0, 32))
        arg = args[1 if rm_exists else 0].raw_to_fp()

        return arg.raw_to_fp().to_fp(claripy.fp.FSort.from_size(self._output_size_bits), rm=rm)

    def _op_fp_to_int(self, args):
        rm = self._translate_rm(args[0])
        arg = args[1].raw_to_fp()

        if self._to_signed == 'S':
            return claripy.fpToSBV(rm, arg, self._to_size)
        else:
            return claripy.fpToUBV(rm, arg, self._to_size)

    def _op_fgeneric_Cmp(self, args): #pylint:disable=no-self-use

        # see https://github.com/angr/vex/blob/master/pub/libvex_ir.h#L580
        a, b = args[0].raw_to_fp(), args[1].raw_to_fp()
        return claripy.ite_cases((
            (claripy.fpLT(a, b), claripy.BVV(0x01, 32)),
            (claripy.fpGT(a, b), claripy.BVV(0x00, 32)),
            (claripy.fpEQ(a, b), claripy.BVV(0x40, 32)),
            ), claripy.BVV(0x45, 32))

    def _op_fgeneric_CmpEQ(self, a0, a1): # pylint: disable=no-self-use
        # for cmpps_eq stuff, i.e. Iop_CmpEQ32Fx4
        return claripy.If(claripy.fpEQ(a0, a1), claripy.BVV(-1, len(a0)), claripy.BVV(0, len(a0)))

    def _auto_vectorize(self, f, args, rm=None, rm_passed=False):
        if rm is not None:
            rm = self._translate_rm(rm)
            if rm_passed:
                f = partial(f, rm)

        if self._vector_size is None:
            return f(args)

        if self._vector_zero:
            chopped = [arg[(self._vector_size - 1):0].raw_to_fp() for arg in args]
            result = f(*chopped).raw_to_bv()
            return claripy.Concat(args[0][(args[0].length - 1):self._vector_size], result)
        else:
            # I'm changing this behavior because I think this branch was never used otherwise
            # before it only chopped the first argument but I'm going to make it chop all of them
            result = []
            for lane_args in self.vector_args(args):
                if self._float:
                    # HACK HACK HACK
                    # this is such a weird divergence. why do the fp generics take several args and the int generics take a list?
                    result.append(f(*lane_args))
                else:
                    result.append(f(lane_args))
            return claripy.Concat(*result)

    @staticmethod
    def _fgeneric_minmax(cmp_op, a, b):
        a, b = a.raw_to_fp(), b.raw_to_fp()
        return claripy.If(cmp_op(a, b), a, b)

    def _fgeneric_Min(self, a, b):
        return self._fgeneric_minmax(claripy.fpLT, a, b)

    def _fgeneric_Max(self, a, b):
        return self._fgeneric_minmax(claripy.fpGT, a, b)

    def _op_fgeneric_Reinterp(self, args):
        if self._to_type == 'I':
            return args[0].raw_to_bv()
        elif self._to_type == 'F':
            return args[0].raw_to_fp()
        else:
            raise SimOperationError("unsupport Reinterp _to_type")

    @supports_vector
    def _op_fgeneric_Round(self, args):
        if self._vector_size is not None:
            rm = {
                'RM': claripy.fp.RM.RM_TowardsNegativeInf,
                'RP': claripy.fp.RM.RM_TowardsPositiveInf,
                'RN': claripy.fp.RM.RM_NearestTiesEven,
                'RZ': claripy.fp.RM.RM_TowardsZero,
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
            return claripy.fpToFP(claripy.fp.RM.RM_NearestTiesEven, rounded_bv, claripy.fp.FSort.from_size(args[1].length))

    def _op_generic_pack_StoU_saturation(self, args, src_size, dst_size):
        """
        Generic pack with unsigned saturation.
        Split args in chunks of src_size signed bits and in pack them into unsigned saturated chunks of dst_size bits.
        Then chunks are concatenated resulting in a BV of len(args)*dst_size//src_size*len(args[0]) bits.
        """
        if src_size <= 0 or dst_size <= 0:
            raise SimOperationError("Can't pack from or to zero or negative size" % self.name)
        result = None
        max_value = claripy.BVV(-1, dst_size).zero_extend(src_size - dst_size) #max value for unsigned saturation
        min_value = claripy.BVV(0, src_size) #min unsigned value always 0
        for v in args:
            for src_value in v.chop(src_size):
                dst_value = self._op_generic_StoU_saturation(src_value, min_value, max_value)
                dst_value = dst_value.zero_extend(dst_size - src_size)
                if result is None:
                    result = dst_value
                else:
                    result = self._op_concat((result, dst_value))
        return result

    def _op_generic_StoU_saturation(self, value, min_value, max_value): #pylint:disable=no-self-use
        """
        Return unsigned saturated BV from signed BV.
        Min and max value should be unsigned.
        """
        return claripy.If(
            claripy.SGT(value, max_value),
            max_value,
            claripy.If(claripy.SLT(value, min_value), min_value, value))

    def _op_Iop_64x4toV256(self, args) :
        return self._op_concat(args)

    @staticmethod
    def _op_Iop_V256to64_0(args): return args[0][63:0]
    @staticmethod
    def _op_Iop_V256to64_1(args): return args[0][127:64]
    @staticmethod
    def _op_Iop_V256to64_2(args): return args[0][191:128]
    @staticmethod
    def _op_Iop_V256to64_3(args): return args[0][255:192]
    @staticmethod
    def _op_Iop_V256toV128_0(args): return args[0][127:0]
    @staticmethod
    def _op_Iop_V256toV128_1(args): return args[0][255:128]

    def _op_Iop_QNarrowBin16Sto8Ux16(self, args):
        """
        PACKUSWB Pack with Unsigned Saturation.Two 128 bits operands version.
        VPACKUSWB Pack with Unsigned Saturation.Three 128 bits operands version.
        """
        return self._op_generic_pack_StoU_saturation(args, 16, 8)

    def _op_Iop_QNarrowBin16Sto8Ux8(self, args):
        """
        PACKUSWB Pack with Unsigned Saturation.Two 64 bits operands version.
        """
        return self._op_generic_pack_StoU_saturation(args, 16, 8)

    @staticmethod
    def _op_Iop_MAddF64(args):
        """
        Ternary operation.
            arg0 == 0
            return arg1 * arg2 + arg3

        :param args:    Arguments to this operation.
        :return:        The operation result.
        """

        return args[1] * args[2] + args[3]

    @supports_vector
    def _op_generic_MulHi(self, args):
        """
        Sign-extend double each lane, multiply each lane, and store only the high half of the result
        """
        if self._vector_signed == 'S':
            lanes_0 = [lane.sign_extend(self._vector_size) for lane in args[0].chop(self._vector_size)]
            lanes_1 = [lane.sign_extend(self._vector_size) for lane in args[1].chop(self._vector_size)]
        else:
            lanes_0 = [lane.zero_extend(self._vector_size) for lane in args[0].chop(self._vector_size)]
            lanes_1 = [lane.zero_extend(self._vector_size) for lane in args[1].chop(self._vector_size)]
        mulres = [a*b for a, b in zip(lanes_0, lanes_1)]
        highparts = [x.chop(self._vector_size)[0] for x in mulres]
        return claripy.Concat(*highparts)

    @supports_vector
    def _op_generic_Perm(self, args):
        ordered_0 = list(reversed(args[0].chop(self._vector_size)))
        ordered_1 = list(reversed(args[1].chop(self._vector_size)))
        res = []
        nbits = int(math.log2(self._vector_size))
        for pword in ordered_1:
            switch = pword[nbits-1:0]
            kill = pword[self._vector_size - 1]
            switched = claripy.ite_cases([(switch == i, v) for i, v in enumerate(ordered_0[:-1])], ordered_0[-1])
            killed = claripy.If(kill == 1, 0, switched)
            res.append(killed)

        return claripy.Concat(*reversed(res))

    @supports_vector
    def _op_generic_CatEvenLanes(self, args):
        vec_0 = args[0].chop(self._vector_size)
        vec_1 = args[1].chop(self._vector_size)
        return claripy.Concat(*(vec_0[1::2] + vec_1[1::2]))

    @supports_vector
    def _op_generic_CatOddLanes(self, args):
        vec_0 = args[0].chop(self._vector_size)
        vec_1 = args[1].chop(self._vector_size)
        return claripy.Concat(*(vec_0[::2] + vec_1[::2]))


    #def _op_Iop_Yl2xF64(self, args):
    #   rm = self._translate_rm(args[0])
    #   arg2_bv = args[2].raw_to_bv()
    #   # IEEE754 double looks like this:
    #   # SEEEEEEEEEEEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    #   # thus, we extract the exponent bits, re-bias them, then
    #   # (signed) convert them back into an FP value for the integer
    #   # part of the log. then we make the approximation that log2(x)
    #   # = x - 1 for 1.0 <= x < 2.0 to account for the mantissa.

    #   # the bias for doubles is 1023
    #   arg2_exp = (arg2_bv[62:52] - 1023).val_to_fp(claripy.fp.FSORT_DOUBLE, signed=True, rm=rm)
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
        for _ in range(n):
            out = claripy.fpMul(rm, arg, out)
        return out

    #def _op_Iop_SinF64(self, args):
    #   rm, arg = args
    #   rm = self._translate_rm(rm)
    #   rounds = 15
    #   accumulator = claripy.FPV(0.0, arg.sort)
    #   factorialpart = 1.0
    #   for i in range(1, rounds + 1):
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
    #   for i in range(1, rounds + 1):
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

def vexop_to_simop(op, extended=True, fp=True):
    res = operations.get(op)
    if res is None and extended:
        attrs = op_attrs(op)
        if attrs is None:
            raise UnsupportedIROpError("Operation not implemented")
        res = SimIROp(op, **attrs)
    if res is None:
        raise UnsupportedIROpError("Operation not implemented")
    if res._float and not fp:
        raise UnsupportedIROpError("Floating point support disabled")
    return res

from angr.errors import UnsupportedIROpError, SimOperationError, SimValueError, SimZeroDivisionException

make_operations()
