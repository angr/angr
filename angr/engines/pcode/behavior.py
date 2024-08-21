import operator
from collections.abc import Callable, Iterable

import claripy
from claripy.ast.bv import BV

from ...errors import AngrError

try:
    from pypcode import OpCode
except ImportError:
    OpCode = None

# pylint:disable=abstract-method


def make_bv_sizes_equal(bv1: BV, bv2: BV) -> tuple[BV, BV]:
    """
    Makes two BVs equal in length through sign extension.
    """
    if bv1.size() < bv2.size():
        return (bv1.sign_extend(bv2.size() - bv1.size()), bv2)
    elif bv1.size() > bv2.size():
        return (bv1, bv2.sign_extend(bv1.size() - bv2.size()))
    else:
        return (bv1, bv2)


# FIXME: Unimplemented ops (mostly floating point related) have associated C++
# reference code from Ghidra which will need to be ported.


class OpBehavior:
    """
    Base class for all operation behaviors.
    """

    __slots__ = ("opcode", "is_unary", "is_special")
    opcode: int
    is_unary: bool
    is_special: bool

    def __init__(self, opcode: int, is_unary: bool, is_special: bool = False) -> None:
        self.opcode = opcode
        self.is_unary = is_unary
        self.is_special = is_special

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:  # pylint:disable=no-self-use
        raise AngrError("Not implemented!")

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:  # pylint:disable=no-self-use
        raise AngrError("Not implemented!")

    @staticmethod
    def generic_compare(args: Iterable[BV], comparison: Callable[[BV, BV], BV]) -> BV:
        return claripy.If(comparison(args[0], args[1]), claripy.BVV(1, 1), claripy.BVV(0, 1))

    @classmethod
    def booleanize(cls, in1: BV) -> BV:
        """
        Reduce input BV to a single bit of truth: out <- 1 if (in1 != 0) else 0.
        """
        return cls.generic_compare((in1, claripy.BVV(0, in1.size())), operator.ne)


class OpBehaviorCopy(OpBehavior):
    """
    Behavior for the COPY operation.
    """

    def __init__(self):
        super().__init__(OpCode.COPY, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1


class OpBehaviorEqual(OpBehavior):
    """
    Behavior for the INT_EQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_EQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), operator.eq)


class OpBehaviorNotEqual(OpBehavior):
    """
    Behavior for the INT_NOTEQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_NOTEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), operator.ne)


class OpBehaviorIntSless(OpBehavior):
    """
    Behavior for the INT_SLESS operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SLESS, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.SLT)


class OpBehaviorIntSlessEqual(OpBehavior):
    """
    Behavior for the INT_SLESSEQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SLESSEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.SLE)


class OpBehaviorIntLess(OpBehavior):
    """
    Behavior for the INT_LESS operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_LESS, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.ULT)


class OpBehaviorIntLessEqual(OpBehavior):
    """
    Behavior for the INT_LESSEQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_LESSEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.ULE)


class OpBehaviorIntZext(OpBehavior):
    """
    Behavior for the INT_ZEXT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_ZEXT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1.zero_extend((size_out - size_in) * 8)


class OpBehaviorIntSext(OpBehavior):
    """
    Behavior for the INT_SEXT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SEXT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1.sign_extend((size_out - size_in) * 8)


class OpBehaviorIntAdd(OpBehavior):
    """
    Behavior for the INT_ADD operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_ADD, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 + in2


class OpBehaviorIntSub(OpBehavior):
    """
    Behavior for the INT_SUB operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SUB, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 - in2


class OpBehaviorIntCarry(OpBehavior):
    """
    Behavior for the INT_CARRY operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_CARRY, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        # origin: ccall.py pc_actions_ADD
        res = in1 + in2
        return claripy.If(claripy.ULT(res, in1), claripy.BVV(1, 1), claripy.BVV(0, 1))


class OpBehaviorIntScarry(OpBehavior):
    """
    Behavior for the INT_SCARRY operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SCARRY, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        res = in1 + in2

        a = (in1 >> (size_in * 8 - 1)) & 1
        b = (in2 >> (size_in * 8 - 1)) & 1
        r = (res >> (size_in * 8 - 1)) & 1

        r ^= a
        a ^= b
        a ^= 1
        r &= a

        return r


class OpBehaviorIntSborrow(OpBehavior):
    """
    Behavior for the INT_SBORROW operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SBORROW, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        res = in1 - in2

        a = (in1 >> (size_in * 8 - 1)) & 1  # Grab sign bit
        b = (in2 >> (size_in * 8 - 1)) & 1  # Grab sign bit
        r = (res >> (size_in * 8 - 1)) & 1  # Grab sign bit

        a ^= r
        r ^= b
        r ^= 1
        a &= r
        return a


class OpBehaviorInt2Comp(OpBehavior):
    """
    Behavior for the INT_2COMP operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_2COMP, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return -in1

    # uintb OpBehaviorInt2Comp::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   uintb res = uintb_negate(in1-1,size_in);
    #   return res;
    # }


class OpBehaviorIntNegate(OpBehavior):
    """
    Behavior for the INT_NEGATE operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_NEGATE, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return ~in1


class OpBehaviorIntXor(OpBehavior):
    """
    Behavior for the INT_XOR operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_XOR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 ^ in2


class OpBehaviorIntAnd(OpBehavior):
    """
    Behavior for the INT_AND operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_AND, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 & in2


class OpBehaviorIntOr(OpBehavior):
    """
    Behavior for the INT_OR operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_OR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 | in2


class OpBehaviorIntLeft(OpBehavior):
    """
    Behavior for the INT_LEFT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_LEFT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1 << in2


class OpBehaviorIntRight(OpBehavior):
    """
    Behavior for the INT_RIGHT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_RIGHT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1.LShR(in2)


class OpBehaviorIntSright(OpBehavior):
    """
    Behavior for the INT_SRIGHT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SRIGHT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1 >> in2


class OpBehaviorIntMult(OpBehavior):
    """
    Behavior for the INT_MULT operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_MULT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1.zero_extend(size_out - size_in) * in2.zero_extend(size_out - size_in)


class OpBehaviorIntDiv(OpBehavior):
    """
    Behavior for the INT_DIV operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_DIV, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 / in2


class OpBehaviorIntSdiv(OpBehavior):
    """
    Behavior for the INT_SDIV operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SDIV, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 / in2

    # uintb OpBehaviorIntSdiv::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   if (in2 == 0)
    #     throw EvaluationError("Divide by 0");
    #   intb num = in1;               // Convert to signed
    #   intb denom = in2;
    #   sign_extend(num,8*size_in-1);
    #   sign_extend(denom,8*size_in-1);
    #   intb sres = num/denom;        // Do the signed division
    #   zero_extend(sres,8*size_out-1); // Cut to appropriate size
    #   return (uintb)sres;           // Recast as unsigned
    # }


class OpBehaviorIntRem(OpBehavior):
    """
    Behavior for the INT_REM operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_REM, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 % in2


class OpBehaviorIntSrem(OpBehavior):
    """
    Behavior for the INT_SREM operation.
    """

    def __init__(self):
        super().__init__(OpCode.INT_SREM, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 % in2

    # uintb OpBehaviorIntSrem::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   if (in2 == 0)
    #     throw EvaluationError("Remainder by 0");
    #   intb val = in1;
    #   intb mod = in2;
    #   sign_extend(val,8*size_in-1);  // Convert inputs to signed values
    #   sign_extend(mod,8*size_in-1);
    #   intb sres = in1 % in2;        // Do the remainder
    #   zero_extend(sres,8*size_out-1); // Convert back to unsigned
    #   return (uintb)sres;
    # }


class OpBehaviorBoolNegate(OpBehavior):
    """
    Behavior for the BOOL_NEGATE operation.
    """

    def __init__(self):
        super().__init__(OpCode.BOOL_NEGATE, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return self.generic_compare((in1, claripy.BVV(0, in1.size())), operator.eq)


class OpBehaviorBoolXor(OpBehavior):
    """
    Behavior for the BOOL_XOR operation.
    """

    def __init__(self):
        super().__init__(OpCode.BOOL_XOR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.booleanize(in1) ^ self.booleanize(in2)


class OpBehaviorBoolAnd(OpBehavior):
    """
    Behavior for the BOOL_AND operation.
    """

    def __init__(self):
        super().__init__(OpCode.BOOL_AND, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.booleanize(in1) & self.booleanize(in2)


class OpBehaviorBoolOr(OpBehavior):
    """
    Behavior for the BOOL_OR operation.
    """

    def __init__(self):
        super().__init__(OpCode.BOOL_OR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.booleanize(in1) | self.booleanize(in2)


class OpBehaviorFloatEqual(OpBehavior):
    """
    Behavior for the FLOAT_EQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_EQUAL, False)

    # uintb OpBehaviorFloatEqual::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opEqual(in1,in2);
    # }


class OpBehaviorFloatNotEqual(OpBehavior):
    """
    Behavior for the FLOAT_NOTEQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_NOTEQUAL, False)

    # uintb OpBehaviorFloatNotEqual::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opNotEqual(in1,in2);
    # }


class OpBehaviorFloatLess(OpBehavior):
    """
    Behavior for the FLOAT_LESS operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_LESS, False)

    # uintb OpBehaviorFloatLess::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opLess(in1,in2);
    # }


class OpBehaviorFloatLessEqual(OpBehavior):
    """
    Behavior for the FLOAT_LESSEQUAL operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_LESSEQUAL, False)

    # uintb OpBehaviorFloatLessEqual::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opLessEqual(in1,in2);
    # }


class OpBehaviorFloatNan(OpBehavior):
    """
    Behavior for the FLOAT_NAN operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_NAN, True)

    # uintb OpBehaviorFloatNan::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opNan(in1);
    # }


class OpBehaviorFloatAdd(OpBehavior):
    """
    Behavior for the FLOAT_ADD operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_ADD, False)

    # uintb OpBehaviorFloatAdd::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opAdd(in1,in2);
    # }


class OpBehaviorFloatDiv(OpBehavior):
    """
    Behavior for the FLOAT_DIV operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_DIV, False)

    # uintb OpBehaviorFloatDiv::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opDiv(in1,in2);
    # }


class OpBehaviorFloatMult(OpBehavior):
    """
    Behavior for the FLOAT_MULT operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_MULT, False)

    # uintb OpBehaviorFloatMult::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opMult(in1,in2);
    # }


class OpBehaviorFloatSub(OpBehavior):
    """
    Behavior for the FLOAT_SUB operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_SUB, False)

    # uintb OpBehaviorFloatSub::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateBinary(size_out,size_in,in1,in2);
    #
    #   return format->opSub(in1,in2);
    # }


class OpBehaviorFloatNeg(OpBehavior):
    """
    Behavior for the FLOAT_NEG operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_NEG, True)

    # uintb OpBehaviorFloatNeg::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opNeg(in1);
    # }


class OpBehaviorFloatAbs(OpBehavior):
    """
    Behavior for the FLOAT_ABS operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_ABS, True)

    # uintb OpBehaviorFloatAbs::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opAbs(in1);
    # }


class OpBehaviorFloatSqrt(OpBehavior):
    """
    Behavior for the FLOAT_SQRT operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_SQRT, True)

    # uintb OpBehaviorFloatSqrt::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opSqrt(in1);
    # }


class OpBehaviorFloatInt2Float(OpBehavior):
    """
    Behavior for the FLOAT_INT2FLOAT operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_INT2FLOAT, True)

    # uintb OpBehaviorFloatInt2Float::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_out);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opInt2Float(in1,size_in);
    # }


class OpBehaviorFloatFloat2Float(OpBehavior):
    """
    Behavior for the FLOAT_FLOAT2FLOAT operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_FLOAT2FLOAT, True)

    # uintb OpBehaviorFloatFloat2Float::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *formatout = translate->getFloatFormat(size_out);
    #   if (formatout == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #   const FloatFormat *formatin = translate->getFloatFormat(size_in);
    #   if (formatin == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return formatin->opFloat2Float(in1,*formatout);
    # }


class OpBehaviorFloatTrunc(OpBehavior):
    """
    Behavior for the FLOAT_TRUNC operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_TRUNC, True)

    # uintb OpBehaviorFloatTrunc::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opTrunc(in1,size_out);
    # }


class OpBehaviorFloatCeil(OpBehavior):
    """
    Behavior for the FLOAT_CEIL operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_CEIL, True)

    # uintb OpBehaviorFloatCeil::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opCeil(in1);
    # }


class OpBehaviorFloatFloor(OpBehavior):
    """
    Behavior for the FLOAT_FLOOR operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_FLOOR, True)

    # uintb OpBehaviorFloatFloor::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opFloor(in1);
    # }


class OpBehaviorFloatRound(OpBehavior):
    """
    Behavior for the FLOAT_ROUND operation.
    """

    def __init__(self):
        super().__init__(OpCode.FLOAT_ROUND, True)

    # uintb OpBehaviorFloatRound::evaluateUnary(int4 size_out,int4 size_in,uintb in1) const
    #
    # {
    #   const FloatFormat *format = translate->getFloatFormat(size_in);
    #   if (format == (const FloatFormat *)0)
    #     return OpBehavior::evaluateUnary(size_out,size_in,in1);
    #
    #   return format->opRound(in1);
    # }


class OpBehaviorPiece(OpBehavior):
    """
    Behavior for the PIECE operation.
    """

    def __init__(self):
        super().__init__(OpCode.PIECE, False)

    # uintb OpBehaviorPiece::evaluateBinary(int4 size_out,int4 size_in,uintb in1,uintb in2) const
    #
    # {
    #   uintb res = ( in1<<((size_out-size_in)*8)) | in2;
    #   return res;
    # }


class OpBehaviorSubpiece(OpBehavior):
    """
    Behavior for the SUBPIECE operation.
    """

    def __init__(self):
        super().__init__(OpCode.SUBPIECE, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        if in2.size() < in1.size():
            in2 = in2.sign_extend(in1.size() - in2.size())
        return (in1 >> (in2 * 8)) & (2 ** (size_out * 8) - 1)


class OpBehaviorPopcount(OpBehavior):
    """
    Behavior for the POPCOUNT operation.
    """

    def __init__(self):
        super().__init__(OpCode.POPCOUNT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        expr = claripy.BVV(0, size_out * 8)
        for a in range(len(in1)):
            expr += claripy.Extract(a, a, in1).zero_extend(size_out * 8 - 1)
        return expr


class OpBehaviorLzcount(OpBehavior):
    """
    Behavior for the LZCOUNT operation.
    """

    def __init__(self):
        super().__init__(OpCode.LZCOUNT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        expr = claripy.BVV(len(in1), size_out * 8)
        for pos in range(len(in1)):
            expr = claripy.If(
                claripy.Extract(pos, pos, in1) == claripy.BVV(1, 1), claripy.BVV(len(in1) - pos - 1, size_out * 8), expr
            )
        return expr


class BehaviorFactory:
    """
    Returns the behavior object for a given opcode.
    """

    def __init__(self):
        self._behaviors = {}
        if OpCode:
            self._register_behaviors()

    def get_behavior_for_opcode(self, opcode: int) -> OpBehavior:
        return self._behaviors[opcode]

    def _register_behaviors(self) -> None:
        self._behaviors.update(
            {
                OpCode.COPY: OpBehaviorCopy(),
                OpCode.LOAD: OpBehavior(OpCode.LOAD, False, True),
                OpCode.STORE: OpBehavior(OpCode.STORE, False, True),
                OpCode.BRANCH: OpBehavior(OpCode.BRANCH, False, True),
                OpCode.CBRANCH: OpBehavior(OpCode.CBRANCH, False, True),
                OpCode.BRANCHIND: OpBehavior(OpCode.BRANCHIND, False, True),
                OpCode.CALL: OpBehavior(OpCode.CALL, False, True),
                OpCode.CALLIND: OpBehavior(OpCode.CALLIND, False, True),
                OpCode.CALLOTHER: OpBehavior(OpCode.CALLOTHER, False, True),
                OpCode.RETURN: OpBehavior(OpCode.RETURN, False, True),
                OpCode.MULTIEQUAL: OpBehavior(OpCode.MULTIEQUAL, False, True),
                OpCode.INDIRECT: OpBehavior(OpCode.INDIRECT, False, True),
                OpCode.PIECE: OpBehaviorPiece(),
                OpCode.SUBPIECE: OpBehaviorSubpiece(),
                OpCode.INT_EQUAL: OpBehaviorEqual(),
                OpCode.INT_NOTEQUAL: OpBehaviorNotEqual(),
                OpCode.INT_SLESS: OpBehaviorIntSless(),
                OpCode.INT_SLESSEQUAL: OpBehaviorIntSlessEqual(),
                OpCode.INT_LESS: OpBehaviorIntLess(),
                OpCode.INT_LESSEQUAL: OpBehaviorIntLessEqual(),
                OpCode.INT_ZEXT: OpBehaviorIntZext(),
                OpCode.INT_SEXT: OpBehaviorIntSext(),
                OpCode.INT_ADD: OpBehaviorIntAdd(),
                OpCode.INT_SUB: OpBehaviorIntSub(),
                OpCode.INT_CARRY: OpBehaviorIntCarry(),
                OpCode.INT_SCARRY: OpBehaviorIntScarry(),
                OpCode.INT_SBORROW: OpBehaviorIntSborrow(),
                OpCode.INT_2COMP: OpBehaviorInt2Comp(),
                OpCode.INT_NEGATE: OpBehaviorIntNegate(),
                OpCode.INT_XOR: OpBehaviorIntXor(),
                OpCode.INT_AND: OpBehaviorIntAnd(),
                OpCode.INT_OR: OpBehaviorIntOr(),
                OpCode.INT_LEFT: OpBehaviorIntLeft(),
                OpCode.INT_RIGHT: OpBehaviorIntRight(),
                OpCode.INT_SRIGHT: OpBehaviorIntSright(),
                OpCode.INT_MULT: OpBehaviorIntMult(),
                OpCode.INT_DIV: OpBehaviorIntDiv(),
                OpCode.INT_SDIV: OpBehaviorIntSdiv(),
                OpCode.INT_REM: OpBehaviorIntRem(),
                OpCode.INT_SREM: OpBehaviorIntSrem(),
                OpCode.BOOL_NEGATE: OpBehaviorBoolNegate(),
                OpCode.BOOL_XOR: OpBehaviorBoolXor(),
                OpCode.BOOL_AND: OpBehaviorBoolAnd(),
                OpCode.BOOL_OR: OpBehaviorBoolOr(),
                OpCode.CAST: OpBehavior(OpCode.CAST, False, True),
                OpCode.PTRADD: OpBehavior(OpCode.PTRADD, False, True),
                OpCode.PTRSUB: OpBehavior(OpCode.PTRSUB, False, True),
                OpCode.FLOAT_EQUAL: OpBehaviorFloatEqual(),
                OpCode.FLOAT_NOTEQUAL: OpBehaviorFloatNotEqual(),
                OpCode.FLOAT_LESS: OpBehaviorFloatLess(),
                OpCode.FLOAT_LESSEQUAL: OpBehaviorFloatLessEqual(),
                OpCode.FLOAT_NAN: OpBehaviorFloatNan(),
                OpCode.FLOAT_ADD: OpBehaviorFloatAdd(),
                OpCode.FLOAT_DIV: OpBehaviorFloatDiv(),
                OpCode.FLOAT_MULT: OpBehaviorFloatMult(),
                OpCode.FLOAT_SUB: OpBehaviorFloatSub(),
                OpCode.FLOAT_NEG: OpBehaviorFloatNeg(),
                OpCode.FLOAT_ABS: OpBehaviorFloatAbs(),
                OpCode.FLOAT_SQRT: OpBehaviorFloatSqrt(),
                OpCode.FLOAT_INT2FLOAT: OpBehaviorFloatInt2Float(),
                OpCode.FLOAT_FLOAT2FLOAT: OpBehaviorFloatFloat2Float(),
                OpCode.FLOAT_TRUNC: OpBehaviorFloatTrunc(),
                OpCode.FLOAT_CEIL: OpBehaviorFloatCeil(),
                OpCode.FLOAT_FLOOR: OpBehaviorFloatFloor(),
                OpCode.FLOAT_ROUND: OpBehaviorFloatRound(),
                OpCode.SEGMENTOP: OpBehavior(OpCode.SEGMENTOP, False, True),
                OpCode.CPOOLREF: OpBehavior(OpCode.CPOOLREF, False, True),
                OpCode.NEW: OpBehavior(OpCode.NEW, False, True),
                OpCode.INSERT: OpBehavior(OpCode.INSERT, False, True),
                OpCode.EXTRACT: OpBehavior(OpCode.EXTRACT, False, True),
                OpCode.POPCOUNT: OpBehaviorPopcount(),
                OpCode.LZCOUNT: OpBehaviorLzcount(),
            }
        )
