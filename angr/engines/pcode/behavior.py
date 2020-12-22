import operator
from typing import Callable, Iterable, Tuple

from pypcode import OpCode, Sleigh
import claripy
from claripy.ast.bv import BV

# pylint:disable=abstract-method

def make_bv_sizes_equal(bv1: BV, bv2: BV) -> Tuple[BV, BV]:
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

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        raise NotImplementedError("Not implemented!")

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        raise NotImplementedError("Not implemented!")

    @staticmethod
    def generic_compare(args: Iterable[BV], comparison: Callable[[BV, BV], BV]) -> BV:
        return claripy.If(
            comparison(args[0], args[1]), claripy.BVV(1, 1), claripy.BVV(0, 1)
        )


class OpBehaviorCopy(OpBehavior):
    """
    Behavior for the COPY operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_COPY, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1


class OpBehaviorEqual(OpBehavior):
    """
    Behavior for the INT_EQUAL operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_EQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), operator.eq)


class OpBehaviorNotEqual(OpBehavior):
    """
    Behavior for the INT_NOTEQUAL operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_NOTEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), operator.ne)


class OpBehaviorIntSless(OpBehavior):
    """
    Behavior for the INT_SLESS operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SLESS, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.SLT)


class OpBehaviorIntSlessEqual(OpBehavior):
    """
    Behavior for the INT_SLESSEQUAL operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SLESSEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.SLE)


class OpBehaviorIntLess(OpBehavior):
    """
    Behavior for the INT_LESS operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_LESS, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.ULT)


class OpBehaviorIntLessEqual(OpBehavior):
    """
    Behavior for the INT_LESSEQUAL operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_LESSEQUAL, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return self.generic_compare((in1, in2), claripy.ULE)


class OpBehaviorIntZext(OpBehavior):
    """
    Behavior for the INT_ZEXT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_ZEXT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1.zero_extend((size_out-size_in)*8)


class OpBehaviorIntSext(OpBehavior):
    """
    Behavior for the INT_SEXT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SEXT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1.sign_extend((size_out-size_in)*8)


class OpBehaviorIntAdd(OpBehavior):
    """
    Behavior for the INT_ADD operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_ADD, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 + in2


class OpBehaviorIntSub(OpBehavior):
    """
    Behavior for the INT_SUB operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SUB, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 - in2


class OpBehaviorIntCarry(OpBehavior):
    """
    Behavior for the INT_CARRY operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_CARRY, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        # origin: ccall.py pc_actions_ADD
        res = in1 + in2
        return claripy.If(claripy.ULT(res, in1), claripy.BVV(1, 1), claripy.BVV(0, 1))


class OpBehaviorIntScarry(OpBehavior):
    """
    Behavior for the INT_SCARRY operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SCARRY, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        res = in1 + in2

        a = (in1>>(size_in*8-1))&1
        b = (in2>>(size_in*8-1))&1
        r = (res>>(size_in*8-1))&1

        r ^= a
        a ^= b
        a ^= 1
        r &= a

        return r


class OpBehaviorIntSborrow(OpBehavior):
    """
    Behavior for the INT_SBORROW operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SBORROW, False)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_2COMP, True)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_NEGATE, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return ~in1


class OpBehaviorIntXor(OpBehavior):
    """
    Behavior for the INT_XOR operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_XOR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 ^ in2


class OpBehaviorIntAnd(OpBehavior):
    """
    Behavior for the INT_AND operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_AND, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 & in2


class OpBehaviorIntOr(OpBehavior):
    """
    Behavior for the INT_OR operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_OR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 | in2


class OpBehaviorIntLeft(OpBehavior):
    """
    Behavior for the INT_LEFT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_LEFT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1 << in2


class OpBehaviorIntRight(OpBehavior):
    """
    Behavior for the INT_RIGHT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_RIGHT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1.LShR(in2)


class OpBehaviorIntSright(OpBehavior):
    """
    Behavior for the INT_SRIGHT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SRIGHT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        in1, in2 = make_bv_sizes_equal(in1, in2)
        return in1 >> in2


class OpBehaviorIntMult(OpBehavior):
    """
    Behavior for the INT_MULT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_MULT, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 * in2


class OpBehaviorIntDiv(OpBehavior):
    """
    Behavior for the INT_DIV operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_DIV, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 / in2


class OpBehaviorIntSdiv(OpBehavior):
    """
    Behavior for the INT_SDIV operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SDIV, False)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_REM, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 % in2


class OpBehaviorIntSrem(OpBehavior):
    """
    Behavior for the INT_SREM operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_INT_SREM, False)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_BOOL_NEGATE, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        return in1 ^ 1


class OpBehaviorBoolXor(OpBehavior):
    """
    Behavior for the BOOL_XOR operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_BOOL_XOR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 ^ in2


class OpBehaviorBoolAnd(OpBehavior):
    """
    Behavior for the BOOL_AND operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_BOOL_AND, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 & in2


class OpBehaviorBoolOr(OpBehavior):
    """
    Behavior for the BOOL_OR operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_BOOL_OR, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        return in1 | in2


class OpBehaviorFloatEqual(OpBehavior):
    """
    Behavior for the FLOAT_EQUAL operation.
    """

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_EQUAL, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_NOTEQUAL, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_LESS, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_LESSEQUAL, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_NAN, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_ADD, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_DIV, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_MULT, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_SUB, False)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_NEG, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_ABS, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_SQRT, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_INT2FLOAT, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_FLOAT2FLOAT, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_TRUNC, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_CEIL, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_FLOOR, True)

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

    __slots__ = ("opcode", "is_unary", "is_special", "_translate")
    _translate: Sleigh

    def __init__(self, trans: Sleigh) -> None:
        self._translate = trans
        super().__init__(OpCode.CPUI_FLOAT_ROUND, True)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_PIECE, False)

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
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_SUBPIECE, False)

    def evaluate_binary(self, size_out: int, size_in: int, in1: BV, in2: BV) -> BV:
        if in2.size() < in1.size():
            in2 = in2.sign_extend(in1.size() - in2.size())
        return (in1>>(in2*8)) & (2**(size_out*8)-1)


class OpBehaviorPopcount(OpBehavior):
    """
    Behavior for the POPCOUNT operation.
    """
    def __init__(self) -> None:
        super().__init__(OpCode.CPUI_POPCOUNT, True)

    def evaluate_unary(self, size_out: int, size_in: int, in1: BV) -> BV:
        expr = claripy.BVV(0, size_out*8)
        for a in range(len(in1)):
            expr += claripy.Extract(a, a, in1).zero_extend(size_out*8-1)
        return expr


class BehaviorFactory:
    """
    Returns the behavior object for a given opcode.
    """
    def __init__(self, trans: Sleigh = None) -> None:
        self._trans = trans
        self._behaviors = {}
        self._register_behaviors()

    def get_behavior_for_opcode(self, opcode: int) -> OpBehavior:
        return self._behaviors[opcode]

    def _register_behaviors(self) -> None:
        self._behaviors.update({
            OpCode.CPUI_COPY: OpBehaviorCopy(),
            OpCode.CPUI_LOAD: OpBehavior(OpCode.CPUI_LOAD, False, True),
            OpCode.CPUI_STORE: OpBehavior(OpCode.CPUI_STORE, False, True),
            OpCode.CPUI_BRANCH: OpBehavior(OpCode.CPUI_BRANCH, False, True),
            OpCode.CPUI_CBRANCH: OpBehavior(OpCode.CPUI_CBRANCH, False, True),
            OpCode.CPUI_BRANCHIND: OpBehavior(OpCode.CPUI_BRANCHIND, False, True),
            OpCode.CPUI_CALL: OpBehavior(OpCode.CPUI_CALL, False, True),
            OpCode.CPUI_CALLIND: OpBehavior(OpCode.CPUI_CALLIND, False, True),
            OpCode.CPUI_CALLOTHER: OpBehavior(OpCode.CPUI_CALLOTHER, False, True),
            OpCode.CPUI_RETURN: OpBehavior(OpCode.CPUI_RETURN, False, True),
            OpCode.CPUI_MULTIEQUAL: OpBehavior(OpCode.CPUI_MULTIEQUAL, False, True),
            OpCode.CPUI_INDIRECT: OpBehavior(OpCode.CPUI_INDIRECT, False, True),
            OpCode.CPUI_PIECE: OpBehaviorPiece(),
            OpCode.CPUI_SUBPIECE: OpBehaviorSubpiece(),
            OpCode.CPUI_INT_EQUAL: OpBehaviorEqual(),
            OpCode.CPUI_INT_NOTEQUAL: OpBehaviorNotEqual(),
            OpCode.CPUI_INT_SLESS: OpBehaviorIntSless(),
            OpCode.CPUI_INT_SLESSEQUAL: OpBehaviorIntSlessEqual(),
            OpCode.CPUI_INT_LESS: OpBehaviorIntLess(),
            OpCode.CPUI_INT_LESSEQUAL: OpBehaviorIntLessEqual(),
            OpCode.CPUI_INT_ZEXT: OpBehaviorIntZext(),
            OpCode.CPUI_INT_SEXT: OpBehaviorIntSext(),
            OpCode.CPUI_INT_ADD: OpBehaviorIntAdd(),
            OpCode.CPUI_INT_SUB: OpBehaviorIntSub(),
            OpCode.CPUI_INT_CARRY: OpBehaviorIntCarry(),
            OpCode.CPUI_INT_SCARRY: OpBehaviorIntScarry(),
            OpCode.CPUI_INT_SBORROW: OpBehaviorIntSborrow(),
            OpCode.CPUI_INT_2COMP: OpBehaviorInt2Comp(),
            OpCode.CPUI_INT_NEGATE: OpBehaviorIntNegate(),
            OpCode.CPUI_INT_XOR: OpBehaviorIntXor(),
            OpCode.CPUI_INT_AND: OpBehaviorIntAnd(),
            OpCode.CPUI_INT_OR: OpBehaviorIntOr(),
            OpCode.CPUI_INT_LEFT: OpBehaviorIntLeft(),
            OpCode.CPUI_INT_RIGHT: OpBehaviorIntRight(),
            OpCode.CPUI_INT_SRIGHT: OpBehaviorIntSright(),
            OpCode.CPUI_INT_MULT: OpBehaviorIntMult(),
            OpCode.CPUI_INT_DIV: OpBehaviorIntDiv(),
            OpCode.CPUI_INT_SDIV: OpBehaviorIntSdiv(),
            OpCode.CPUI_INT_REM: OpBehaviorIntRem(),
            OpCode.CPUI_INT_SREM: OpBehaviorIntSrem(),
            OpCode.CPUI_BOOL_NEGATE: OpBehaviorBoolNegate(),
            OpCode.CPUI_BOOL_XOR: OpBehaviorBoolXor(),
            OpCode.CPUI_BOOL_AND: OpBehaviorBoolAnd(),
            OpCode.CPUI_BOOL_OR: OpBehaviorBoolOr(),
            OpCode.CPUI_CAST: OpBehavior(OpCode.CPUI_CAST, False, True),
            OpCode.CPUI_PTRADD: OpBehavior(OpCode.CPUI_PTRADD, False, True),
            OpCode.CPUI_PTRSUB: OpBehavior(OpCode.CPUI_PTRSUB, False, True),
            OpCode.CPUI_FLOAT_EQUAL: OpBehaviorFloatEqual(self._trans),
            OpCode.CPUI_FLOAT_NOTEQUAL: OpBehaviorFloatNotEqual(self._trans),
            OpCode.CPUI_FLOAT_LESS: OpBehaviorFloatLess(self._trans),
            OpCode.CPUI_FLOAT_LESSEQUAL: OpBehaviorFloatLessEqual(self._trans),
            OpCode.CPUI_FLOAT_NAN: OpBehaviorFloatNan(self._trans),
            OpCode.CPUI_FLOAT_ADD: OpBehaviorFloatAdd(self._trans),
            OpCode.CPUI_FLOAT_DIV: OpBehaviorFloatDiv(self._trans),
            OpCode.CPUI_FLOAT_MULT: OpBehaviorFloatMult(self._trans),
            OpCode.CPUI_FLOAT_SUB: OpBehaviorFloatSub(self._trans),
            OpCode.CPUI_FLOAT_NEG: OpBehaviorFloatNeg(self._trans),
            OpCode.CPUI_FLOAT_ABS: OpBehaviorFloatAbs(self._trans),
            OpCode.CPUI_FLOAT_SQRT: OpBehaviorFloatSqrt(self._trans),
            OpCode.CPUI_FLOAT_INT2FLOAT: OpBehaviorFloatInt2Float(self._trans),
            OpCode.CPUI_FLOAT_FLOAT2FLOAT: OpBehaviorFloatFloat2Float(self._trans),
            OpCode.CPUI_FLOAT_TRUNC: OpBehaviorFloatTrunc(self._trans),
            OpCode.CPUI_FLOAT_CEIL: OpBehaviorFloatCeil(self._trans),
            OpCode.CPUI_FLOAT_FLOOR: OpBehaviorFloatFloor(self._trans),
            OpCode.CPUI_FLOAT_ROUND: OpBehaviorFloatRound(self._trans),
            OpCode.CPUI_SEGMENTOP: OpBehavior(OpCode.CPUI_SEGMENTOP, False, True),
            OpCode.CPUI_CPOOLREF: OpBehavior(OpCode.CPUI_CPOOLREF, False, True),
            OpCode.CPUI_NEW: OpBehavior(OpCode.CPUI_NEW, False, True),
            OpCode.CPUI_INSERT: OpBehavior(OpCode.CPUI_INSERT, False, True),
            OpCode.CPUI_EXTRACT: OpBehavior(OpCode.CPUI_EXTRACT, False, True),
            OpCode.CPUI_POPCOUNT: OpBehaviorPopcount(),
            })
