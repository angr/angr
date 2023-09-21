import math

import claripy

# Copied from engines/vex/claripy/irop.py
fp_rm_map = {
    0: claripy.fp.RM.RM_NearestTiesEven,
    1: claripy.fp.RM.RM_TowardsNegativeInf,
    2: claripy.fp.RM.RM_TowardsPositiveInf,
    3: claripy.fp.RM.RM_TowardsZero,
}


def translate_rm(rm_num):
    if not rm_num.symbolic:
        return fp_rm_map[rm_num.concrete_value]

    return claripy.fp.RM.default()


def concretize_2xm1(state, args):
    # 2xm1(x) = 2 ** x - 1. Concretize 2**x part alone since only that cannot be modelled in Z3.
    arg_x = state.solver.eval(args[1])
    if -1 <= arg_x <= 1:
        return state.solver.FPV(math.pow(2, arg_x) - 1, claripy.FSORT_DOUBLE)

    # If x is outside range [-1.0, 1.0], result is undefined. We return argument itself as observed on an Intel CPU.
    return args[1]


def concretize_abs_float64(state, args):
    arg_val = state.solver.eval(args[0])
    return state.solver.FPV(abs(arg_val), args[0].sort)


def concretize_add_float64(state, args):
    arg0 = state.solver.eval(args[1])
    arg1 = state.solver.eval(args[2])
    return state.solver.FPV(arg0 + arg1, claripy.FSORT_DOUBLE)


def concretize_add32f04(state, args):
    fp_arg0 = state.solver.eval(args[0][31:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][31:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 + fp_arg1, claripy.FSORT_FLOAT).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_add64f02(state, args):
    fp_arg0 = state.solver.eval(args[0][63:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][63:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 + fp_arg1, claripy.FSORT_DOUBLE).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_cmpf64(state, args):
    fp_arg0 = state.solver.eval(args[0])
    fp_arg1 = state.solver.eval(args[1])
    if fp_arg0 < fp_arg1:
        return state.solver.BVV(1, 32)
    if fp_arg0 > fp_arg1:
        return state.solver.BVV(0, 32)
    if fp_arg0 == fp_arg1:
        return state.solver.BVV(0x40, 32)

    return state.solver.BVV(0x45, 32)


def concretize_divf64(state, args):
    arg1 = state.solver.eval(args[1])
    arg2 = state.solver.eval(args[2])
    if arg2 == 0:
        return state.solver.FPV(math.inf, args[1].sort)

    return state.solver.FPV(arg1 / arg2, args[1].sort)


def concretize_div32f04(state, args):
    fp_arg0 = state.solver.eval(args[0][31:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][31:0].raw_to_fp())
    if fp_arg1 == 0:
        result = state.solver.FPV(math.inf, claripy.FSORT_FLOAT).raw_to_bv()
    else:
        result = state.solver.FPV(fp_arg0 / fp_arg1, claripy.FSORT_FLOAT).raw_to_bv()

    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_div64f02(state, args):
    fp_arg0 = state.solver.eval(args[0][63:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][63:0].raw_to_fp())
    if fp_arg1 == 0:
        result = state.solver.FPV(math.inf, claripy.FSORT_DOUBLE).raw_to_bv()
    else:
        result = state.solver.FPV(fp_arg0 / fp_arg1, claripy.FSORT_DOUBLE).raw_to_bv()

    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_float32_to_float64(state, args):
    arg0 = state.solver.eval(args[0])
    return state.solver.FPV(arg0, claripy.FSORT_DOUBLE)


def concretize_float64_to_float32(state, args):
    arg = state.solver.eval(args[1])
    return state.solver.FPV(arg, claripy.FSORT_FLOAT)


def concretize_float64_to_int64s(state, args):
    rm = translate_rm(args[0])
    return state.solver.fpToSBV(rm, args[1], 64)


def concretize_int32s_to_float64(state, args):
    arg = state.solver.BVV(state.solver.eval(args[0]), args[0].size())
    return arg.val_to_fp(claripy.fp.FSort.from_size(64), signed=True, rm=fp_rm_map[0])


def concretize_int64s_to_float64(state, args):
    rm = translate_rm(args[0])
    arg = state.solver.BVV(state.solver.eval(args[1]), args[1].size())
    return arg.val_to_fp(claripy.fp.FSort.from_size(64), signed=True, rm=rm)


def concretize_mulf64(state, args):
    arg1 = state.solver.eval(args[1])
    arg2 = state.solver.eval(args[2])
    return state.solver.FPV(arg1 / arg2, args[1].sort)


def concretize_mul32f04(state, args):
    fp_arg0 = state.solver.eval(args[0][31:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][31:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 * fp_arg1, claripy.FSORT_FLOAT).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_mul64f02(state, args):
    fp_arg0 = state.solver.eval(args[0][63:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][63:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 * fp_arg1, claripy.FSORT_DOUBLE).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_fscale(state, args):
    # fscale(x, y) = x * (2 ** y)
    arg_x = state.solver.eval(args[1])
    arg_y = math.floor(state.solver.eval(args[2]))
    if math.isnan(arg_x) or math.isnan(arg_y):
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs(arg_x) == math.inf and arg_y == -1 * math.inf:
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if arg_x == 0.0 and arg_y == math.inf:
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    return state.solver.FPV(arg_x * math.pow(2, arg_y), claripy.FSORT_DOUBLE)


def concretize_fsqrt(state, args):
    # Concretize floating point square root. Z3 does support square root but unsure if that includes floating point
    arg_1 = state.solver.eval(args[1])
    if arg_1 < 0 or math.isnan(arg_1):
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    return state.solver.FPV(math.sqrt(arg_1), claripy.FSORT_DOUBLE)


def concretize_prem(state, args):
    # Compute partial remainder. Z3 does not support modulo for reals: https://github.com/Z3Prover/z3/issues/557
    # Implementation based on description in the Intel software manual
    dividend = state.solver.eval(args[1])
    divisor = state.solver.eval(args[2])
    if math.isnan(dividend) or math.isnan(divisor) or abs(dividend) == math.inf or divisor == 0.0:
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs(divisor) == math.inf or dividend == 0.0:
        return args[1]

    _, exp_dividend = math.frexp(dividend)
    _, exp_divisor = math.frexp(divisor)
    if exp_dividend - exp_divisor < 64:
        quotient = math.floor(dividend / divisor)
        result = dividend - (divisor * quotient)
    else:
        # According to Intel manual, N is an implementation-dependent number between 32 and 63. 60 was chosen
        # arbitrarily.
        N = 60
        quotient = math.floor((dividend / divisor) / pow(2, exp_dividend - exp_divisor - N))
        result = dividend - (divisor * quotient * pow(2, exp_dividend - exp_divisor - N))

    if result == 0.0:
        if math.copysign(1.0, dividend) < 0:
            # According to Intel manual, if result is 0, its sign should be same as that of dividend.
            return state.solver.FPV(-0.0, claripy.FSORT_DOUBLE)

    return state.solver.FPV(result, claripy.FSORT_DOUBLE)


def concretize_prem_flags(state, args):
    # Compute FPU flags for partial remainder.
    # Implementation based on description in the Intel software manual
    dividend = state.solver.eval(args[1])
    divisor = state.solver.eval(args[2])
    # pylint: disable=too-many-boolean-expressions
    if (
        math.isnan(dividend)
        or math.isnan(divisor)
        or abs(dividend) == math.inf
        or divisor == 0.0
        or abs(divisor) == math.inf
        or dividend == 0.0
    ):
        # Since these are exception cases, the manual does not specify anything for these flags. These are set to
        # zero based on what was observed on an Intel CPU.
        flag_c0 = 0
        flag_c1 = 0
        flag_c2 = 0
        flag_c3 = 0
    else:
        _, exp_dividend = math.frexp(dividend)
        _, exp_divisor = math.frexp(divisor)
        if exp_dividend - exp_divisor < 64:
            quotient = math.floor(dividend / divisor)
            flag_c2 = 0
            flag_c0 = (quotient & 4) >> 2
            flag_c3 = (quotient & 2) >> 1
            flag_c1 = quotient & 1
        else:
            # Nothing is explicitly specified for C0 and C3 bits in this case so arbitrarily set to 0
            # TODO: C1 should be set to 0 only if floating point stack underflows. How to detect that?
            flag_c2 = 1
            flag_c0 = 0
            flag_c1 = 0
            flag_c3 = 0

    flags = (flag_c3 << 14) | (flag_c2 << 10) | (flag_c1 << 9) | (flag_c0 << 8)
    return claripy.BVV(flags, 16)


def concretize_reinterp_float64_as_int64(state, args):
    return state.solver.FPV(state.solver.eval(args[0]), args[0].sort).raw_to_bv()


def concretize_sub32f04(state, args):
    fp_arg0 = state.solver.eval(args[0][31:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][31:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 - fp_arg1, claripy.FSORT_FLOAT).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_sub64f02(state, args):
    fp_arg0 = state.solver.eval(args[0][63:0].raw_to_fp())
    fp_arg1 = state.solver.eval(args[1][63:0].raw_to_fp())
    result = state.solver.FPV(fp_arg0 - fp_arg1, claripy.FSORT_DOUBLE).raw_to_bv()
    return claripy.Concat(args[0][(args[0].length - 1) : result.size()], result)


def concretize_trig_cos(state, args):
    # cos(x). Z3 does support *some* cases of cos(see https://github.com/Z3Prover/z3/issues/680) but we don't use
    # the feature and concretize fully instead.
    arg_x = state.solver.eval(args[1])
    abs_arg_x = abs(arg_x)

    if math.isnan(abs_arg_x):
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x == math.inf:
        # Floating-point invalid-operation exception
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x > pow(2, 63):
        # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
        # exception: leave value changed
        return args[1]

    return state.solver.FPV(math.cos(arg_x), claripy.FSORT_DOUBLE)


def concretize_trig_sin(state, args):
    # sin(x). Z3 does support *some* cases of sin(see https://github.com/Z3Prover/z3/issues/680) but we don't use
    # the feature and concretize fully instead.
    arg_x = state.solver.eval(args[1])
    abs_arg_x = abs(arg_x)

    if math.isnan(abs_arg_x):
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x == math.inf:
        # Floating-point invalid-operation exception
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x > pow(2, 63):
        # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
        # exception: leave value changed
        return args[1]

    return state.solver.FPV(math.sin(arg_x), claripy.FSORT_DOUBLE)


def concretize_trig_tan(state, args):
    # tan(x). Concretize fully since it cannot be modelled in Z3.
    # TODO: How to handle NaN arg?
    arg_x = state.solver.eval(args[1])
    abs_arg_x = abs(arg_x)

    if math.isnan(abs_arg_x):
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x == math.inf:
        # Floating-point invalid-operation exception
        return state.solver.FPV(math.nan, claripy.FSORT_DOUBLE)

    if abs_arg_x > pow(2, 63):
        # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
        # exception: leave value changed
        return args[1]

    return state.solver.FPV(math.tan(arg_x), claripy.FSORT_DOUBLE)


def concretize_yl2x(state, args):
    # yl2x(y, x) = y * log2(x)
    # 3 arguments are passed: first is FP rounding mode. y is from st(1) and x from st(0).
    # TODO: Return NaN if either arg is non-numeric.
    # TODO: Set FPU flags.
    arg_x = state.solver.eval(args[2])
    arg_y = state.solver.eval(args[1])
    if arg_x < 0:
        # TODO: Indicate floating-point invalid-operation exception
        return state.solver.FPV(arg_x, claripy.FSORT_DOUBLE)

    if arg_x == 0:
        if abs(arg_y) == math.inf:
            return state.solver.FPV(-1 * arg_y, claripy.FSORT_DOUBLE)
        elif arg_y == 0:
            # TODO: Indicate floating-point invalid-operation exception
            return state.solver.FPV(arg_x, claripy.FSORT_DOUBLE)
        else:
            # TODO: Indicate floating-point zero-division exception
            return state.solver.FPV(arg_x, claripy.FSORT_DOUBLE)

    if arg_x == 1:
        if abs(arg_y) == math.inf:
            # TODO: Indicate floating-point invalid-operation exception
            return state.solver.FPV(arg_x, claripy.FSORT_DOUBLE)

        # TODO: How to distiguish between +0 and -0?
        return state.solver.FPV(0, claripy.FSORT_DOUBLE)

    if arg_x == math.inf:
        if arg_y == 0:
            # TODO: Indicate floating-point invalid-operation exception
            return state.solver.FPV(arg_x, claripy.FSORT_DOUBLE)
        if arg_y < 0:
            return state.solver.FPV(-1 * math.inf, claripy.FSORT_DOUBLE)

        return state.solver.FPV(math.inf, claripy.FSORT_DOUBLE)

    return state.solver.FPV(arg_y * math.log2(arg_x), claripy.FSORT_DOUBLE)


concretizers = {
    "Iop_Yl2xF64": concretize_yl2x,
    "Iop_ScaleF64": concretize_fscale,
    "Iop_2xm1F64": concretize_2xm1,
    "Iop_SqrtF64": concretize_fsqrt,
    "Iop_CosF64": concretize_trig_cos,
    "Iop_SinF64": concretize_trig_sin,
    "Iop_TanF64": concretize_trig_tan,
    "Iop_PRemF64": concretize_prem,
    "Iop_PRemC3210F64": concretize_prem_flags,
    "Iop_I32StoF64": concretize_int32s_to_float64,
    "Iop_Mul64F0x2": concretize_mul64f02,
    "Iop_Add64F0x2": concretize_add64f02,
    "Iop_Div64F0x2": concretize_div64f02,
    "Iop_I64StoF64": concretize_int64s_to_float64,
    "Iop_DivF64": concretize_divf64,
    "Iop_MulF64": concretize_mulf64,
    "Iop_F64toI64S": concretize_float64_to_int64s,
    "Iop_AbsF64": concretize_abs_float64,
    "Iop_Sub64F0x2": concretize_sub64f02,
    "Iop_AddF64": concretize_add_float64,
    "Iop_F64toF32": concretize_float64_to_float32,
    "Iop_Div32F0x4": concretize_div32f04,
    "Iop_Sub32F0x4": concretize_sub32f04,
    "Iop_Add32F0x4": concretize_add32f04,
    "Iop_Mul32F0x4": concretize_mul32f04,
    "Iop_CmpF64": concretize_cmpf64,
    "Iop_F32toF64": concretize_float32_to_float64,
    "Iop_ReinterpF64asI64": concretize_reinterp_float64_as_int64,
}
