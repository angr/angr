import math

import claripy
import pyvex

from ..light.resilience import VEXResilienceMixin, raiseme
from ..claripy.datalayer import ClaripyDataMixin, symbol, value
from angr import sim_options as o

# Copied from engines/vex/claripy/irop.py
fp_rm_map = {
    0: claripy.fp.RM.RM_NearestTiesEven,
    1: claripy.fp.RM.RM_TowardsNegativeInf,
    2: claripy.fp.RM.RM_TowardsPositiveInf,
    3: claripy.fp.RM.RM_TowardsZero,
}

def _translate_rm(rm_num):
    if not rm_num.symbolic:
        return fp_rm_map[rm_num._model_concrete.value]

    return claripy.fp.RM.default()

class HeavyResilienceMixin(VEXResilienceMixin, ClaripyDataMixin):
    @staticmethod
    def __make_default(ty, symbolic, name):
        if symbolic:
            return symbol(ty, name)
        else:
            return value(ty, 0)

    def _check_unsupported_ccall(self, func_name, retty, args, **kwargs):
        if o.BYPASS_UNSUPPORTED_IRCCALL not in self.state.options:
            return super()._check_unsupported_ccall(func_name, retty, args, **kwargs)
        self.state.history.add_event('resilience', resilience_type='ccall', callee=func_name, message='unsupported ccall')
        return self.__make_default(retty, o.UNSUPPORTED_BYPASS_ZERO_DEFAULT not in self.state.options, 'unsupported_' + func_name)

    def _check_errored_ccall(self, func_name, ty, args, **kwargs):
        if o.BYPASS_ERRORED_IRCCALL not in self.state.options:
            return super()._check_errored_ccall(func_name, ty, args, **kwargs)
        self.state.history.add_event('resilience', resilience_type='ccall', callee=func_name, message='ccall raised SimCCallError')
        return self.__make_default(ty, True, 'errored_' + func_name)

    def _check_unsupported_dirty(self, func_name, ty, args, **kwargs):
        if o.BYPASS_UNSUPPORTED_IRDIRTY not in self.state.options:
            return super()._check_unsupported_dirty(func_name, ty, args, **kwargs)
        if ty is None:
            return None
        return self.__make_default(ty, o.UNSUPPORTED_BYPASS_ZERO_DEFAULT not in self.state.options, 'unsupported_' + func_name)

    def _check_unsupported_op(self, op, args):
        ty = pyvex.get_op_retty(op)
        if o.BYPASS_UNSUPPORTED_IROP not in self.state.options:
            return super()._check_unsupported_op(op, args)

        force_concretizers = {"Iop_Yl2xF64": self._concretize_yl2x, "Iop_ScaleF64": self._concretize_fscale,
                              "Iop_2xm1F64": self._concretize_2xm1, "Iop_SqrtF64": self._concretize_fsqrt,
                              "Iop_CosF64": self._concretize_trig_cos, "Iop_SinF64": self._concretize_trig_sin,
                              "Iop_TanF64": self._concretize_trig_tan, "Iop_PRemF64": self._concretize_prem,
                              "Iop_PRemC3210F64": self._concretize_prem_flags
                             }
        self.state.history.add_event('resilience', resilience_type='irop', op=op, message='unsupported IROp')
        if o.UNSUPPORTED_FORCE_CONCRETIZE in self.state.options:
            try:
                concretizer = force_concretizers[op]
                return concretizer(args)
            except KeyError:
                pass

        return self.__make_default(ty, o.UNSUPPORTED_BYPASS_ZERO_DEFAULT not in self.state.options, 'unsupported_' + op)

    def _check_errored_op(self, op, args):
        ty = pyvex.get_op_retty(op)
        if o.BYPASS_ERRORED_IROP not in self.state.options:
            return super()._check_errored_op(op, args)
        self.state.history.add_event('resilience', resilience_type='irop', op=op, message='unsupported IROp')
        return self.__make_default(ty, True, 'errored_' + op)

    def _check_zero_division(self, op, args):
        if getattr(self.state, 'mode', None) == 'static' and len(args) == 2 and (args[1] == 0).is_true():
            # Monkeypatch the dividend to another value instead of 0
            args = list(args)
            ty = pyvex.expr.op_arg_types(op)[1][1]
            args[1] = value(ty, 1)
            return self._perform_vex_expr_Op(op, args)
        res = super()._check_zero_division(op, args)
        if res is not raiseme:
            return res
        return self._check_errored_op(op, args)

    def _check_errored_stmt(self, stmt):
        if o.BYPASS_ERRORED_IRSTMT not in self.state.options:
            return super()._check_errored_stmt(stmt)
        self.state.history.add_event(
                'resilience',
                resilience_type='irstmt',
                stmt=type(stmt).__name__,
                message='errored IRStmt')
        return None

    def _concretize_2xm1(self, args):
        # 2xm1(x) = 2 ** x - 1. Concretize 2**x part alone since only that cannot be modelled in Z3.
        arg_x = self.state.solver.eval(args[1])
        if -1 <= arg_x <= 1:
            return claripy.FPV(math.pow(2, arg_x) - 1, claripy.FSORT_DOUBLE)

        # If x is outside range [-1.0, 1.0], result is undefined. We return argument itself as observed on an Intel CPU.
        return args[1]

    def _concretize_fscale(self, args):
        # fscale(x, y) = x * (2 ** y). Concretize 2**y part alone since only that cannot be modelled in Z3.
        rm = _translate_rm(args[0])
        arg_x = args[1]
        arg_y = args[2]
        e_arg_x = self.state.solver.eval(arg_x)
        e_arg_y = math.floor(self.state.solver.eval(arg_y))
        if math.isnan(e_arg_x) or math.isnan(e_arg_y):
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs(e_arg_x) == math.inf and e_arg_y == -1 * math.inf:
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if e_arg_x == 0.0 and e_arg_y == math.inf:
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        arg_2_y = claripy.FPV(math.pow(2, e_arg_y), claripy.FSORT_DOUBLE)
        return claripy.fpMul(rm, arg_x, arg_2_y)

    def _concretize_fsqrt(self, args):
        # Concretize floating point square root. Z3 does support square root but unsure if that includes floating point
        arg_1 = self.state.solver.eval(args[1])
        if arg_1 < 0 or math.isnan(arg_1):
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        return claripy.FPV(math.sqrt(arg_1), claripy.FSORT_DOUBLE)

    def _concretize_prem(self, args):
        # Compute partial remainder. Z3 does not support modulo for reals: https://github.com/Z3Prover/z3/issues/557
        # Implementation based on description in the Intel software manual
        dividend = self.state.solver.eval(args[1])
        divisor = self.state.solver.eval(args[2])
        _, exp_dividend = math.frexp(dividend)
        _, exp_divisor = math.frexp(divisor)
        if exp_dividend - exp_divisor < 64:
            quotient = math.floor(dividend/divisor)
            result = dividend - (divisor * quotient)
        else:
            # According to Intel manual, N is an implementation-dependent number between 32 and 63. 60 was chosen
            # arbitrarily.
            N = 60
            quotient = math.floor((dividend / divisor) / pow(2, exp_dividend - exp_divisor - N))
            result = dividend - (divisor * quotient * pow(2, exp_dividend - exp_divisor - N))

        return claripy.FPV(result, claripy.FSORT_DOUBLE)

    def _concretize_prem_flags(self, args):
        # Compute FPU flags for partial remainder.
        # Implementation based on description in the Intel software manual
        dividend = self.state.solver.eval(args[1])
        divisor = self.state.solver.eval(args[2])
        _, exp_dividend = math.frexp(dividend)
        _, exp_divisor = math.frexp(divisor)
        if exp_dividend - exp_divisor < 64:
            quotient = math.floor(dividend/divisor)
            flag_c2 = 0
            flag_c0 = (quotient & 4) >> 2
            flag_c3 = (quotient & 2) >> 1
            flag_c1 = (quotient & 1)
        else:
            # Nothing is explicitly mentioned for C0 and C3 bits in this case so arbitrarily set to 0
            # TODO: C1 should be set to 0 only if floating point stack underflows. How to detect that?
            flag_c2 = 1
            flag_c0 = 0
            flag_c1 = 0
            flag_c3 = 0

        flags = (flag_c3 << 14) | (flag_c2 << 10) | (flag_c1 << 9) | (flag_c0 << 8)
        return claripy.BVV(flags, 16)

    def _concretize_trig_cos(self, args):
        # cos(x). Z3 does support *some* cases of cos(see https://github.com/Z3Prover/z3/issues/680) but we don't use
        # the feature and concretize fully instead.
        arg_x = self.state.solver.eval(args[1])
        abs_arg_x = abs(arg_x)

        if math.isnan(abs_arg_x):
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x == math.inf:
            # Floating-point invalid-operation exception
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x > pow(2, 63):
            # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
            # exception: leave value changed
            return args[1]

        return claripy.FPV(math.cos(arg_x), claripy.FSORT_DOUBLE)

    def _concretize_trig_sin(self, args):
        # sin(x). Z3 does support *some* cases of sin(see https://github.com/Z3Prover/z3/issues/680) but we don't use
        # the feature and concretize fully instead.
        arg_x = self.state.solver.eval(args[1])
        abs_arg_x = abs(arg_x)

        if math.isnan(abs_arg_x):
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x == math.inf:
            # Floating-point invalid-operation exception
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x > pow(2, 63):
            # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
            # exception: leave value changed
            return args[1]

        return claripy.FPV(math.sin(arg_x), claripy.FSORT_DOUBLE)

    def _concretize_trig_tan(self, args):
        # tan(x). Concretize fully since it cannot be modelled in Z3.
        # TODO: How to handle NaN arg?
        arg_x = self.state.solver.eval(args[1])
        abs_arg_x = abs(arg_x)

        if math.isnan(abs_arg_x):
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x == math.inf:
            # Floating-point invalid-operation exception
            return claripy.FPV(math.nan, claripy.FSORT_DOUBLE)

        if abs_arg_x > pow(2, 63):
            # Intel manual says argument must be in range [-2^63, 2^63]. Otherwise, floating-point invalid-operation
            # exception: leave value changed
            return args[1]

        return claripy.FPV(math.tan(arg_x), claripy.FSORT_DOUBLE)

    def _concretize_yl2x(self, args):
        # yl2x(y, x) = y * log2(x). Concretize log2(x) part alone since only that cannot be modelled in Z3.
        # 3 arguments are passed: first is FP rounding mode. y is from st(1) and x from st(0).
        # TODO: Return NaN if either arg is non-numeric.
        # TODO: Set FPU flags.
        rm = _translate_rm(args[0])
        arg_y = args[1]
        arg_x = args[2]
        e_arg_x = self.state.solver.eval(arg_x)
        e_arg_y = self.state.solver.eval(arg_y)
        if e_arg_x < 0:
            # TODO: Indicate floating-point invalid-operation exception
            return arg_x

        if e_arg_x == 0:
            if abs(e_arg_y) == math.inf:
                return claripy.FPV(-1 * e_arg_y, claripy.FSORT_DOUBLE)
            elif e_arg_y == 0:
                # TODO: Indicate floating-point invalid-operation exception
                return arg_x
            else:
                # TODO: Indicate floating-point zero-division exception
                return arg_x

        if e_arg_x == 1:
            if abs(e_arg_y) == math.inf:
                # TODO: Indicate floating-point invalid-operation exception
                return arg_x

            # TODO: How to distiguish between +0 and -0?
            return claripy.FPV(0, claripy.FSORT_DOUBLE)

        if e_arg_x == math.inf:
            if e_arg_y == 0:
                # TODO: Indicate floating-point invalid-operation exception
                return arg_x
            if e_arg_y < 0:
                return claripy.FPV(-1 * math.inf, claripy.FSORT_DOUBLE)

            return claripy.FPV(math.inf, claripy.FSORT_DOUBLE)

        log2_arg_x = claripy.FPV(math.log2(e_arg_x), claripy.FSORT_DOUBLE)
        return claripy.fpMul(rm, arg_y, log2_arg_x)
