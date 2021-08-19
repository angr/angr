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
        return claripy.FPV(math.pow(2, arg_x) - 1, claripy.FSORT_DOUBLE)

    def _concretize_fscale(self, args):
        # fscale(x, y) = x * (2 ** y). Concretize 2**y part alone since only that cannot be modelled in Z3.
        rm = _translate_rm(args[0])
        arg_x = args[1]
        arg_y = self.state.solver.eval(args[2])
        arg_2_y = claripy.FPV(math.pow(2, arg_y), claripy.FSORT_DOUBLE)
        return claripy.fpMul(rm, arg_x, arg_2_y)

    def _concretize_fsqrt(self, args):
        # Concretize floating point square root. Z3 does support square root but unsure if that includes floating point
        return claripy.FPV(math.sqrt(self.state.solver.eval(args[1])), claripy.FSORT_DOUBLE)

    def _concretize_yl2x(self, args):
        # yl2x(y, x) = y * log2(x). Concretize log2(x) part alone since only that cannot be modelled in Z3.
        # 3 arguments are passed: first is FP rounding mode.
        rm = _translate_rm(args[0])
        arg_y = args[1]
        arg_x = claripy.FPV(self.state.solver.eval(args[2]), claripy.FSORT_DOUBLE)
        arg_x = self.state.solver.eval(args[2])
        arg_log2_x = claripy.FPV(math.log2(arg_x), claripy.FSORT_DOUBLE)
        return claripy.fpMul(rm, arg_y, arg_log2_x)
