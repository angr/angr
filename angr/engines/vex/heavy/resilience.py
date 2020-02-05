import pyvex

from ..light.resilience import VEXResilienceMixin, raiseme
from ..claripy.datalayer import ClaripyDataMixin, symbol, value
from angr import sim_options as o

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
        self.state.history.add_event('resilience', resilience_type='irop', op=op, message='unsupported IROp')
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
