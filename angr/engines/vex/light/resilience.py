from angr.engines.vex.light import VEXMixin
from angr import errors

raiseme = object()
class VEXResilienceMixin(VEXMixin):
    def _check_unsupported_ccall(self, func_name, retty, args, **kwargs):
        return raiseme

    def _check_errored_ccall(self, func_name, ty, args, **kwargs):
        return raiseme

    def _check_unsupported_op(self, op, args):
        return raiseme

    def _check_zero_division(self, op, args):
        return raiseme

    def _check_errored_op(self, op, args):
        return raiseme

    def _check_unsupported_dirty(self, func_name, ty, args, **kwargs):
        return raiseme

    def _check_errored_dirty(self, func_name, ty, args, **kwargs):
        return raiseme

    def _check_errored_stmt(self, stmt):
        return raiseme

def _make_wrapper(func, *args):
    excs = args[::2]
    handlers = args[1::2]

    def inner(self, *iargs, **ikwargs):
        try:
            return getattr(super(VEXResilienceMixin, self), func)(*iargs, **ikwargs)
        except excs as e:
            for exc, handler in zip(excs, handlers):
                if isinstance(e, exc):
                    v = getattr(self, handler)(*iargs, **ikwargs)
                    if v is raiseme:
                        raise
                    return v
            assert False, "this should be unreachable if Python is working correctly"
    setattr(VEXResilienceMixin, func, inner)

_make_wrapper('_perform_vex_stmt_Dirty_call', errors.UnsupportedDirtyError, '_check_unsupported_dirty', errors.SimOperationError, '_check_errored_dirty')
_make_wrapper('_perform_vex_expr_CCall', errors.UnsupportedCCallError, '_check_unsupported_ccall', errors.SimOperationError, '_check_errored_ccall')
_make_wrapper('_perform_vex_expr_Op', errors.SimZeroDivisionException, '_check_zero_division', errors.UnsupportedIROpError, '_check_unsupported_op')
_make_wrapper('_handle_vex_stmt', errors.SimError, '_check_errored_stmt')
