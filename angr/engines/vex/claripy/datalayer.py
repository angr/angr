from typing import Optional
import logging

import claripy
import pyvex

from . import irop
from . import ccall
from ..light import VEXMixin
from .... import errors
from .... import sim_options as o

l = logging.getLogger(__name__)
zero = claripy.BVV(0, 32)

def value(ty, val, size: Optional[int]=None):
    if ty == 'Ity_F32':
        return claripy.FPV(float(val), claripy.FSORT_FLOAT)
    elif ty == 'Ity_F64':
        return claripy.FPV(float(val), claripy.FSORT_DOUBLE)
    else:
        if size is not None:
            return claripy.BVV(int(val), size)
        return claripy.BVV(int(val), pyvex.get_type_size(ty))

def symbol(ty, name):
    if ty == 'Ity_F32':
        return claripy.FPS(name, claripy.FSORT_FLOAT)
    elif ty == 'Ity_F64':
        return claripy.FPS(name, claripy.FSORT_DOUBLE)
    else:
        return claripy.BVS(name, pyvex.get_type_size(ty))

class ClaripyDataMixin(VEXMixin):
    """
    This mixin provides methods that makes the vex engine process guest code using claripy ASTs as the data domain.
    """

    # util methods

    def _is_true(self, v):
        return claripy.is_true(v)

    def _is_false(self, v):
        return claripy.is_false(v)

    def _optimize_guarded_addr(self, addr, guard):
        # optimization: is the guard the same as the condition inside the address? if so, unpack the address and remove
        # the guarding condition.
        if isinstance(guard, claripy.ast.Base) and guard.op == 'If' \
                and isinstance(addr, claripy.ast.Base) and addr.op == 'If':
            if guard.args[0] is addr.args[0]:
                # the address is guarded by the same guard! unpack the addr
                return addr.args[1]
        return addr

    # consts

    def _handle_vex_const(self, const):
        return value(const.type, const.value)

    # statements

    def _perform_vex_stmt_LoadG(self, addr, alt, guard, dst, cvt, end):
        addr = self._optimize_guarded_addr(addr, guard)
        super()._perform_vex_stmt_LoadG(addr, alt, guard, dst, cvt, end)

    def _perform_vex_stmt_StoreG(self, addr, data, guard, ty, endness, **kwargs):
        addr = self._optimize_guarded_addr(addr, guard)
        super()._perform_vex_stmt_StoreG(addr, data, guard, ty, endness, **kwargs)

    # is this right? do I care?
    def _handle_vex_expr_GSPTR(self, expr):
        return zero

    def _handle_vex_expr_VECRET(self, expr):
        return zero

    def _handle_vex_expr_Binder(self, expr):
        return zero

    # simple wrappers to implement the fp/bv data casting

    def _perform_vex_expr_Get(self, offset, ty, **kwargs):
        res = super()._perform_vex_expr_Get(offset, ty, **kwargs)
        if ty.startswith('Ity_F'):
            return res.raw_to_fp()
        else:
            return res

    def _perform_vex_expr_Load(self, addr, ty, endness, **kwargs):
        res = super()._perform_vex_expr_Load(addr, ty, endness, **kwargs)
        if ty.startswith('Ity_F'):
            return res.raw_to_fp()
        else:
            return res

    def _perform_vex_stmt_Put(self, offset, data, **kwargs):
        super()._perform_vex_stmt_Put(offset, data.raw_to_bv(), **kwargs)

    def _perform_vex_stmt_Store(self, addr, data, endness, **kwargs):
        super()._perform_vex_stmt_Store(addr, data.raw_to_bv(), endness, **kwargs)

    # op support

    def _perform_vex_expr_ITE(self, cond, ifTrue, ifFalse):
        try:
            return claripy.If(cond != 0, ifTrue, ifFalse)
        except claripy.ClaripyError as e:
            raise errors.SimError("Claripy failed") from e

    def _perform_vex_expr_Op(self, op, args):
        # TODO: get rid of these hacks (i.e. state options and modes) and move these switches into engine properties
        options = getattr(self.state, 'options', {o.SUPPORT_FLOATING_POINT})
        simop = irop.vexop_to_simop(
            op,
            extended=o.EXTENDED_IROP_SUPPORT in options,
            fp=o.SUPPORT_FLOATING_POINT in options
        )
        return simop.calculate(*args)

    # ccall support

    def _perform_vex_expr_CCall(self, func_name, ty, args, func=None):
        if func is None:
            try:
                func = getattr(ccall, func_name)
            except AttributeError as e:
                raise errors.UnsupportedCCallError(f"Unsupported ccall {func_name}") from e

        try:
            return func(self.state, *args)
        except ccall.CCallMultivaluedException as e:
            cases, to_replace = e.args
            # pylint: disable=undefined-loop-variable
            for i, arg in enumerate(args):
                if arg is to_replace:
                    break
            else:
                raise errors.UnsupportedCCallError("Trying to concretize a value which is not an argument")
            evaluated_cases = [(case, func(self.state, *args[:i], value_, *args[i+1:])) for case, value_ in cases]
            try:
                return claripy.ite_cases(evaluated_cases, value(ty, 0))
            except claripy.ClaripyError as ce:
                raise errors.SimOperationError("Claripy failed") from ce
