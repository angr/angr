from typing import TYPE_CHECKING

import claripy
import pyvex

from ...engines.vex.claripy.datalayer import value as claripy_value
from ...engines.light import SimEngineLightVEXMixin
from ..typehoon import typevars, typeconsts
from .engine_base import SimEngineVRBase, RichR

if TYPE_CHECKING:
    from .variable_recovery_base import VariableRecoveryStateBase


class SimEngineVRVEX(
    SimEngineLightVEXMixin,
    SimEngineVRBase,
):
    state: 'VariableRecoveryStateBase'

    # Statement handlers

    def _handle_Put(self, stmt):
        offset = stmt.offset
        r = self._expr(stmt.data)
        size = stmt.data.result_size(self.tyenv) // 8

        if offset == self.arch.ip_offset:
            return
        self._assign_to_register(offset, r, size)

    def _handle_Store(self, stmt):
        addr_r = self._expr(stmt.addr)
        size = stmt.data.result_size(self.tyenv) // 8
        r = self._expr(stmt.data)

        self._store(addr_r, r, size, stmt=stmt)

    def _handle_StoreG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:

            addr = self._expr(stmt.addr)
            size = stmt.data.result_size(self.tyenv) // 8
            data = self._expr(stmt.data)
            self._store(addr, data, size, stmt=stmt)

    def _handle_LoadG(self, stmt):
        guard = self._expr(stmt.guard)
        if guard is True:
            addr = self._expr(stmt.addr)
            if addr is not None:
                self.tmps[stmt.dst] = self._load(addr, self.tyenv.sizeof(stmt.dst) // 8)
        elif guard is False:
            data = self._expr(stmt.alt)
            self.tmps[stmt.dst] = data
        else:
            self.tmps[stmt.dst] = None

    def _handle_LLSC(self, stmt: pyvex.IRStmt.LLSC):
        if stmt.storedata is None:
            # load-link
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.result) // self.arch.byte_width
            data = self._load(addr, size)
            self.tmps[stmt.result] = data
        else:
            # store-conditional
            storedata = self._expr(stmt.storedata)
            addr = self._expr(stmt.addr)
            size = self.tyenv.sizeof(stmt.storedata.tmp) // self.arch.byte_width

            self._store(addr, storedata, size)

            result_size = self.tyenv.sizeof(stmt.result)
            self.tmps[stmt.result] = RichR(claripy.BVV(1, result_size))

    def _handle_NoOp(self, stmt):
        pass

    # Expression handlers

    def _expr(self, expr) -> RichR:
        """

        :param expr:
        :return:
        :rtype: RichR
        """

        r = super()._expr(expr)
        if r is None:
            bits = expr.result_size(self.tyenv)
            return RichR(self.state.top(bits))
        return r

    def _handle_Get(self, expr):
        reg_offset = expr.offset
        reg_size = expr.result_size(self.tyenv) // 8

        return self._read_from_register(reg_offset, reg_size, expr=expr)

    def _handle_Load(self, expr: pyvex.IRExpr.Load) -> RichR:
        addr = self._expr(expr.addr)
        size = expr.result_size(self.tyenv) // 8

        return self._load(addr, size)

    def _handle_CCall(self, expr):  # pylint:disable=useless-return
        # ccalls don't matter
        return RichR(self.state.top(expr.result_size(self.tyenv)))

    def _handle_Conversion(self, expr: pyvex.IRExpr.Unop) -> RichR:
        return RichR(self.state.top(expr.result_size(self.tyenv)))


    # Function handlers

    def _handle_function(self, func_addr):  # pylint:disable=unused-argument,no-self-use,useless-return
        return None

    def _handle_Const(self, expr):
        return RichR(claripy_value(expr.con.type, expr.con.value), typevar=typeconsts.int_type(expr.con.size))

    def _handle_Add(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data + r1.data,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        typevar = None
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.AddN(r1.data._model_concrete.value))

        sum_ = r0.data + r1.data
        return RichR(sum_,
                     typevar=typevar,
                     type_constraints={ typevars.Subtype(r0.typevar, r1.typevar) },
                     )

    def _handle_Sub(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data - r1.data,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        typevar = None
        if r0.typevar is not None and r1.data.concrete:
            typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data._model_concrete.value))

        diff = r0.data - r1.data
        return RichR(diff,
                     typevar=typevar,
                     )

    def _handle_And(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data & r1.data)

        if self.state.is_stack_address(r0.data):
            r = r0.data
        elif self.state.is_stack_address(r1.data):
            r = r1.data
        else:
            r = self.state.top(result_size)
        return RichR(r)

    def _handle_Xor(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data ^ r1.data)

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_Or(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data | r1.data)

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_Not(self, expr):
        arg = expr.args[0]
        r0 = self._expr(arg)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete:
            # constants
            return RichR(~r0.data)

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_Mul(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data * r1.data)

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_DivMod(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            try:
                signed = "U" in expr.op  # Iop_DivModU64to32 vs Iop_DivMod
                from_size = r0.data.size()
                to_size = r1.data.size()
                if signed:
                    quotient = (r0.data.SDiv(claripy.SignExt(from_size - to_size, r1.data)))
                    remainder = (r0.data.SMod(claripy.SignExt(from_size - to_size, r1.data)))
                    quotient_size = to_size
                    remainder_size = to_size
                    result = claripy.Concat(
                        claripy.Extract(remainder_size - 1, 0, remainder),
                        claripy.Extract(quotient_size - 1, 0, quotient)
                    )
                else:
                    quotient = (r0.data // claripy.ZeroExt(from_size - to_size, r1.data))
                    remainder = (r0.data % claripy.ZeroExt(from_size - to_size, r1.data))
                    quotient_size = to_size
                    remainder_size = to_size
                    result = claripy.Concat(
                        claripy.Extract(remainder_size - 1, 0, remainder),
                        claripy.Extract(quotient_size - 1, 0, quotient)
                    )

                return RichR(result)
            except ZeroDivisionError:
                pass

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_Div(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            try:
                return RichR(r0.data / r1.data)
            except ZeroDivisionError:
                pass

        r = self.state.top(result_size)
        return RichR(r)

    def _handle_Shr(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(claripy.LShR(r0.data, r1.data._model_concrete.value),
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(result_size)
        return RichR(r,
                     typevar=r0.typevar,
                     )

    def _handle_Sar(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data >> r1.data._model_concrete.value,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(result_size)
        return RichR(r,
                     typevar=r0.typevar,
                     )

    def _handle_Shl(self, expr):
        arg0, arg1 = expr.args
        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        result_size = expr.result_size(self.tyenv)
        if r0.data.concrete and r1.data.concrete:
            # constants
            return RichR(r0.data << r1.data._model_concrete.value,
                         typevar=typeconsts.int_type(result_size),
                         type_constraints=None)

        r = self.state.top(result_size)
        return RichR(r,
                     typevar=r0.typevar,
                     )

    def _handle_CmpEQ(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))

    def _handle_CmpNE(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))

    def _handle_CmpLE(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))

    def _handle_CmpLT(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))

    def _handle_CmpGE(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))

    def _handle_CmpGT(self, expr):
        arg0, arg1 = expr.args
        _ = self._expr(arg0)
        _ = self._expr(arg1)

        return RichR(self.state.top(1))
