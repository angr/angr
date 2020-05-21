
from typing import Optional
import logging

import ailment

from ...calling_conventions import SimRegArg
from ...sim_type import SimTypeFunction
from ...engines.light import SimEngineLightAILMixin, SpOffset
from ..typehoon import typeconsts, typevars
from ..typehoon.lifter import TypeLifter
from .engine_base import SimEngineVRBase, RichR

l = logging.getLogger(name=__name__)


class SimEngineVRAIL(
    SimEngineLightAILMixin,
    SimEngineVRBase,
):

    # Statement handlers

    def _ail_handle_Assignment(self, stmt):
        dst_type = type(stmt.dst)

        if dst_type is ailment.Expr.Register:
            offset = stmt.dst.reg_offset
            data = self._expr(stmt.src)
            size = stmt.src.bits // 8

            self._assign_to_register(offset, data, size, src=stmt.src, dst=stmt.dst)

        elif dst_type is ailment.Expr.Tmp:
            # simply write to self.tmps
            data = self._expr(stmt.src)
            if data is None:
                return

            self.tmps[stmt.dst.tmp_idx] = data

        else:
            l.warning('Unsupported dst type %s.', dst_type)

    def _ail_handle_Store(self, stmt):
        addr_r = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        size = stmt.data.bits // 8

        self._store(addr_r, data, size, stmt=stmt)

    def _ail_handle_Jump(self, stmt):
        pass

    def _ail_handle_ConditionalJump(self, stmt):
        self._expr(stmt.condition)

    def _ail_handle_Call(self, stmt):
        target = stmt.target
        args = [ ]
        if stmt.args:
            for arg in stmt.args:
               args.append(self._expr(arg))

        ret_expr: Optional[ailment.Expr.Register] = stmt.ret_expr
        if ret_expr is not None:
            ret_reg_offset = ret_expr.reg_offset
        else:
            if stmt.calling_convention is not None:
                # return value
                ret_expr: SimRegArg = stmt.calling_convention.RETURN_VAL
            else:
                l.debug("Unknown calling convention for function %s. Fall back to default calling convention.", target)
                ret_expr: SimRegArg = self.project.factory.cc().RETURN_VAL
            ret_reg_offset = self.project.arch.registers[ret_expr.reg_name][0]

        # discovery the prototype
        prototype: Optional[SimTypeFunction] = None
        if stmt.calling_convention is not None:
            prototype = stmt.calling_convention.func_ty
        elif isinstance(stmt.target, ailment.Expr.Const):
            func_addr = stmt.target.value
            if func_addr in self.kb.functions:
                func = self.kb.functions[func_addr]
                prototype = func.prototype

        if ret_expr is not None:
            # dump the type of the return value
            if prototype is not None:
                ret_ty = TypeLifter(self.arch.bits).lift(prototype.returnty)
            else:
                ret_ty = None

            self._assign_to_register(
                ret_reg_offset,
                RichR(None, typevar=ret_ty),
                self.state.arch.bytes,
                dst=ret_expr,
            )

        if prototype is not None and args:
            # add type constraints
            for arg, arg_type in zip(args, prototype.args):
                arg_ty = TypeLifter(self.arch.bits).lift(arg_type)
                type_constraint = typevars.Subtype(
                    arg.typevar, arg_ty
                )
                self.state.add_type_constraint(type_constraint)

    # Expression handlers

    def _expr(self, expr):
        """

        :param expr:
        :return:
        :rtype: RichR
        """

        expr = super()._expr(expr)
        if expr is None:
            return RichR(None)
        return expr

    def _ail_handle_Register(self, expr):
        offset = expr.reg_offset
        size = expr.bits // 8

        return self._read_from_register(offset, size, expr=expr)

    def _ail_handle_Load(self, expr):
        addr_r = self._expr(expr.addr)
        size = expr.size

        return self._load(addr_r, size, expr=expr)

    def _ail_handle_Const(self, expr):
        return RichR(expr.value, typevar=typeconsts.int_type(expr.size * 8))

    def _ail_handle_BinaryOp(self, expr):
        r = super()._ail_handle_BinaryOp(expr)
        if r is None:
            # Treat it as a normal binaryop expression
            self._expr(expr.operands[0])
            self._expr(expr.operands[1])
            # still return a RichR instance
            r = RichR(None)
        return r

    def _ail_handle_Convert(self, expr: ailment.Expr.Convert):
        r = self._expr(expr.operand)
        typevar = None
        if r.typevar is not None:
            if isinstance(r.typevar, typevars.DerivedTypeVariable) and isinstance(r.typevar.label, typevars.ConvertTo):
                # there is already a conversion - overwrite it
                typevar = typevars.DerivedTypeVariable(r.typevar.type_var, typevars.ConvertTo(expr.to_bits))
            else:
                typevar = typevars.DerivedTypeVariable(r.typevar, typevars.ConvertTo(expr.to_bits))

        return RichR(r.data, typevar=typevar)

    def _ail_handle_StackBaseOffset(self, expr):
        return RichR(
            SpOffset(self.arch.bits, expr.offset, is_base=False)
        )

    def _ail_handle_ITE(self, expr: ailment.Expr.ITE):
        # pylint:disable=unused-variable
        cond = self._expr(expr.cond)
        r0 = self._expr(expr.iftrue)
        r1 = self._expr(expr.iffalse)

    def _ail_handle_Cmp(self, expr):  # pylint:disable=useless-return
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        return RichR(None)

    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp

    def _ail_handle_Add(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            typevar = None
            if r0.typevar is not None and isinstance(r1.data, int):
                typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.AddN(r1.data))

            sum_ = None
            if r0.data is not None and r1.data is not None:
                sum_ = r0.data + r1.data

            return RichR(sum_,
                         typevar=typevar,
                         type_constraints={ typevars.Subtype(r0.typevar, r1.typevar) }
                         )
        except TypeError:
            return RichR(ailment.Expr.BinaryOp(expr.idx, 'Add', [r0, r1], **expr.tags))

    def _ail_handle_Sub(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            typevar = None
            if r0.typevar is not None and isinstance(r1.data, int):
                typevar = typevars.DerivedTypeVariable(r0.typevar, typevars.SubN(r1.data))

            sub = None
            if r0.data is not None and r1.data is not None:
                sub = r0.data - r1.data

            return RichR(sub,
                         typevar=typevar,
                         type_constraints={ typevars.Subtype(r0.typevar, r1.typevar) },
                         )
        except TypeError:
            return RichR(ailment.Expr.BinaryOp(expr.idx, 'Sub', [r0, r1], **expr.tags))

    def _ail_handle_Mul(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data * r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            remainder = None
            if r0.data is not None and r1.data is not None:
                remainder = r0.data * r1.data

            return RichR(remainder,
                         typevar=r0.typevar,
                         )
        except TypeError:
            return RichR(ailment.Expr.BinaryOp(expr.idx, 'Mul', [r0, r1], **expr.tags))

    def _ail_handle_Div(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data // r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            remainder = None
            if r0.data is not None and r1.data is not None:
                remainder = r0.data // r1.data

            return RichR(remainder,
                         typevar=r0.typevar,
                         )
        except TypeError:
            return RichR(ailment.Expr.BinaryOp(expr.idx, 'Div', [r0, r1], **expr.tags))

    def _ail_handle_Xor(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data ^ r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            remainder = None
            if r0.data is not None and r1.data is not None:
                remainder = r0.data ^ r1.data

            return RichR(remainder,
                         typevar=r0.typevar,
                         )
        except TypeError:
            return RichR(ailment.Expr.BinaryOp(expr.idx, 'Xor', [r0, r1], **expr.tags))

    def _ail_handle_Shl(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data << r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data << r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _ail_handle_Shr(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data >> r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data >> r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _ail_handle_Sal(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                result_size = arg0.bits
                # constants
                return RichR(r0.data << r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data << r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _ail_handle_Sar(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                # constants
                result_size = arg0.bits
                return RichR(r0.data >> r1.data,
                             typevar=typeconsts.int_type(result_size),
                             type_constraints=None)

            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data >> r1.data

            return RichR(r,
                         typevar=r0.typevar,
                         )

        except TypeError as ex:
            self.l.warning(ex)
            return RichR(None)

    def _ail_handle_And(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                result_size = arg0.bits
                return RichR(
                    r0.data & r1.data,
                    typevar=typeconsts.int_type(result_size),
                    type_constraints=None,
                )
            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data & r1.data
            return RichR(r, typevar=r0.typevar)

        except TypeError:
            self.l.warning("_ail_handle_And(): TypeError.", exc_info=True)
            return RichR(None)

    def _ail_handle_Or(self, expr):

        arg0, arg1 = expr.operands

        r0 = self._expr(arg0)
        r1 = self._expr(arg1)

        try:
            if isinstance(r0.data, int) and isinstance(r1.data, int):
                result_size = arg0.bits
                return RichR(
                    r0.data | r1.data,
                    typevar=typeconsts.int_type(result_size),
                    type_constraints=None,
                )
            r = None
            if r0.data is not None and r1.data is not None:
                r = r0.data | r1.data
            return RichR(r, typevar=r0.typevar)

        except TypeError:
            self.l.warning("_ail_handle_Or(): TypeError.", exc_info=True)
            return RichR(None)

    def _ail_handle_Not(self, expr):
        arg = expr.operands[0]
        expr = self._expr(arg)
        try:
            result_size = arg.bits
            mask = (1 << result_size) - 1
            if isinstance(expr.data, int):
                return RichR(
                    (~expr.data) & mask,
                    typevar=typeconsts.int_type(result_size),
                    type_constraints=None,
                )
            r = None
            if expr.data is not None:
                r = (~expr.data) & mask
            return RichR(r, typevar=expr.typevar)

        except TypeError:
            self.l.warning("_ail_handle_Not(): TypeError.", exc_info=True)
            return RichR(None)
