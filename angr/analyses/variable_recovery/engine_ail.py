
import logging

import ailment

from ...engines.light import SimEngineLightAILMixin, SpOffset
from ..typehoon import typeconsts, typevars
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
        if stmt.args:
            for arg in stmt.args:
               self._expr(arg)

        ret_expr = stmt.ret_expr
        if ret_expr is None:
            if stmt.calling_convention is not None:
                # return value
                ret_expr = stmt.calling_convention.RETURN_VAL
            else:
                l.debug("Unknown calling convention for function %s. Fall back to default calling convention.", target)
                ret_expr = self.project.factory.cc().RETURN_VAL

        if ret_expr is not None:
            self._assign_to_register(
                ret_expr.reg_offset,
                RichR(None),
                self.state.arch.bytes,
                dst=ret_expr,
            )

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

    def _ail_handle_Convert(self, expr):
        return self._expr(expr.operand)

    def _ail_handle_StackBaseOffset(self, expr):
        return RichR(
            SpOffset(self.arch.bits, expr.offset, is_base=False)
        )

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

        except TypeError as e:
            self.l.warning(e)
            return RichR(None)
