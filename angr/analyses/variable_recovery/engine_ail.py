
import logging

import ailment

from ...engines.light import SimEngineLightAILMixin, SpOffset
from .engine_base import SimEngineVRBase

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
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)
        size = stmt.data.bits // 8

        self._store(addr, data, size, stmt=stmt)

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
                None,
                self.state.arch.bytes,
                dst=ret_expr,
            )

    # Expression handlers

    def _ail_handle_Register(self, expr):
        offset = expr.reg_offset
        size = expr.bits // 8

        return self._read_from_register(offset, size, expr=expr)

    def _ail_handle_Load(self, expr):
        addr = self._expr(expr.addr)
        size = expr.size

        return self._load(addr, size, expr=expr)

    def _ail_handle_BinaryOp(self, expr):
        r = super()._ail_handle_BinaryOp(expr)
        if r is None:
            # Treat it as a normal binaryop expression
            self._expr(expr.operands[0])
            self._expr(expr.operands[1])
        return r

    def _ail_handle_Convert(self, expr):
        return self._expr(expr.operand)

    def _ail_handle_StackBaseOffset(self, expr):
        return SpOffset(self.arch.bits, expr.offset, is_base=False)

    def _ail_handle_Cmp(self, expr):  # pylint:disable=useless-return
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        return None

    _ail_handle_CmpEQ = _ail_handle_Cmp
    _ail_handle_CmpNE = _ail_handle_Cmp
    _ail_handle_CmpLT = _ail_handle_Cmp
    _ail_handle_CmpLE = _ail_handle_Cmp
    _ail_handle_CmpGT = _ail_handle_Cmp
    _ail_handle_CmpGE = _ail_handle_Cmp
