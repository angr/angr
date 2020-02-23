
import logging

from ailment import Stmt, Expr

from ...utils.constants import is_alignment_mask
from ...engines.light import SimEngineLightAILMixin
from .engine_base import SimEnginePropagatorBase

l = logging.getLogger(name=__name__)


class SimEnginePropagatorAIL(
    SimEngineLightAILMixin,
    SimEnginePropagatorBase,
):

    #
    # AIL statement handlers
    #

    def _ail_handle_Assignment(self, stmt):
        """

        :param Stmt.Assignment stmt:
        :return:
        """

        src = self._expr(stmt.src)
        dst = stmt.dst

        if type(dst) is Expr.Tmp:
            new_src = self.state.get_variable(src)
            if new_src is not None:
                l.debug("%s = %s, replace %s with %s.", dst, src, src, new_src)
                self.state.store_variable(dst, new_src)

            else:
                l.debug("Replacing %s with %s.", dst, src)
                self.state.store_variable(dst, src)

        elif type(dst) is Expr.Register:
            self.state.store_variable(dst, src)
        else:
            l.warning('Unsupported type of Assignment dst %s.', type(dst).__name__)

    def _ail_handle_Store(self, stmt):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)

        if isinstance(addr, Expr.StackBaseOffset):
            # Storing data to a stack variable
            self.state.store_stack_variable(addr, data.bits // 8, data, endness=stmt.endness)

    def _ail_handle_Jump(self, stmt):
        _ = self._expr(stmt.target)

    def _ail_handle_Call(self, stmt):
        target = self._expr(stmt.target)

        new_args = None

        if stmt.args:
            new_args = [ ]
            for arg in stmt.args:
                new_arg = self._expr(arg)
                replacement = self.state.get_variable(new_arg)
                if replacement is not None:
                    new_args.append(replacement)
                else:
                    new_args.append(arg)

        if new_args != stmt.args:
            new_call_stmt = Stmt.Call(stmt.idx, target, calling_convention=stmt.calling_convention,
                                      prototype=stmt.prototype, args=new_args, ret_expr=stmt.ret_expr,
                                      **stmt.tags)
            self.state.add_replacement(self._codeloc(),
                                             stmt,
                                             new_call_stmt,
                                             )

    def _ail_handle_ConditionalJump(self, stmt):
        cond = self._expr(stmt.condition)
        true_target = self._expr(stmt.true_target)
        false_target = self._expr(stmt.false_target)

        if cond is stmt.condition and \
                true_target is stmt.true_target and \
                false_target is stmt.false_target:
            pass
        else:
            new_jump_stmt = Stmt.ConditionalJump(stmt.idx, cond, true_target, false_target, **stmt.tags)
            self.state.add_replacement(self._codeloc(),
                                             stmt,
                                             new_jump_stmt,
                                             )

    #
    # AIL expression handlers
    #

    def _ail_handle_Tmp(self, expr):
        new_expr = self.state.get_variable(expr)

        if new_expr is not None:
            l.debug("Add a replacement: %s with %s", expr, new_expr)
            self.state.add_replacement(self._codeloc(), expr, new_expr)
            if type(new_expr) in [Expr.Register, Expr.Const, Expr.Convert, Expr.StackBaseOffset, Expr.BasePointerOffset]:
                expr = new_expr

        return expr

    def _ail_handle_Register(self, expr):
        # Special handling for SP and BP
        if self._stack_pointer_tracker is not None:
            if expr.reg_offset == self.arch.sp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.sp_offset)
                if sb_offset is not None:
                    new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                    self.state.add_replacement(self._codeloc(), expr, new_expr)
                    return new_expr
            elif expr.reg_offset == self.arch.bp_offset:
                sb_offset = self._stack_pointer_tracker.offset_before(self.ins_addr, self.arch.bp_offset)
                if sb_offset is not None:
                    new_expr = Expr.StackBaseOffset(None, self.arch.bits, sb_offset)
                    self.state.add_replacement(self._codeloc(), expr, new_expr)
                    return new_expr

        new_expr = self.state.get_variable(expr)
        if new_expr is not None:
            l.debug("Add a replacement: %s with %s", expr, new_expr)
            self.state.add_replacement(self._codeloc(), expr, new_expr)
            expr = new_expr
        return expr

    def _ail_handle_Load(self, expr):
        addr = self._expr(expr.addr)

        if isinstance(addr, Expr.StackBaseOffset):
            var = self.state.get_stack_variable(addr, expr.size, endness=expr.endness)
            if var is not None:
                return var

        if addr != expr.addr:
            return Expr.Load(expr.idx, addr, expr.size, expr.endness, **expr.tags)
        return expr

    def _ail_handle_Convert(self, expr):
        operand_expr = self._expr(expr.operand)

        if type(operand_expr) is Expr.Convert:
            if expr.from_bits == operand_expr.to_bits and expr.to_bits == operand_expr.from_bits:
                # eliminate the redundant Convert
                return operand_expr.operand
            else:
                return Expr.Convert(expr.idx, operand_expr.from_bits, expr.to_bits, expr.is_signed, operand_expr.operand)
        elif type(operand_expr) is Expr.Const:
            # do the conversion right away
            value = operand_expr.value
            mask = (2 ** expr.to_bits) - 1
            value &= mask
            return Expr.Const(expr.idx, operand_expr.variable, value, expr.to_bits)

        converted = Expr.Convert(expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, operand_expr)
        return converted

    def _ail_handle_Const(self, expr):
        return expr

    def _ail_handle_DirtyExpression(self, expr):  # pylint:disable=no-self-use
        return expr

    def _ail_handle_CmpLE(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        return Expr.BinaryOp(expr.idx, 'CmpLE', [ operand_0, operand_1 ])

    def _ail_handle_CmpEQ(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        return Expr.BinaryOp(expr.idx, 'CmpEQ', [ operand_0, operand_1 ])

    def _ail_handle_Add(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if isinstance(operand_0, Expr.Const) and isinstance(operand_1, Expr.Const):
            return Expr.Const(expr.idx, None, operand_0.value + operand_1.value, expr.bits)
        elif isinstance(operand_0, Expr.BasePointerOffset) and isinstance(operand_1, Expr.Const):
            r = operand_0.copy()
            r.offset += operand_1.value
            return r
        return Expr.BinaryOp(expr.idx, 'Add', [operand_0 if operand_0 is not None else expr.operands[0],
                                               operand_1 if operand_1 is not None else expr.operands[1]
                                               ])

    def _ail_handle_Sub(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if isinstance(operand_0, Expr.Const) and isinstance(operand_1, Expr.Const):
            return Expr.Const(expr.idx, None, operand_0.value - operand_1.value, expr.bits)
        elif isinstance(operand_0, Expr.BasePointerOffset) and isinstance(operand_1, Expr.Const):
            r = operand_0.copy()
            r.offset -= operand_1.value
            return r
        return Expr.BinaryOp(expr.idx, 'Sub', [ operand_0 if operand_0 is not None else expr.operands[0],
                                                operand_1 if operand_1 is not None else expr.operands[1]
                                                ])

    def _ail_handle_StackBaseOffset(self, expr):  # pylint:disable=no-self-use
        return expr

    def _ail_handle_And(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        # Special logic for SP alignment
        if type(operand_0) is Expr.StackBaseOffset and \
                type(operand_1) is Expr.Const and is_alignment_mask(operand_1.value):
            return operand_0

        return Expr.BinaryOp(expr.idx, 'And', [ operand_0, operand_1 ])

    def _ail_handle_Xor(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        return Expr.BinaryOp(expr.idx, 'Xor', [ operand_0, operand_1 ])
