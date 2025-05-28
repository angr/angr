# pylint:disable=too-many-boolean-expressions
from __future__ import annotations
import logging

import angr.ailment as ailment

from angr.engines.light import SimEngineLightAIL

_l = logging.getLogger(name=__name__)


class SimplifierAILState:
    """
    The abstract state used in SimplifierAILEngine.
    """

    def __init__(self, arch, variables=None):
        self.arch = arch
        self._variables = {} if variables is None else variables

    def __repr__(self):
        return "<SimplifierAILState>"

    def copy(self):
        return SimplifierAILState(
            self.arch,
            variables=self._variables.copy(),
        )

    def merge(self, *others):
        raise NotImplementedError

    def store_variable(self, old: ailment.expression.VirtualVariable, new):
        if new is not None:
            self._variables[old.varid] = new

    def get_variable(self, old: ailment.expression.VirtualVariable):
        return self._variables.get(old.varid, None)

    def remove_variable(self, old):
        self._variables.pop(old, None)


class SimplifierAILEngine(
    SimEngineLightAIL[SimplifierAILState, ailment.expression.Expression, ailment.statement.Statement, ailment.Block]
):
    """
    Essentially implements a peephole optimization engine for AIL statements (because we do not perform memory or
    register loads).
    """

    def _process_block_end(self, block, stmt_data, whitelist):
        if whitelist is None:
            block.statements = stmt_data
        else:
            for stmt_idx, stmt in zip(sorted(whitelist), stmt_data):
                block.statements[stmt_idx] = stmt
        return block

    def _top(self, bits):
        assert False, "This code should be unreachable"

    def _is_top(self, expr):
        assert False, "This code should be unreachable"

    # handle stmt

    def _handle_stmt_Assignment(self, stmt):
        src = self._expr(stmt.src)
        dst = self._expr(stmt.dst)

        if isinstance(dst, ailment.expression.VirtualVariable) and not isinstance(src, ailment.expression.Phi):
            self.state.store_variable(dst, src)

        if (src, dst) != (stmt.src, stmt.dst):
            return ailment.statement.Assignment(stmt.idx, dst, src, **stmt.tags)  # type:ignore

        return stmt

    def _handle_stmt_WeakAssignment(self, stmt: ailment.statement.WeakAssignment):
        src = self._expr(stmt.src)
        dst = self._expr(stmt.dst)

        if (src, dst) != (stmt.src, stmt.dst):
            return ailment.statement.WeakAssignment(stmt.idx, dst, src, **stmt.tags)  # type:ignore

        return stmt

    def _handle_stmt_CAS(self, stmt: ailment.statement.CAS) -> ailment.statement.CAS:
        # we assume that we never have to deal with CAS statements at this point; they should have been rewritten to
        # intrinsics
        return stmt

    def _handle_stmt_Store(self, stmt):
        addr = self._expr(stmt.addr)
        data = self._expr(stmt.data)

        # replace
        if (addr, data) != (stmt.addr, stmt.data):
            return ailment.statement.Store(
                stmt.idx, addr, data, stmt.size, stmt.endness, variable=stmt.variable, **stmt.tags
            )

        return stmt

    def _handle_stmt_Jump(self, stmt):
        target = self._expr(stmt.target)

        return ailment.statement.Jump(stmt.idx, target, **stmt.tags)

    def _handle_stmt_ConditionalJump(self, stmt):  # pylint: disable=no-self-use
        condition = self._expr(stmt.condition)
        iftrue = self._expr(stmt.true_target) if stmt.true_target is not None else None
        iffalse = self._expr(stmt.false_target) if stmt.false_target is not None else None

        if (condition, iftrue, iffalse) != (stmt.condition, stmt.true_target, stmt.false_target):
            return ailment.statement.ConditionalJump(
                stmt.idx,
                condition,
                iftrue,
                iffalse,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
        return stmt

    def _handle_stmt_Call(self, stmt):
        target = self._expr(stmt.target) if isinstance(stmt.target, ailment.Expr.Expression) else stmt.target

        new_args = None

        if stmt.args:
            new_args = []
            for arg in stmt.args:
                new_arg = self._expr(arg)
                new_args.append(new_arg)

        return ailment.statement.Call(
            stmt.idx,
            target,
            calling_convention=stmt.calling_convention,
            prototype=stmt.prototype,
            args=new_args,
            ret_expr=stmt.ret_expr,
            fp_ret_expr=stmt.fp_ret_expr,
            bits=stmt.bits,
            **stmt.tags,
        )

    def _handle_stmt_Return(self, stmt):
        if stmt.ret_exprs:
            new_retexprs = []
            for ret_expr in stmt.ret_exprs:
                new_retexpr = self._expr(ret_expr)
                new_retexprs.append(new_retexpr)

            if new_retexprs != stmt.ret_exprs:
                new_stmt = stmt.copy()
                new_stmt.ret_exprs = new_retexprs
                return new_stmt
        return stmt

    def _handle_stmt_DirtyStatement(self, stmt):
        expr = self._expr(stmt.dirty)
        if expr != stmt.dirty:
            return ailment.statement.DirtyStatement(stmt.idx, expr, **stmt.tags)  # type:ignore
        return stmt

    def _handle_stmt_Label(self, stmt):
        return stmt

    # handle expr

    def _handle_expr_StackBaseOffset(self, expr):  # pylint:disable=no-self-use
        return expr

    def _handle_expr_VirtualVariable(self, expr):  # pylint:disable=no-self-use
        # We don't want to return new values and construct new AIL expressions in caller methods without def-use
        # information. Otherwise, we may end up creating incorrect expressions.
        # Therefore, we do not perform vvar load, which essentially turns SimplifierAILEngine into a peephole
        # optimization engine.
        return expr

    def _handle_expr_Phi(self, expr):  # pylint:disable=no-self-use
        return expr

    def _handle_expr_Load(self, expr):
        # We don't want to load new values and construct new AIL expressions in caller methods without def-use
        # information. Otherwise, we may end up creating incorrect expressions.
        # Therefore, we do not perform memory load, which essentially turns SimplifierAILEngine into a peephole
        # optimization engine.
        addr = self._expr(expr.addr)
        if addr != expr.addr:
            return ailment.expression.Load(expr.idx, addr, expr.size, expr.endness, **expr.tags)
        return expr

    def _handle_expr_Register(self, expr):  # pylint:disable=no-self-use
        # We don't want to return new values and construct new AIL expressions in caller methods without def-use
        # information. Otherwise, we may end up creating incorrect expressions.
        # Therefore, we do not perform register load, which essentially turns SimplifierAILEngine into a peephole
        # optimization engine.
        return expr

    def _handle_binop_Mul(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return ailment.expression.BinaryOp(expr.idx, "Mul", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _handle_binop_Mull(self, expr):
        operand_0 = self._expr(expr.operands[0])
        operand_1 = self._expr(expr.operands[1])

        if (operand_0, operand_1) != (expr.operands[0], expr.operands[1]):
            return ailment.expression.BinaryOp(expr.idx, "Mull", [operand_0, operand_1], expr.signed, **expr.tags)
        return expr

    def _handle_expr_Convert(self, expr):
        operand_expr = self._expr(expr.operand)

        if isinstance(operand_expr, ailment.expression.Convert):
            if expr.from_bits == operand_expr.to_bits and expr.to_bits == operand_expr.from_bits:
                # eliminate the redundant Convert
                return operand_expr.operand
            return ailment.expression.Convert(
                expr.idx,
                operand_expr.from_bits,
                expr.to_bits,
                expr.is_signed,
                operand_expr.operand,
                from_type=operand_expr.from_type,
                to_type=expr.to_type,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )
        if (
            type(operand_expr) is ailment.expression.Const
            and expr.from_type == ailment.expression.Convert.TYPE_INT
            and expr.to_type == ailment.expression.Convert.TYPE_INT
        ):
            # do the conversion right away
            value = operand_expr.value
            mask = (2**expr.to_bits) - 1
            value &= mask
            return ailment.expression.Const(expr.idx, operand_expr.variable, value, expr.to_bits, **expr.tags)
        if type(operand_expr) is ailment.expression.BinaryOp and operand_expr.op in {
            "Mul",
            "Shl",
            "Div",
            "Mod",
            "Add",
            "Sub",
        }:
            if isinstance(operand_expr.operands[1], ailment.expression.Const):
                if (
                    isinstance(operand_expr.operands[0], ailment.expression.Register)
                    and expr.from_bits == operand_expr.operands[0].bits
                ):
                    converted = ailment.expression.Convert(
                        expr.idx, expr.from_bits, expr.to_bits, expr.is_signed, operand_expr.operands[0]
                    )
                    converted_const = ailment.expression.Const(
                        operand_expr.operands[1].idx,
                        operand_expr.operands[1].variable,
                        operand_expr.operands[1].value,
                        expr.to_bits,
                        **operand_expr.operands[1].tags,
                    )
                    return ailment.expression.BinaryOp(
                        operand_expr.idx,
                        operand_expr.op,
                        [converted, converted_const],
                        operand_expr.signed,
                        **expr.tags,
                    )
                # TODO: the below optimization was unsound
                # Conv(32->64, (Conv(64->32, r14<8>) + 0x1<32>)) became Add(r14<8>, 0x1<32>)
                # ideally it should become Conv(32->64, Conv(64->32, r14<8> + 0x1<64>))
                # and then the double convert can be pretty-printed away
                # elif isinstance(operand_expr.operands[0], ailment.expression.Convert) and \
                #        expr.from_bits == operand_expr.operands[0].to_bits and \
                #        expr.to_bits == operand_expr.operands[0].from_bits:
                #    return ailment.expression.BinaryOp(operand_expr.idx, operand_expr.op,
                #                         [operand_expr.operands[0].operand, operand_expr.operands[1]],
                #                         operand_expr.signed,
                #                         **operand_expr.tags)
            elif (
                isinstance(operand_expr.operands[0], ailment.expression.Convert)
                and isinstance(operand_expr.operands[1], ailment.expression.Convert)
                and operand_expr.operands[0].from_bits == operand_expr.operands[1].from_bits
            ) and (
                operand_expr.operands[0].to_bits == operand_expr.operands[1].to_bits
                and expr.from_bits == operand_expr.operands[0].to_bits
                and expr.to_bits == operand_expr.operands[1].from_bits
            ):
                return ailment.expression.BinaryOp(
                    operand_expr.idx,
                    operand_expr.op,
                    [operand_expr.operands[0].operand, operand_expr.operands[1].operand],
                    expr.is_signed,
                    **operand_expr.tags,
                )

        return ailment.expression.Convert(
            expr.idx,
            expr.from_bits,
            expr.to_bits,
            expr.is_signed,
            operand_expr,
            from_type=expr.from_type,
            to_type=expr.to_type,
            rounding_mode=expr.rounding_mode,
            **expr.tags,
        )

    def _handle_expr_Const(self, expr):
        return expr

    def _handle_expr_Tmp(self, expr):
        return expr

    def _handle_expr_Reinterpret(self, expr):
        return expr

    def _handle_expr_ITE(self, expr):
        return ailment.expression.ITE(
            expr.idx,
            self._expr(expr.cond),
            self._expr(expr.iffalse),
            self._expr(expr.iftrue),
            variable=expr.variable,
            variable_offset=expr.variable_offset,
            **expr.tags,
        )

    def _handle_expr_Call(self, expr):
        return expr

    def _handle_expr_DirtyExpression(self, expr):
        return expr

    def _handle_expr_VEXCCallExpression(self, expr):
        return expr

    def _handle_expr_MultiStatementExpression(self, expr):
        return expr

    def _handle_expr_BasePointerOffset(self, expr):
        return expr

    def _handle_unop_Default(self, expr):
        operand = self._expr(expr.operand)
        if operand != expr.operand:
            return ailment.expression.UnaryOp(
                expr.idx, expr.op, operand, variable=expr.variable, variable_offset=expr.variable_offset, **expr.tags
            )
        return expr

    _handle_unop_Not = _handle_unop_Default
    _handle_unop_Neg = _handle_unop_Default
    _handle_unop_BitwiseNeg = _handle_unop_Default
    _handle_unop_Reference = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default

    def _handle_binop_Default(self, expr):
        lhs = self._expr(expr.operands[0])
        rhs = self._expr(expr.operands[1])
        if (lhs, rhs) != tuple(expr.operands):
            return ailment.expression.BinaryOp(
                expr.idx,
                expr.op,
                (lhs, rhs),
                expr.signed,
                variable=expr.variable,
                variable_offset=expr.variable_offset,
                bits=expr.bits,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                vector_count=expr.vector_count,
                vector_size=expr.vector_size,
                **expr.tags,
            )
        return expr

    _handle_binop_Add = _handle_binop_Default

    _handle_binop_AddF = _handle_binop_Default

    _handle_binop_AddV = _handle_binop_Default

    _handle_binop_Sub = _handle_binop_Default

    _handle_binop_SubF = _handle_binop_Default

    _handle_binop_SubV = _handle_binop_Default

    _handle_binop_MulF = _handle_binop_Default

    _handle_binop_MulV = _handle_binop_Default

    _handle_binop_MulHiV = _handle_binop_Default

    _handle_binop_Div = _handle_binop_Default

    _handle_binop_DivV = _handle_binop_Default

    _handle_binop_DivF = _handle_binop_Default

    _handle_binop_Mod = _handle_binop_Default

    _handle_binop_Xor = _handle_binop_Default

    _handle_binop_And = _handle_binop_Default

    _handle_binop_Or = _handle_binop_Default

    _handle_binop_LogicalAnd = _handle_binop_Default

    _handle_binop_LogicalOr = _handle_binop_Default

    _handle_binop_Shl = _handle_binop_Default

    _handle_binop_Shr = _handle_binop_Default

    _handle_binop_Sar = _handle_binop_Default

    _handle_binop_CmpF = _handle_binop_Default

    _handle_binop_CmpEQ = _handle_binop_Default

    _handle_binop_CmpNE = _handle_binop_Default

    _handle_binop_CmpLT = _handle_binop_Default

    _handle_binop_CmpLE = _handle_binop_Default

    _handle_binop_CmpGT = _handle_binop_Default

    _handle_binop_CmpGE = _handle_binop_Default

    _handle_binop_Concat = _handle_binop_Default

    _handle_binop_Ror = _handle_binop_Default

    _handle_binop_Rol = _handle_binop_Default

    _handle_binop_Carry = _handle_binop_Default

    _handle_binop_SCarry = _handle_binop_Default

    _handle_binop_SBorrow = _handle_binop_Default

    _handle_binop_InterleaveLOV = _handle_binop_Default

    _handle_binop_InterleaveHIV = _handle_binop_Default

    _handle_binop_CasCmpEQ = _handle_binop_Default

    _handle_binop_CasCmpNE = _handle_binop_Default

    _handle_binop_ExpCmpNE = _handle_binop_Default

    _handle_binop_SarNV = _handle_binop_Default

    _handle_binop_ShrNV = _handle_binop_Default

    _handle_binop_ShlNV = _handle_binop_Default

    _handle_binop_CmpEQV = _handle_binop_Default

    _handle_binop_CmpNEV = _handle_binop_Default

    _handle_binop_CmpGEV = _handle_binop_Default

    _handle_binop_CmpGTV = _handle_binop_Default

    _handle_binop_CmpLEV = _handle_binop_Default

    _handle_binop_CmpLTV = _handle_binop_Default

    _handle_binop_MinV = _handle_binop_Default

    _handle_binop_MaxV = _handle_binop_Default

    _handle_binop_QAddV = _handle_binop_Default

    _handle_binop_QNarrowBinV = _handle_binop_Default

    _handle_binop_PermV = _handle_binop_Default

    _handle_binop_Set = _handle_binop_Default
