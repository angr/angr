# pylint:disable=unused-argument,no-self-use,too-many-boolean-expressions
from __future__ import annotations
from typing import TYPE_CHECKING
import logging

from angr.ailment.block import Block
from angr.ailment.statement import (
    Statement,
    Assignment,
    Store,
    Call,
    CAS,
    Return,
    ConditionalJump,
    DirtyStatement,
    WeakAssignment,
)
from angr.ailment.expression import (
    Atom,
    Expression,
    VirtualVariable,
    Load,
    BinaryOp,
    UnaryOp,
    Phi,
    Convert,
    ITE,
    VEXCCallExpression,
    DirtyExpression,
    Reinterpret,
)
from angr.engines.light import SimEngineNostmtAIL

if TYPE_CHECKING:
    from angr import KnowledgeBase


_l = logging.getLogger(__name__)


class SimEngineDephiRewriting(SimEngineNostmtAIL[None, Expression | None, Statement | tuple[Statement, ...], None]):
    """
    This engine rewrites every block to insert phi variables and replaces every used variable with their versioned
    copies at each use location.
    """

    state: None

    def __init__(
        self,
        project,
        vvar_to_vvar: dict[int, int],
        func_addr: int | None = None,
        variable_kb: KnowledgeBase | None = None,
    ):
        super().__init__(project)

        self.vvar_to_vvar = vvar_to_vvar
        self.out_block = None
        self.func_addr = func_addr
        self.variable_kb = variable_kb

        self._stmt_handlers["IncompleteSwitchCaseHeadStatement"] = self._handle_stmt_IncompleteSwitchCaseHeadStatement

    def _top(self, bits):
        assert False, "Unreachable"

    def _is_top(self, expr):
        return False

    def append_statement(self, stmt: Statement) -> None:
        if self.out_block is None:
            self.out_block = Block(self.block.addr, self.block.original_size, statements=[], idx=self.block.idx)
        self.out_block.statements.append(stmt)

    #
    # Handlers
    #

    def _process_block_end(self, block, stmt_data, whitelist):
        assert whitelist is None
        for stmt_idx, new_stmt in enumerate(stmt_data):
            if new_stmt is not None:
                if isinstance(new_stmt, tuple):
                    for stmt_ in new_stmt:
                        self.append_statement(stmt_)
                else:
                    self.append_statement(new_stmt)
            else:
                self.append_statement(block.statements[stmt_idx])

    def _handle_stmt_Assignment(self, stmt):
        new_src = self._expr(stmt.src)
        new_dst = None

        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in self.vvar_to_vvar:
            new_varid = self.vvar_to_vvar[stmt.dst.varid]
            new_dst = VirtualVariable(
                stmt.dst.idx,
                new_varid,
                stmt.dst.bits,
                stmt.dst.category,
                oident=stmt.dst.oident,
                variable=stmt.dst.variable,
                variable_offset=stmt.dst.variable_offset,
                **stmt.dst.tags,
            )

        # ensure we do not generate vvar_A = vvar_A or var_A = var_A (even if lhs and rhs are different vvars, they
        # can be mapped to the same variable)
        dst = stmt.dst if new_dst is None else new_dst
        src = stmt.src if new_src is None else new_src
        if isinstance(dst, VirtualVariable) and isinstance(src, VirtualVariable):
            if dst.varid == src.varid:
                # skip it
                return ()
            if (
                self.func_addr is not None
                and self.variable_kb is not None
                and self.func_addr in self.variable_kb.variables
            ):
                dst_var = getattr(dst, "variable", None)
                src_var = getattr(src, "variable", None)
                var_manager = self.variable_kb.variables[self.func_addr]
                if (
                    dst_var is not None
                    and src_var is not None
                    and var_manager.unified_variable(dst_var) is var_manager.unified_variable(src_var)
                ):
                    # skip it
                    return ()

            return Assignment(stmt.idx, dst, src, **stmt.tags)
        return None

    def _handle_stmt_WeakAssignment(self, stmt) -> WeakAssignment | None:
        new_src = self._expr(stmt.src)
        new_dst = self._expr(stmt.dst)

        if new_dst is not None or new_src is not None:
            return WeakAssignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,  # type: ignore
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
        return None

    def _handle_stmt_CAS(self, stmt: CAS) -> CAS | None:
        new_addr = self._expr(stmt.addr)
        new_data_lo = self._expr(stmt.data_lo)
        new_data_hi = self._expr(stmt.data_hi) if stmt.data_hi is not None else None
        new_expd_lo = self._expr(stmt.expd_lo)
        new_expd_hi = self._expr(stmt.expd_hi) if stmt.expd_hi is not None else None
        new_old_lo = self._expr(stmt.old_lo)
        new_old_hi = self._expr(stmt.old_hi) if stmt.old_hi is not None else None
        assert new_old_lo is None or isinstance(new_old_lo, Atom)
        assert new_old_hi is None or isinstance(new_old_hi, Atom)

        if (
            new_addr is not None
            or new_old_lo is not None
            or new_old_hi is not None
            or new_data_lo is not None
            or new_data_hi is not None
            or new_expd_lo is not None
            or new_expd_hi is not None
        ):
            return CAS(
                stmt.idx,
                stmt.addr if new_addr is None else new_addr,
                stmt.data_lo if new_data_lo is None else new_data_lo,
                stmt.data_hi if new_data_hi is None else new_data_hi,
                stmt.expd_lo if new_expd_lo is None else new_expd_lo,
                stmt.expd_hi if new_expd_hi is None else new_expd_hi,
                stmt.old_lo if new_old_lo is None else new_old_lo,
                stmt.old_hi if new_old_hi is None else new_old_hi,
                stmt.endness,
                **stmt.tags,
            )
        return None

    def _handle_stmt_Store(self, stmt):
        new_addr = self._expr(stmt.addr)
        new_data = self._expr(stmt.data)

        if new_addr is not None or new_data is not None:
            return Store(
                stmt.idx,
                stmt.addr if new_addr is None else new_addr,
                stmt.data if new_data is None else new_data,
                stmt.size,
                stmt.endness,
                variable=stmt.variable,
                guard=stmt.guard,
                **stmt.tags,
            )

        return None

    def _handle_stmt_ConditionalJump(self, stmt):
        new_cond = self._expr(stmt.condition)
        new_true_target = self._expr(stmt.true_target) if stmt.true_target is not None else None
        new_false_target = self._expr(stmt.false_target) if stmt.false_target is not None else None

        if new_cond is not None or new_true_target is not None or new_false_target is not None:
            return ConditionalJump(
                stmt.idx,
                stmt.condition if new_cond is None else new_cond,
                stmt.true_target if new_true_target is None else new_true_target,
                stmt.false_target if new_false_target is None else new_false_target,
                true_target_idx=stmt.true_target_idx,
                false_target_idx=stmt.false_target_idx,
                **stmt.tags,
            )
        return None

    def _handle_stmt_Call(self, stmt):
        new_target = self._expr(stmt.target) if stmt.target is not None and not isinstance(stmt.target, str) else None
        new_ret_expr = self._expr(stmt.ret_expr) if stmt.ret_expr is not None else None
        new_fp_ret_expr = self._expr(stmt.fp_ret_expr) if stmt.fp_ret_expr is not None else None

        if new_target is not None or new_ret_expr is not None or new_fp_ret_expr is not None:
            return Call(
                stmt.idx,
                stmt.target if new_target is None else new_target,
                calling_convention=stmt.calling_convention,
                prototype=stmt.prototype,
                args=stmt.args,
                ret_expr=stmt.ret_expr if new_ret_expr is None else new_ret_expr,
                fp_ret_expr=stmt.fp_ret_expr if new_fp_ret_expr is None else new_fp_ret_expr,
                bits=stmt.bits,
                **stmt.tags,
            )
        return None

    def _handle_stmt_DirtyStatement(self, stmt: DirtyStatement) -> DirtyStatement | None:
        dirty = self._expr(stmt.dirty)
        if dirty is None or dirty is stmt.dirty:
            return None
        assert isinstance(dirty, DirtyExpression)
        return DirtyStatement(stmt.idx, dirty, **stmt.tags)

    def _handle_expr_Load(self, expr):
        new_addr = self._expr(expr.addr)
        if new_addr is not None:
            return Load(expr.idx, new_addr, expr.size, expr.endness, guard=expr.guard, alt=expr.alt, **expr.tags)
        return None

    def _handle_expr_Convert(self, expr: Convert) -> Convert | None:
        new_operand = self._expr(expr.operand)
        if new_operand is not None:
            return Convert(
                expr.idx,
                expr.from_bits,
                expr.to_bits,
                expr.is_signed,
                new_operand,
                from_type=expr.from_type,
                to_type=expr.to_type,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )
        return None

    def _handle_expr_Reinterpret(self, expr: Reinterpret) -> Reinterpret | None:
        new_operand = self._expr(expr.operand)
        if new_operand is not None:
            return Reinterpret(
                expr.idx,
                expr.from_bits,
                expr.from_type,
                expr.to_bits,
                expr.to_type,
                new_operand,
                **expr.tags,
            )
        return None

    def _handle_expr_Const(self, expr):
        return None

    def _handle_expr_Phi(self, expr: Phi) -> None:
        return None

    def _handle_expr_VirtualVariable(self, expr: VirtualVariable) -> VirtualVariable | None:
        if expr.varid in self.vvar_to_vvar:
            return VirtualVariable(
                expr.idx,
                self.vvar_to_vvar[expr.varid],
                expr.bits,
                expr.category,
                oident=expr.oident,
                variable=expr.variable,
                variable_offset=expr.variable_offset,
                **expr.tags,
            )
        return None

    def _handle_stmt_Return(self, stmt):
        if stmt.ret_exprs is None:
            new_ret_exprs = None
        else:
            updated = False
            new_ret_exprs = []
            for r in stmt.ret_exprs:
                new_r = self._expr(r)
                if new_r is not None:
                    updated = True
                new_ret_exprs.append(new_r if new_r is not None else None)
            if not updated:
                new_ret_exprs = None

        if new_ret_exprs:
            return Return(stmt.idx, new_ret_exprs, **stmt.tags)
        return None

    def _handle_stmt_IncompleteSwitchCaseHeadStatement(self, stmt):
        return None

    def _handle_expr_BinaryOp(self, expr):
        new_op0 = self._expr(expr.operands[0])
        new_op1 = self._expr(expr.operands[1])

        if new_op0 is not None or new_op1 is not None:
            return BinaryOp(
                expr.idx,
                expr.op,
                [
                    expr.operands[0] if new_op0 is None else new_op0,
                    expr.operands[1] if new_op1 is None else new_op1,
                ],
                expr.signed,
                bits=expr.bits,
                floating_point=expr.floating_point,
                rounding_mode=expr.rounding_mode,
                **expr.tags,
            )
        return None

    def _handle_expr_UnaryOp(self, expr):
        new_op0 = self._expr(expr.operands[0])

        if new_op0 is not None:
            return UnaryOp(
                expr.idx,
                expr.op,
                expr.operands[0] if new_op0 is None else new_op0,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_expr_ITE(self, expr):
        new_cond = self._expr(expr.cond)
        new_iftrue = self._expr(expr.iftrue)
        new_iffalse = self._expr(expr.iffalse)

        if new_cond is not None or new_iftrue is not None or new_iffalse is not None:
            return ITE(
                expr.idx,
                expr.cond if new_cond is None else new_cond,
                expr.iftrue if new_iftrue is None else new_iftrue,
                expr.iffalse if new_iffalse is None else new_iffalse,
                **expr.tags,
            )
        return None

    def _handle_VEXCCallExpression(self, expr: VEXCCallExpression) -> VEXCCallExpression | None:
        new_operands = []
        updated = False
        for o in expr.operands:
            new_o = self._expr(o)
            if new_o is not None:
                updated = True
                new_operands.append(new_o)
            else:
                new_operands.append(o)

        if updated:
            return VEXCCallExpression(
                expr.idx,
                expr.callee,
                tuple(new_operands),
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_expr_DirtyExpression(self, expr: DirtyExpression) -> DirtyExpression | None:
        new_operands = []
        updated = False
        for o in expr.operands:
            new_o = self._expr(o)
            if new_o is not None:
                updated = True
                new_operands.append(new_o)
            else:
                new_operands.append(o)

        new_guard = None
        if expr.guard is not None:
            new_guard = self._expr(expr.guard)
            if new_guard is not None:
                updated = True

        if updated:
            return DirtyExpression(
                expr.idx,
                expr.callee,
                new_operands,
                guard=new_guard,
                mfx=expr.mfx,
                maddr=expr.maddr,
                msize=expr.msize,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_expr_BasePointerOffset(self, expr):
        return None

    def _handle_expr_StackBaseOffset(self, expr):
        return None

    def _handle_expr_Call(self, expr: Call):
        new_target = self._expr(expr.target) if expr.target is not None and not isinstance(expr.target, str) else None
        new_ret_expr = self._expr(expr.ret_expr) if expr.ret_expr is not None else None
        new_fp_ret_expr = self._expr(expr.fp_ret_expr) if expr.fp_ret_expr is not None else None

        if new_target is not None or new_ret_expr is not None or new_fp_ret_expr is not None:
            return Call(
                expr.idx,
                expr.target if new_target is None else new_target,
                calling_convention=expr.calling_convention,
                prototype=expr.prototype,
                args=expr.args,
                ret_expr=expr.ret_expr if new_ret_expr is None else new_ret_expr,
                fp_ret_expr=expr.fp_ret_expr if new_fp_ret_expr is None else new_fp_ret_expr,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_expr_MultiStatementExpression(self, expr):
        return None

    def _handle_expr_Register(self, expr):
        return None

    def _handle_expr_Tmp(self, expr):
        return None

    def _handle_expr_VEXCCallExpression(self, expr):
        return None

    def _unreachable(self, *args, **kwargs):
        assert False

    _handle_binop_Add = _unreachable
    _handle_binop_AddF = _unreachable
    _handle_binop_AddV = _unreachable
    _handle_binop_And = _unreachable
    _handle_binop_Carry = _unreachable
    _handle_binop_CmpEQ = _unreachable
    _handle_binop_CmpF = _unreachable
    _handle_binop_CmpGE = _unreachable
    _handle_binop_CmpGT = _unreachable
    _handle_binop_CmpLE = _unreachable
    _handle_binop_CmpLT = _unreachable
    _handle_binop_CmpNE = _unreachable
    _handle_binop_Concat = _unreachable
    _handle_binop_Div = _unreachable
    _handle_binop_DivF = _unreachable
    _handle_binop_DivV = _unreachable
    _handle_binop_LogicalAnd = _unreachable
    _handle_binop_LogicalOr = _unreachable
    _handle_binop_Mod = _unreachable
    _handle_binop_Mul = _unreachable
    _handle_binop_Mull = _unreachable
    _handle_binop_MulF = _unreachable
    _handle_binop_MulV = _unreachable
    _handle_binop_MulHiV = _unreachable
    _handle_binop_Or = _unreachable
    _handle_binop_Rol = _unreachable
    _handle_binop_Ror = _unreachable
    _handle_binop_SBorrow = _unreachable
    _handle_binop_SCarry = _unreachable
    _handle_binop_Sar = _unreachable
    _handle_binop_Shl = _unreachable
    _handle_binop_Shr = _unreachable
    _handle_binop_Sub = _unreachable
    _handle_binop_SubF = _unreachable
    _handle_binop_SubV = _unreachable
    _handle_binop_Xor = _unreachable
    _handle_binop_InterleaveLOV = _unreachable
    _handle_binop_InterleaveHIV = _unreachable
    _handle_binop_CasCmpEQ = _unreachable
    _handle_binop_CasCmpNE = _unreachable
    _handle_binop_ExpCmpNE = _unreachable
    _handle_binop_SarNV = _unreachable
    _handle_binop_ShrNV = _unreachable
    _handle_binop_ShlNV = _unreachable
    _handle_binop_CmpEQV = _unreachable
    _handle_binop_CmpNEV = _unreachable
    _handle_binop_CmpGEV = _unreachable
    _handle_binop_CmpGTV = _unreachable
    _handle_binop_CmpLEV = _unreachable
    _handle_binop_CmpLTV = _unreachable
    _handle_binop_MinV = _unreachable
    _handle_binop_MaxV = _unreachable
    _handle_binop_QAddV = _unreachable
    _handle_binop_QNarrowBinV = _unreachable
    _handle_binop_PermV = _unreachable
    _handle_binop_Set = _unreachable
    _handle_unop_BitwiseNeg = _unreachable
    _handle_unop_Dereference = _unreachable
    _handle_unop_Neg = _unreachable
    _handle_unop_Not = _unreachable
    _handle_unop_Reference = _unreachable
    _handle_unop_Clz = _unreachable
    _handle_unop_Ctz = _unreachable
    _handle_unop_GetMSBs = _unreachable
    _handle_unop_unpack = _unreachable
    _handle_unop_Sqrt = _unreachable
    _handle_unop_RSqrtEst = _unreachable
