# pylint:disable=unused-argument,no-self-use
from __future__ import annotations
import logging

from ailment.block import Block
from ailment.statement import Statement, Assignment, Store, Call, Return, ConditionalJump
from ailment.expression import (
    Register,
    VirtualVariable,
    Load,
    Const,
    BinaryOp,
    Phi,
    Convert,
    StackBaseOffset,
    ITE,
)

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin


_l = logging.getLogger(__name__)


class SimEngineDephiRewriting(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine rewrites every block to insert phi variables and replaces every used variable with their versioned
    copies at each use location.
    """

    state: None

    def __init__(
        self,
        arch,
        vvar_to_vvar: dict[int, int],
    ):
        super().__init__()

        self.arch = arch
        self.vvar_to_vvar = vvar_to_vvar
        self.out_block = None

    def append_statement(self, stmt: Statement) -> None:
        if self.out_block is None:
            self.out_block = Block(self.block.addr, self.block.original_size, statements=[], idx=self.block.idx)
        self.out_block.statements.append(stmt)

    #
    # Handlers
    #

    def _handle_Stmt(self, stmt: Statement):
        new_stmt = super()._handle_Stmt(stmt)
        if new_stmt is not None:
            if type(new_stmt) is tuple:
                for s in new_stmt:
                    self.append_statement(s)
            else:
                self.append_statement(new_stmt)
        else:
            self.append_statement(stmt)

    def _handle_Assignment(self, stmt: Assignment) -> Assignment | tuple[Assignment, ...] | None:
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

        if new_dst is not None or new_src is not None:
            return Assignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
        return None

    def _handle_Store(self, stmt: Store) -> Store | None:
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

    def _handle_ConditionalJump(self, stmt: ConditionalJump) -> ConditionalJump | None:
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

    def _handle_Call(self, stmt: Call) -> Call | None:
        new_target = self._expr(stmt.target) if stmt.target is not None else None
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
                **stmt.tags,
            )
        return None

    def _handle_Register(self, expr: Register) -> None:
        return None

    def _handle_Load(self, expr: Load) -> Load | None:
        new_addr = self._expr(expr.addr)
        if new_addr is not None:
            return Load(expr.idx, new_addr, expr.size, expr.endness, guard=expr.guard, alt=expr.alt, **expr.tags)
        return None

    def _handle_Convert(self, expr: Convert) -> Convert | None:
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

    def _handle_Const(self, expr: Const) -> None:
        return None

    def _handle_Phi(self, expr: Phi) -> None:
        return None

    def _handle_VirtualVariable(self, expr: VirtualVariable) -> VirtualVariable | None:
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

    def _handle_Return(self, expr: Return) -> Return | None:
        if expr.ret_exprs is None:
            new_ret_exprs = None
        else:
            updated = False
            new_ret_exprs = []
            for r in expr.ret_exprs:
                new_r = self._expr(r)
                if new_r is not None:
                    updated = True
                new_ret_exprs.append(new_r if new_r is not None else None)
            if not updated:
                new_ret_exprs = None

        if new_ret_exprs:
            return Return(expr.idx, new_ret_exprs, **expr.tags)
        return None

    def _handle_BinaryOp(self, expr: BinaryOp) -> BinaryOp | None:
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
                from_bits=expr.from_bits,
                to_bits=expr.to_bits,
                **expr.tags,
            )
        return None

    def _handle_ITE(self, expr: ITE) -> ITE | None:
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

    def _handle_StackBaseOffset(self, expr: StackBaseOffset) -> None:
        return None
