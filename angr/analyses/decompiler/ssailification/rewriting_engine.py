from __future__ import annotations
from typing import Any

from ailment.statement import Statement, Assignment, Store, Call, Return, ConditionalJump
from ailment.expression import (
    Expression,
    Register,
    VirtualVariable,
    Load,
    Const,
    VirtualVariableCategory,
    BinaryOp,
    Phi,
)

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin
from .rewriting_state import RewritingState


class SimEngineSSARewriting(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine rewrites every block to insert phi variables and replaces every used variable with their versioned
    copies at each use location.
    """

    state: RewritingState

    def __init__(
        self,
        arch,
        sp_tracker=None,
        bp_as_gpr: bool = False,
        def_to_vvid: dict[Any, int] = None,
        udef_to_phiid: dict[tuple, set[int]] = None,
        phiid_to_loc: dict[int, tuple[int, int | None]] = None,
    ):
        super().__init__()

        self.arch = arch
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.def_to_vvid = def_to_vvid
        self.udef_to_phiid = udef_to_phiid
        self.phiid_to_loc = phiid_to_loc

    #
    # Handlers
    #

    def _handle_Stmt(self, stmt: Statement):
        new_stmt = super()._handle_Stmt(stmt)
        if new_stmt is not None:
            self.state.append_statement(new_stmt)
        else:
            self.state.append_statement(stmt)

    def _handle_Assignment(self, stmt: Assignment) -> Assignment | None:
        new_src = self._expr(stmt.src)

        if isinstance(stmt.dst, VirtualVariable):
            if stmt.dst.category == VirtualVariableCategory.REGISTER:
                self.state.registers[stmt.dst.oident] = stmt.dst
            new_dst = None
        else:
            new_dst = self._replace_def_expr(stmt.dst)

        if new_dst is not None:
            if isinstance(stmt.dst, Register):
                # TODO: Support partial registers
                self.state.registers[stmt.dst.reg_offset] = new_dst
            else:
                raise NotImplementedError()

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
        new_target = self._replace_use_reg(stmt.target) if isinstance(stmt.target, Register) else None
        new_ret_expr = self._replace_def_expr(stmt.ret_expr) if stmt.ret_expr is not None else None
        new_fp_ret_expr = self._replace_def_expr(stmt.fp_ret_expr) if stmt.fp_ret_expr is not None else None

        if new_ret_expr is not None:
            if isinstance(stmt.ret_expr, Register):
                self.state.registers[stmt.ret_expr.reg_offset] = new_ret_expr
        if new_fp_ret_expr is not None:
            if isinstance(stmt.fp_ret_expr, Register):
                self.state.registers[stmt.fp_ret_expr.reg_offset] = new_fp_ret_expr

        if new_target is not None or new_ret_expr is not None:
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

    def _handle_Register(self, expr: Register) -> VirtualVariable | None:
        new_expr = self._replace_use_reg(expr)
        if new_expr is None:
            # maybe it's used for the first time here, in which case it's defined here!
            new_expr = self._replace_def_expr(expr)
            if new_expr is not None:
                self.state.registers[expr.reg_offset] = new_expr
        return new_expr

    def _handle_Load(self, expr: Load) -> Load | None:
        new_addr = self._expr(expr.addr)
        if new_addr is not None:
            return Load(expr.idx, new_addr, expr.size, expr.endness, guard=expr.guard, alt=expr.alt, **expr.tags)
        return None

    def _handle_Const(self, expr: Const) -> None:
        return None

    def _handle_Phi(self, expr: Phi) -> None:
        return None

    def _handle_Return(self, expr: Return) -> Return | None:
        new_ret_exprs = tuple(map(self._expr, expr.ret_exprs)) if expr.ret_exprs is not None else None
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
                rounding=expr.rounding_mode,
                from_bits=expr.from_bits,
                to_bits=expr.to_bits,
                **expr.tags,
            )
        return None

    #
    # Expression replacement
    #

    def _replace_def_expr(self, expr: Expression) -> VirtualVariable | None:
        if isinstance(expr, Register):
            # get the virtual variable ID
            vvid = self.get_vvid_by_def(expr)
            if vvid is not None:
                return VirtualVariable(
                    expr.idx, vvid, expr.bits, VirtualVariableCategory.REGISTER, oident=expr.reg_offset, **expr.tags
                )
        return None

    def _replace_use_reg(self, reg_expr: Register) -> VirtualVariable | None:
        if reg_expr.reg_offset in self.state.registers:
            vvar = self.state.registers[reg_expr.reg_offset]
            if vvar is not None:
                return VirtualVariable(
                    reg_expr.idx,
                    vvar.varid,
                    reg_expr.bits,
                    VirtualVariableCategory.REGISTER,
                    oident=reg_expr.reg_offset,
                    **reg_expr.tags,
                )
        return None

    #
    # Utils
    #

    def get_vvid_by_def(self, expr: Expression) -> int | None:
        return self.def_to_vvid.get(expr, None)
