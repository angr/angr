from __future__ import annotations
from typing import Any
from itertools import count
import logging

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
    Convert,
)

from angr.utils.ssa import get_reg_offset_base_and_size
from angr.engines.light import SimEngineLight, SimEngineLightAILMixin
from .rewriting_state import RewritingState


_l = logging.getLogger(__name__)


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
        udef_to_phiid: dict[tuple, set[int]] = None,
        phiid_to_loc: dict[int, tuple[int, int | None]] = None,
        ail_manager=None,
    ):
        super().__init__()

        self.arch = arch
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.def_to_vvid: dict[Any, int] = {}
        self.vvar_id_ctr = count()
        self.udef_to_phiid = udef_to_phiid
        self.phiid_to_loc = phiid_to_loc
        self.ail_manager = ail_manager

    #
    # Handlers
    #

    def _handle_Stmt(self, stmt: Statement):
        new_stmt = super()._handle_Stmt(stmt)
        if new_stmt is not None:
            if type(new_stmt) is tuple:
                map(self.state.append_statement, new_stmt)
            else:
                self.state.append_statement(new_stmt)
        else:
            self.state.append_statement(stmt)

    def _handle_Assignment(self, stmt: Assignment) -> Assignment | tuple[Assignment, ...] | None:
        new_src = self._expr(stmt.src)

        if isinstance(stmt.dst, VirtualVariable):
            if stmt.dst.category == VirtualVariableCategory.REGISTER:
                self.state.registers[stmt.dst.oident][stmt.dst.size] = stmt.dst
            new_dst = None
        else:
            new_dst = self._replace_def_expr(stmt.dst)

        stmt_base_reg = None
        if new_dst is not None:
            if isinstance(stmt.dst, Register):
                # remove everything else that is an alias
                # we keep the base register around because it's always updated immediately, and will be used in the
                # case of partial register update
                self._clear_aliasing_regs(stmt.dst.reg_offset, stmt.dst.size, remove_base_reg=False)

                self.state.registers[stmt.dst.reg_offset][stmt.dst.size] = new_dst

                # generate an assignment that updates the base register if needed
                base_offset, base_size = get_reg_offset_base_and_size(
                    stmt.dst.reg_offset, self.arch, size=stmt.dst.size
                )
                if base_offset != stmt.dst.reg_offset or base_size != stmt.dst.size:
                    base_reg_expr = Register(
                        self.ail_manager.next_atom(),
                        None,
                        base_offset,
                        base_size * self.arch.byte_width,
                        **stmt.dst.tags,
                    )
                    existing_base_reg_vvar = self._replace_use_reg(base_reg_expr)
                    base_reg_vvar = self._replace_def_expr(base_reg_expr)
                    stmt_base_reg = Assignment(
                        self.ail_manager.next_atom(),
                        base_reg_vvar,
                        self._reg_update_expr(
                            existing_base_reg_vvar, base_offset, base_size, new_dst, stmt.dst.reg_offset, stmt.dst.size
                        ),
                        **stmt.tags,
                    )
                    self.state.registers[base_offset][base_size] = base_reg_vvar
            else:
                raise NotImplementedError()

        if new_dst is not None or new_src is not None:
            new_stmt = Assignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
            if stmt_base_reg is not None:
                return new_stmt, stmt
            return new_stmt
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
                base_off, base_size = get_reg_offset_base_and_size(
                    stmt.ret_expr.reg_offset, self.arch, size=stmt.ret_expr.size
                )
                self._clear_aliasing_regs(base_off, base_size)
                self.state.registers[base_off][base_size] = new_ret_expr
        if new_fp_ret_expr is not None:
            if isinstance(stmt.fp_ret_expr, Register):
                self._clear_aliasing_regs(stmt.fp_ret_expr.reg_offset, stmt.fp_ret_expr.size)
                self.state.registers[stmt.fp_ret_expr.reg_offset][stmt.fp_ret_expr.size] = new_fp_ret_expr

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

    def _reg_update_expr(
        self,
        existing_vvar: VirtualVariable,
        base_offset: int,
        base_size: int,
        new_vvar: VirtualVariable,
        offset: int,
        size: int,
    ) -> VirtualVariable | Expression:
        if offset == base_offset and base_size == size:
            return new_vvar
        if base_offset > offset:
            raise ValueError(f"Base offset {base_offset} is greater than expression offset {offset}")

        base_mask = ((1 << (base_size * self.arch.byte_width)) - 1) ^ (
            ((1 << (size * self.arch.byte_width)) - 1) << ((offset - base_offset) * self.arch.byte_width)
        )
        new_base_expr = BinaryOp(
            self.ail_manager.next_atom(),
            "Or",
            [existing_vvar, base_mask],
            False,
            bits=existing_vvar.bits,
            **existing_vvar.tags,
        )
        assert size < base_size
        extended_vvar = Convert(
            self.ail_manager.next_atom(),
            size * self.arch.byte_width,
            base_size * self.arch.byte_width,
            False,
            new_vvar,
            **new_vvar.tags,
        )
        if base_offset < offset:
            shift_amount = Const(
                self.ail_manager.next_atom(), None, (offset - base_offset) * self.arch.byte_width, self.arch.byte_width
            )
            shifted_vvar = BinaryOp(
                self.ail_manager.next_atom(),
                "Shl",
                [
                    extended_vvar,
                    shift_amount,
                ],
                extended_vvar.bits,
                **extended_vvar.tags,
            )
        else:
            shifted_vvar = extended_vvar
        assert new_base_expr.bits == shifted_vvar.bits
        new_expr = BinaryOp(
            self.ail_manager.next_atom(),
            "Or",
            [
                new_base_expr,
                shifted_vvar,
            ],
            False,
            bits=new_base_expr.bits,
            **new_base_expr.tags,
        )
        return new_expr

    def _replace_def_expr(self, expr: Expression) -> VirtualVariable | None:
        """
        Return a new virtual variable for the given defined expression.
        """

        if isinstance(expr, Register):
            # get the virtual variable ID
            vvid = self.get_vvid_by_def(expr)
            base_offset, base_size = get_reg_offset_base_and_size(expr.reg_offset, self.arch, size=expr.size)
            return VirtualVariable(
                expr.idx,
                vvid,
                base_size * self.arch.byte_width,
                VirtualVariableCategory.REGISTER,
                oident=base_offset,
                **expr.tags,
            )
        return None

    def _get_full_reg_vvar(self, reg_offset: int, size: int) -> VirtualVariable:
        base_off, base_size = get_reg_offset_base_and_size(reg_offset, self.arch, size=size)
        if base_off not in self.state.registers or base_size not in self.state.registers[base_off]:
            # somehow it's never defined before...
            _l.warning("Creating a new virtual variable for an undefined register (%d [%d]).", base_off, base_size)
            vvar = VirtualVariable(
                self.ail_manager.next_atom(),
                next(self.vvar_id_ctr),
                base_size * self.arch.byte_width,
                category=VirtualVariableCategory.REGISTER,
                oident=base_off,
                # FIXME: tags
            )
            self.state.registers[base_off][base_size] = vvar
            return vvar
        return self.state.registers[base_off][base_size]

    def _replace_use_reg(self, reg_expr: Register) -> VirtualVariable | Expression:

        if reg_expr.reg_offset in self.state.registers:
            if reg_expr.size in self.state.registers[reg_expr.reg_offset]:
                vvar = self.state.registers[reg_expr.reg_offset][reg_expr.size]
                return VirtualVariable(
                    reg_expr.idx,
                    vvar.varid,
                    vvar.bits,
                    VirtualVariableCategory.REGISTER,
                    oident=reg_expr.reg_offset,
                    **reg_expr.tags,
                )

            for existing_size in sorted(self.state.registers[reg_expr.reg_offset], reverse=True):
                if reg_expr.size < existing_size:
                    vvar = self.state.registers[reg_expr.reg_offset][existing_size]
                    # extract it
                    truncated = Convert(
                        self.ail_manager.next_atom(),
                        vvar.bits,
                        reg_expr.bits,
                        False,
                        vvar,
                        **reg_expr.tags,
                    )
                    return truncated
                else:
                    break

        # no good size available
        # get the full register, then extract from there
        vvar = self._get_full_reg_vvar(reg_expr.reg_offset, reg_expr.size)
        # extract
        shift_amount = Const(
            self.ail_manager.next_atom(),
            None,
            (reg_expr.reg_offset - vvar.oident) * self.arch.byte_width,
            8,
            **reg_expr.tags,
        )
        shifted = BinaryOp(
            self.ail_manager.next_atom(),
            "Shr",
            [
                vvar,
                shift_amount,
            ],
            False,
            bits=vvar.bits,
            **reg_expr.tags,
        )
        truncated = Convert(
            self.ail_manager.next_atom(),
            shifted.bits,
            reg_expr.bits,
            False,
            shifted,
            **reg_expr.tags,
        )
        return truncated

    #
    # Utils
    #

    def get_vvid_by_def(self, expr: Expression) -> int:
        if expr in self.def_to_vvid:
            return self.def_to_vvid[expr]
        vvid = next(self.vvar_id_ctr)
        self.def_to_vvid[expr] = vvid
        return vvid

    def _clear_aliasing_regs(self, reg_offset: int, size: int, remove_base_reg: bool = True) -> None:
        base_offset, base_size = get_reg_offset_base_and_size(reg_offset, self.arch, size=size)
        for off in range(base_offset, base_offset + base_size):
            if off in self.state.registers:
                if not remove_base_reg and off == base_offset and base_size in self.state.registers[off]:
                    if len(self.state.registers[off]) > 1:
                        self.state.registers[off] = {base_size: self.state.registers[off][base_size]}
                else:
                    del self.state.registers[off]
