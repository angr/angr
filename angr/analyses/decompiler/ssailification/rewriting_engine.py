# pylint:disable=no-self-use,unused-argument
from __future__ import annotations
import logging

from ailment.manager import Manager
from ailment.statement import Statement, Assignment, Store, Call, Return, ConditionalJump, DirtyStatement
from ailment.expression import (
    Expression,
    Register,
    VirtualVariable,
    Load,
    Const,
    VirtualVariableCategory,
    BinaryOp,
    UnaryOp,
    Convert,
    StackBaseOffset,
    VEXCCallExpression,
    ITE,
    Tmp,
    DirtyExpression,
)

from angr.engines.light.engine import SimEngineNostmtAIL
from angr.utils.ssa import get_reg_offset_base_and_size
from .rewriting_state import RewritingState


_l = logging.getLogger(__name__)


class SimEngineSSARewriting(
    SimEngineNostmtAIL[RewritingState, Expression | None, Statement | tuple[Statement, ...], None]
):
    """
    This engine rewrites every block to insert phi variables and replaces every used variable with their versioned
    copies at each use location.
    """

    def __init__(
        self,
        project,
        *,
        sp_tracker,
        udef_to_phiid: dict[tuple, set[int]],
        phiid_to_loc: dict[int, tuple[int, int | None]],
        stackvar_locs: dict[int, int],
        ail_manager: Manager,
        vvar_id_start: int = 0,
        bp_as_gpr: bool = False,
        rewrite_tmps: bool = False,
    ):
        super().__init__(project)

        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.def_to_vvid: dict[tuple[int, int | None, int, Expression | Statement], int] = {}
        self.stackvar_locs = stackvar_locs
        self.udef_to_phiid = udef_to_phiid
        self.phiid_to_loc = phiid_to_loc
        self.rewrite_tmps = rewrite_tmps
        self.ail_manager = ail_manager

        self._current_vvar_id = vvar_id_start

    @property
    def current_vvar_id(self) -> int:
        return self._current_vvar_id

    def next_vvar_id(self) -> int:
        self._current_vvar_id += 1
        return self._current_vvar_id

    #
    # Handlers
    #

    def _top(self, bits):
        assert False, "Unreachable"

    def _is_top(self, expr):
        assert False, "Unreachable"

    def _process_block_end(self, block, stmt_data, whitelist):
        assert whitelist is None
        for stmt_idx, new_stmt in enumerate(stmt_data):
            if new_stmt is not None:
                if isinstance(new_stmt, tuple):
                    for stmt_ in new_stmt:
                        self.state.append_statement(stmt_)
                else:
                    self.state.append_statement(new_stmt)
            else:
                self.state.append_statement(block.statements[stmt_idx])

    def _handle_stmt_Assignment(self, stmt):
        new_src = self._expr(stmt.src)

        if isinstance(stmt.dst, VirtualVariable):
            if stmt.dst.category == VirtualVariableCategory.REGISTER:
                self.state.registers[stmt.dst.reg_offset][stmt.dst.size] = stmt.dst
            elif stmt.dst.category == VirtualVariableCategory.STACK:
                self.state.stackvars[stmt.dst.stack_offset][stmt.dst.size] = stmt.dst
            elif stmt.dst.category == VirtualVariableCategory.TMP:
                self.state.tmps[stmt.dst.tmp_idx] = stmt.dst
            new_dst = None
        else:
            new_dst = self._replace_def_expr(self.block.addr, self.block.idx, self.stmt_idx, stmt.dst)

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
                    base_reg_vvar = self._replace_def_expr(
                        self.block.addr, self.block.idx, self.stmt_idx, base_reg_expr
                    )
                    stmt_base_reg = Assignment(
                        self.ail_manager.next_atom(),
                        base_reg_vvar,
                        self._reg_update_expr(
                            existing_base_reg_vvar, base_offset, base_size, new_dst, stmt.dst.reg_offset, stmt.dst.size
                        ),
                        **stmt.tags,
                    )
                    self.state.registers[base_offset][base_size] = base_reg_vvar
            elif isinstance(stmt.dst, Tmp):
                pass
            else:
                raise NotImplementedError

        if new_dst is not None or new_src is not None:
            new_stmt = Assignment(
                stmt.idx,
                stmt.dst if new_dst is None else new_dst,
                stmt.src if new_src is None else new_src,
                **stmt.tags,
            )
            if stmt_base_reg is not None:
                return new_stmt, stmt_base_reg
            return new_stmt
        return None

    def _handle_stmt_Store(self, stmt: Store) -> Store | Assignment | None:
        new_data = self._expr(stmt.data)
        if stmt.guard is None:
            vvar = self._replace_def_store(self.block.addr, self.block.idx, self.stmt_idx, stmt)
            if vvar is not None:
                return Assignment(stmt.idx, vvar, stmt.data if new_data is None else new_data, **stmt.tags)

        # fall back to Store
        new_addr = self._expr(stmt.addr)
        new_guard = self._expr(stmt.guard) if stmt.guard is not None else None

        if new_addr is not None or new_data is not None or new_guard is not None:
            return Store(
                stmt.idx,
                stmt.addr if new_addr is None else new_addr,
                stmt.data if new_data is None else new_data,
                stmt.size,
                stmt.endness,
                guard=stmt.guard if new_guard is None else new_guard,
                **stmt.tags,
            )

        return None

    def _handle_stmt_ConditionalJump(self, stmt: ConditionalJump) -> ConditionalJump | None:
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

    def _handle_stmt_Call(self, stmt: Call) -> Call | None:
        changed = False

        new_target = self._replace_use_expr(stmt.target)
        new_ret_expr = (
            self._replace_def_expr(self.block.addr, self.block.idx, self.stmt_idx, stmt.ret_expr)
            if stmt.ret_expr is not None
            else None
        )
        new_fp_ret_expr = (
            self._replace_def_expr(self.block.addr, self.block.idx, self.stmt_idx, stmt.fp_ret_expr)
            if stmt.fp_ret_expr is not None
            else None
        )

        cc = stmt.calling_convention if stmt.calling_convention is not None else self.project.factory.cc()
        if cc is not None:
            # clean up all caller-saved registers (and their subregisters)
            for reg_name in cc.CALLER_SAVED_REGS:
                base_off, base_size = self.arch.registers[reg_name]
                self._clear_aliasing_regs(base_off, base_size)
                self.state.registers[base_off][base_size] = None

        if new_ret_expr is not None and isinstance(stmt.ret_expr, Register):
            base_off, base_size = get_reg_offset_base_and_size(
                stmt.ret_expr.reg_offset, self.arch, size=stmt.ret_expr.size
            )
            self._clear_aliasing_regs(base_off, base_size)
            self.state.registers[base_off][base_size] = new_ret_expr
        if new_fp_ret_expr is not None and isinstance(stmt.fp_ret_expr, Register):
            self._clear_aliasing_regs(stmt.fp_ret_expr.reg_offset, stmt.fp_ret_expr.size)
            self.state.registers[stmt.fp_ret_expr.reg_offset][stmt.fp_ret_expr.size] = new_fp_ret_expr

        new_args = None
        if stmt.args is not None:
            new_args = []
            for arg in stmt.args:
                new_arg = self._expr(arg)
                if new_arg is not None:
                    changed = True
                    new_args.append(new_arg)
                else:
                    new_args.append(arg)

        if new_target is not None or new_ret_expr is not None or new_fp_ret_expr is not None:
            changed = True

        if changed:
            return Call(
                stmt.idx,
                stmt.target if new_target is None else new_target,
                calling_convention=stmt.calling_convention,
                prototype=stmt.prototype,
                args=new_args,
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

    def _handle_expr_Register(self, expr: Register) -> VirtualVariable | None:
        return self._replace_use_reg(expr)

    def _handle_expr_Tmp(self, expr: Tmp) -> VirtualVariable | None:
        return (
            self._replace_use_tmp(self.block.addr, self.block.idx, self.stmt_idx, expr) if self.rewrite_tmps else None
        )

    def _handle_expr_Load(self, expr: Load) -> Load | VirtualVariable | None:
        if isinstance(expr.addr, StackBaseOffset) and isinstance(expr.addr.offset, int):
            new_expr = self._replace_use_load(expr)
            if new_expr is not None:
                return new_expr

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

    def _handle_stmt_Return(self, stmt: Return) -> Return | None:
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

    def _handle_expr_BinaryOp(self, expr: BinaryOp) -> BinaryOp | None:
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

    def _handle_expr_UnaryOp(self, expr) -> UnaryOp | None:
        new_op = self._expr(expr.operand)
        if new_op is not None:
            return UnaryOp(
                expr.idx,
                expr.op,
                new_op,
                bits=expr.bits,
                **expr.tags,
            )
        return None

    def _handle_expr_ITE(self, expr: ITE) -> ITE | None:
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

    def _handle_expr_VEXCCallExpression(self, expr: VEXCCallExpression) -> VEXCCallExpression | None:
        updated = False
        new_operands = []
        for operand in expr.operands:
            new_operand = self._expr(operand)
            if new_operand is not None:
                updated = True
                new_operands.append(new_operand)
            else:
                new_operands.append(operand)

        if updated:
            return VEXCCallExpression(expr.idx, expr.callee, tuple(new_operands), bits=expr.bits, **expr.tags)
        return None

    def _handle_expr_BasePointerOffset(self, expr):
        return None

    def _handle_expr_Call(self, expr):
        return self._handle_stmt_Call(expr)

    def _handle_expr_Const(self, expr):
        return None

    def _handle_expr_DirtyExpression(self, expr: DirtyExpression) -> DirtyExpression | None:
        updated = False
        new_operands = []
        for operand in expr.operands:
            new_operand = self._expr(operand)
            if new_operand is not None:
                updated = True
                new_operands.append(new_operand)
            else:
                new_operands.append(operand)

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

    def _handle_expr_MultiStatementExpression(self, expr):
        return None

    def _handle_expr_Phi(self, expr):
        return None

    def _handle_expr_Reinterpret(self, expr):
        return None

    def _handle_expr_StackBaseOffset(self, expr):
        return None

    def _handle_expr_VirtualVariable(self, expr):
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
        base_mask = Const(self.ail_manager.next_atom(), None, base_mask, existing_vvar.bits)
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
                bits=extended_vvar.bits,
                **extended_vvar.tags,
            )
        else:
            shifted_vvar = extended_vvar
        assert new_base_expr.bits == shifted_vvar.bits
        return BinaryOp(
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

    def _replace_def_expr(
        self, block_addr: int, block_idx: int | None, stmt_idx: int, thing: Expression | Statement
    ) -> VirtualVariable | None:
        """
        Return a new virtual variable for the given defined expression.
        """
        if isinstance(thing, Register):
            return self._replace_def_reg(block_addr, block_idx, stmt_idx, thing)
        if isinstance(thing, Store):
            return self._replace_def_store(block_addr, block_idx, stmt_idx, thing)
        if isinstance(thing, Tmp) and self.rewrite_tmps:
            return self._replace_def_tmp(block_addr, block_idx, stmt_idx, thing)
        return None

    def _replace_def_reg(
        self, block_addr: int, block_idx: int | None, stmt_idx: int, expr: Register
    ) -> VirtualVariable:
        """
        Return a new virtual variable for the given defined register.
        """

        # get the virtual variable ID
        vvid = self.get_vvid_by_def(block_addr, block_idx, stmt_idx, expr)
        return VirtualVariable(
            expr.idx,
            vvid,
            expr.bits,
            VirtualVariableCategory.REGISTER,
            oident=expr.reg_offset,
            **expr.tags,
        )

    def _get_full_reg_vvar(self, reg_offset: int, size: int, ins_addr: int | None = None) -> VirtualVariable:
        base_off, base_size = get_reg_offset_base_and_size(reg_offset, self.arch, size=size)
        if (
            base_off not in self.state.registers
            or base_size not in self.state.registers[base_off]
            or self.state.registers[base_off][base_size] is None
        ):
            # somehow it's never defined before...
            _l.debug("Creating a new virtual variable for an undefined register (%d [%d]).", base_off, base_size)
            tags = {}
            if ins_addr is not None:
                tags["ins_addr"] = ins_addr
            vvar = VirtualVariable(
                self.ail_manager.next_atom(),
                self.next_vvar_id(),
                base_size * self.arch.byte_width,
                category=VirtualVariableCategory.REGISTER,
                oident=base_off,
                **tags,
            )
            self.state.registers[base_off][base_size] = vvar
            return vvar
        return self.state.registers[base_off][base_size]

    def _replace_def_store(
        self, block_addr: int, block_idx: int | None, stmt_idx: int, stmt: Store
    ) -> VirtualVariable | None:
        if (
            isinstance(stmt.addr, StackBaseOffset)
            and isinstance(stmt.addr.offset, int)
            and stmt.addr.offset in self.stackvar_locs
            and stmt.size == self.stackvar_locs[stmt.addr.offset]
        ):
            vvar_id = self.get_vvid_by_def(block_addr, block_idx, stmt_idx, stmt)
            vvar = VirtualVariable(
                self.ail_manager.next_atom(),
                vvar_id,
                stmt.size * self.arch.byte_width,
                category=VirtualVariableCategory.STACK,
                oident=stmt.addr.offset,
                **stmt.tags,
            )
            self.state.stackvars[stmt.addr.offset][stmt.size] = vvar
            return vvar
        return None

    def _replace_def_tmp(self, block_addr: int, block_idx: int | None, stmt_idx: int, expr: Tmp) -> VirtualVariable:
        vvid = self.get_vvid_by_def(block_addr, block_idx, stmt_idx, expr)
        vvar = VirtualVariable(
            expr.idx,
            vvid,
            expr.bits,
            VirtualVariableCategory.TMP,
            oident=expr.tmp_idx,
            **expr.tags,
        )
        self.state.tmps[expr.tmp_idx] = vvar
        return vvar

    def _replace_use_expr(self, thing: Expression | Statement) -> VirtualVariable | None:
        """
        Return a new virtual variable for the given defined expression.
        """
        if isinstance(thing, Register):
            return self._replace_use_reg(thing)
        if isinstance(thing, Store):
            raise NotImplementedError("Store expressions are not supported in _replace_use_expr.")
        if isinstance(thing, Tmp) and self.rewrite_tmps:
            return self._replace_use_tmp(self.block.addr, self.block.idx, self.stmt_idx, thing)
        return None

    def _replace_use_reg(self, reg_expr: Register) -> VirtualVariable | Expression:

        if reg_expr.reg_offset in self.state.registers:
            if (
                reg_expr.size in self.state.registers[reg_expr.reg_offset]
                and self.state.registers[reg_expr.reg_offset][reg_expr.size] is not None
            ):
                vvar = self.state.registers[reg_expr.reg_offset][reg_expr.size]
                assert vvar is not None
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
                    if vvar is not None:
                        # extract it
                        return Convert(
                            self.ail_manager.next_atom(),
                            vvar.bits,
                            reg_expr.bits,
                            False,
                            vvar,
                            **reg_expr.tags,
                        )
                else:
                    break

        # no good size available
        # get the full register, then extract from there
        vvar = self._get_full_reg_vvar(
            reg_expr.reg_offset,
            reg_expr.size,
            ins_addr=reg_expr.ins_addr,
        )
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
        return Convert(
            self.ail_manager.next_atom(),
            shifted.bits,
            reg_expr.bits,
            False,
            shifted,
            **reg_expr.tags,
        )

    def _replace_use_load(self, expr: Load) -> VirtualVariable | None:
        if (
            isinstance(expr.addr, StackBaseOffset)
            and isinstance(expr.addr.offset, int)
            and expr.addr.offset in self.stackvar_locs
            and expr.size == self.stackvar_locs[expr.addr.offset]
        ):
            if expr.size not in self.state.stackvars[expr.addr.offset]:
                # create it on the fly
                vvar_id = self.get_vvid_by_def(self.block.addr, self.block.idx, self.stmt_idx, expr)
                return VirtualVariable(
                    self.ail_manager.next_atom(),
                    vvar_id,
                    expr.size * self.arch.byte_width,
                    category=VirtualVariableCategory.STACK,
                    oident=expr.addr.offset,
                    **expr.tags,
                )

            # TODO: Support truncation
            # TODO: Maybe also support concatenation
            vvar = self.state.stackvars[expr.addr.offset][expr.size]
            return VirtualVariable(
                expr.idx,
                vvar.varid,
                vvar.bits,
                VirtualVariableCategory.STACK,
                oident=vvar.stack_offset,
                **vvar.tags,
            )
        return None

    def _replace_use_tmp(self, block_addr: int, block_idx: int | None, stmt_idx: int, expr: Tmp) -> VirtualVariable:
        vvar = self.state.tmps.get(expr.tmp_idx)
        if vvar is None:
            return self._replace_def_tmp(block_addr, block_idx, stmt_idx, expr)
        return VirtualVariable(
            expr.idx,
            vvar.varid,
            vvar.bits,
            VirtualVariableCategory.TMP,
            oident=expr.tmp_idx,
            **expr.tags,
        )

    #
    # Utils
    #

    def get_vvid_by_def(
        self, block_addr: int, block_idx: int | None, stmt_idx: int, thing: Expression | Statement
    ) -> int:
        key = block_addr, block_idx, stmt_idx, thing
        if key in self.def_to_vvid:
            return self.def_to_vvid[key]
        vvid = self.next_vvar_id()
        self.def_to_vvid[key] = vvid
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
