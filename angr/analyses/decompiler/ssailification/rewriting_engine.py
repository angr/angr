# pylint:disable=no-self-use,unused-argument,too-many-boolean-expressions
from __future__ import annotations
from typing import TYPE_CHECKING
from collections.abc import MutableMapping
import logging

import archinfo

from angr.ailment.block import Block
from angr.ailment.manager import Manager
from angr.ailment.statement import (
    Statement,
    Assignment,
    CAS,
    Store,
    SideEffectStatement,
    Return,
    ConditionalJump,
    DirtyStatement,
    Jump,
    WeakAssignment,
)
from angr.ailment.expression import (
    Atom,
    Call,
    Expression,
    Extract,
    Insert,
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
    Reinterpret,
)

from angr.ailment.tagged_object import TaggedObject
from angr.engines.light.engine import SimEngineNostmtAIL
from .rewriting_state import RewritingState
from .consts import MAX_STACK_VAR_SIZE

if TYPE_CHECKING:
    from angr.analyses.decompiler.ssailification.ssailification import Def, UDef


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
        ail_manager: Manager,
        def_to_udef: MutableMapping[Def, UDef],
        incomplete_defs: set[Def],
        vvar_id_start: int = 0,
        rewrite_tmps: bool = False,
        stackvars: bool = False,
        fail_fast: bool = False,
    ):
        super().__init__(project)

        self.def_to_vvid_cache: dict[Def, int] = {}
        self.tmp_to_vvid_cache: dict[tuple[int, int | None, int], int] = {}
        self.rewrite_tmps = rewrite_tmps
        self.ail_manager = ail_manager
        self.hclb_side_exit_state: RewritingState | None = None
        self.out_block: Block | None = None
        self.def_to_udef = def_to_udef
        self.stackvars = stackvars
        self.incomplete_defs = incomplete_defs
        self._fail_fast = fail_fast

        self._current_vvar_id = vvar_id_start
        self._extra_defs: list[int] = []

    @property
    def current_vvar_id(self) -> int:
        return self._current_vvar_id

    #
    # Util functions
    #

    @staticmethod
    def _is_head_controlled_loop_jump(block, jump_stmt: ConditionalJump) -> bool:
        concrete_targets = []
        if isinstance(jump_stmt.true_target, Const):
            concrete_targets.append(jump_stmt.true_target.value)
        if isinstance(jump_stmt.false_target, Const):
            concrete_targets.append(jump_stmt.false_target.value)
        return not all(block.addr <= t < block.addr + block.original_size for t in concrete_targets)

    #
    # Handlers
    #

    def process(
        self, state: RewritingState, *, block: Block | None = None, whitelist: set[int] | None = None, **kwargs
    ) -> None:
        super().process(state, block=block, whitelist=whitelist, **kwargs)

    def _top(self, bits):
        assert False, "Unreachable"

    def _is_top(self, expr):
        assert False, "Unreachable"

    def _process_block_end(self, block, stmt_data, whitelist):
        assert whitelist is None
        if all(stmt is None for stmt in stmt_data):
            self.out_block = block
            return

        self.out_block = Block(block.addr, block.original_size, idx=block.idx)
        for stmt_idx, new_stmt in enumerate(stmt_data):
            if new_stmt is not None:
                if isinstance(new_stmt, tuple):
                    for stmt_ in new_stmt:
                        self.out_block.statements.append(stmt_)
                else:
                    self.out_block.statements.append(new_stmt)
            else:
                self.out_block.statements.append(block.statements[stmt_idx])

    def _stmt(self, stmt: Statement):
        self._extra_defs = []
        result = super()._stmt(stmt)
        for rstmt in result if isinstance(result, tuple) else [result] if isinstance(result, Statement) else []:
            if self._extra_defs:
                rstmt.tags["extra_defs"] = self._extra_defs
            else:
                rstmt.tags.pop("extra_defs", None)

        return result

    def _handle_expr_VirtualVariable(self, expr):
        return None

    def _handle_stmt_Assignment(self, stmt):
        new_src = self._expr(stmt.src)
        new_dst = self._replace_def_expr(stmt.dst, new_src or stmt.src, stmt)
        if new_dst is not None:
            return new_dst

        if new_src is not None:
            return Assignment(
                stmt.idx,
                stmt.dst,
                new_src,
                **stmt.tags,
            )
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

    def _handle_stmt_Store(self, stmt: Store) -> Store | Assignment | tuple[Assignment, ...] | None:
        new_data = self._expr(stmt.data)
        if self.stackvars and stmt.guard is None and isinstance(stmt.addr, StackBaseOffset):
            # vvar assignment
            vvar = self._expr_to_vvar(stmt.addr, False)
            assert isinstance(stmt.addr.offset, int)
            return self._vvar_update(vvar, stmt.addr.offset - vvar.stack_offset, new_data or stmt.data, stmt)

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

    def _handle_stmt_Jump(self, stmt: Jump) -> Jump | None:
        new_target = self._expr(stmt.target)
        if new_target is not None:
            return Jump(stmt.idx, new_target, stmt.target_idx, **stmt.tags)
        return None

    def _handle_stmt_ConditionalJump(self, stmt: ConditionalJump) -> ConditionalJump | None:
        new_cond = self._expr(stmt.condition)
        new_true_target = self._expr(stmt.true_target) if stmt.true_target is not None else None
        new_false_target = self._expr(stmt.false_target) if stmt.false_target is not None else None

        if self.stmt_idx != len(self.block.statements) - 1 and self._is_head_controlled_loop_jump(self.block, stmt):
            # the conditional jump is in the middle of the block (e.g., the block generated from lifting rep stosq).
            # we need to make a copy of the state and use the state of this point in its successor
            self.hclb_side_exit_state = self.state.copy()

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

    def _handle_stmt_SideEffectStatement(self, stmt: SideEffectStatement) -> Statement:
        new_args = None
        if stmt.expr.args is not None:
            new_args = []
            for arg in stmt.expr.args:
                new_arg = self._expr(arg)
                if new_arg is not None:
                    new_args.append(new_arg)
                else:
                    new_args.append(arg)

        new_target = self._expr(stmt.expr.target) if not isinstance(stmt.expr.target, str) else None
        replaced_call = Call(
            stmt.idx,
            stmt.expr.target if new_target is None else new_target,
            calling_convention=stmt.expr.calling_convention,
            prototype=stmt.expr.prototype,
            args=new_args,
            bits=stmt.bits,
            **stmt.tags,
        )

        cc = stmt.expr.calling_convention if stmt.expr.calling_convention is not None else self.project.factory.cc()
        if cc is not None:
            # clean up all caller-saved registers (and their subregisters)
            for reg_name in cc.CALLER_SAVED_REGS:
                base_off, base_size = self.arch.registers[reg_name]
                for suboff in range(base_off, base_off + base_size):
                    self.state.registers.pop(suboff, None)

        new_stmt = None
        if stmt.ret_expr is not None:
            assert isinstance(stmt.ret_expr, Atom)
            new_stmt = self._replace_def_expr(stmt.ret_expr, replaced_call, stmt)
        elif stmt.fp_ret_expr is not None:
            assert isinstance(stmt.fp_ret_expr, Atom)
            new_stmt = self._replace_def_expr(stmt.fp_ret_expr, replaced_call, stmt)
        if new_stmt is None:
            new_stmt = SideEffectStatement(stmt.idx, replaced_call, **stmt.tags)

        return new_stmt

    def _handle_stmt_DirtyStatement(self, stmt: DirtyStatement) -> DirtyStatement | None:
        dirty = self._expr(stmt.dirty)
        if dirty is None or dirty is stmt.dirty:
            return None
        assert isinstance(dirty, DirtyExpression)
        return DirtyStatement(stmt.idx, dirty, **stmt.tags)

    def _handle_expr_Register(self, expr: Register) -> VirtualVariable | Expression | None:
        vvar = self._expr_to_vvar(expr, True)
        return self._vvar_extract(vvar, expr.size, expr.reg_offset - vvar.reg_offset, expr)

    def _handle_expr_Tmp(self, expr: Tmp) -> VirtualVariable | None:
        if not self.rewrite_tmps:
            return None
        tmp_key = self.block.addr, self.block.idx, expr.tmp_idx
        if (vvid := self.tmp_to_vvid_cache.get(tmp_key, None)) is None:
            vvid = self.tmp_to_vvid_cache[tmp_key] = self._current_vvar_id
            self._current_vvar_id += 1
        return VirtualVariable(
            expr.idx,
            vvid,
            expr.bits,
            VirtualVariableCategory.TMP,
            oident=expr.tmp_idx,
            **(expr.tags | {"ins_addr": self.ins_addr}),
        )

    def _handle_expr_Load(self, expr: Load) -> Expression | None:
        if self.stackvars and isinstance(expr.addr, StackBaseOffset):
            # vvar assignment
            vvar = self._expr_to_vvar(expr.addr, True)
            assert isinstance(expr.addr.offset, int)
            if vvar.stack_offset + vvar.size >= expr.addr.offset + expr.size:
                return self._vvar_extract(vvar, expr.size, expr.addr.offset - vvar.stack_offset, expr)

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
            return None

        updated = False
        new_ret_exprs = []
        for r in stmt.ret_exprs:
            new_r = self._expr(r)
            if new_r is not None:
                updated = True
                new_ret_exprs.append(new_r)
            else:
                new_ret_exprs.append(r)

        if not updated:
            return None
        return Return(stmt.idx, new_ret_exprs, **stmt.tags)

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
                expr.iffalse if new_iffalse is None else new_iffalse,
                expr.iftrue if new_iftrue is None else new_iftrue,
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
        new_args = None
        if expr.args is not None:
            new_args = []
            for arg in expr.args:
                new_arg = self._expr(arg)
                if new_arg is not None:
                    new_args.append(new_arg)
                else:
                    new_args.append(arg)

        new_target = self._expr(expr.target) if not isinstance(expr.target, str) else None
        if new_target is not None or new_args is not None:
            return Call(
                expr.idx,
                expr.target if new_target is None else new_target,
                calling_convention=expr.calling_convention,
                prototype=expr.prototype,
                args=new_args if new_args is not None else expr.args,
                bits=expr.bits,
                **expr.tags,
            )
        return None

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

    def _handle_expr_StackBaseOffset(self, expr):
        if not self.stackvars:
            return None

        # if we get here, it means it's NOT through a Load or Store
        # so we won't get the opportunity to lift this into an appropriate Assignment
        # so if we don't completely redefine the value we should not create a new vvar
        if expr in self.incomplete_defs and expr.offset in self.state.stackvars:
            self.def_to_udef.pop(expr, None)

        vvar = self._expr_to_vvar(expr, True)
        refers = UnaryOp(expr.idx, "Reference", vvar, bits=expr.bits, **expr.tags)
        if expr in self.def_to_udef:
            refers.tags["extra_def"] = True
            self._extra_defs.append(vvar.varid)
        if vvar.stack_offset == expr.offset:
            return refers

        return BinaryOp(expr.idx, "Add", [refers, Const(None, None, vvar.stack_offset - expr.offset, refers.bits)])

    def _handle_expr_Extract(self, expr: Extract):
        base = self._expr(expr.base) or expr.base
        offset = self._expr(expr.offset) or expr.offset

        if base is not expr.base or offset is not expr.offset:
            return Extract(expr.idx, expr.bits, base, offset, expr.endness, **expr.tags)
        return None

    def _handle_expr_Insert(self, expr: Insert):
        base = self._expr(expr.base) or expr.base
        offset = self._expr(expr.offset) or expr.offset
        value = self._expr(expr.value) or expr.value

        if base is not expr.base or offset is not expr.offset or value is not expr.value:
            return Insert(expr.idx, base, offset, value, expr.endness, **expr.tags)
        return None

    #
    # Expression replacement
    #

    def _replace_def_expr(self, thing: Atom, value: Expression, orig_tags: TaggedObject) -> Assignment | None:
        """
        Return a new virtual variable for the given defined expression.
        """
        if isinstance(thing, Register):
            return self._replace_def_reg(thing, value, orig_tags)
        if isinstance(thing, Tmp) and self.rewrite_tmps:
            return self._replace_def_tmp(thing, value, orig_tags)
        if isinstance(thing, VirtualVariable):
            # update liveness info
            if thing.category == VirtualVariableCategory.REGISTER:
                for suboff in range(thing.reg_offset, thing.reg_offset + thing.size):
                    self.state.registers[suboff] = thing
            elif thing.category == VirtualVariableCategory.STACK:
                for suboff in range(thing.stack_offset, thing.stack_offset + thing.size):
                    self.state.stackvars[suboff] = thing
        return None

    def _replace_def_reg(self, expr: Register, value: Expression, orig_tags: TaggedObject) -> Assignment:
        """
        Return a new virtual variable for the given defined register.
        """
        vvar = self._expr_to_vvar(expr, False)
        return self._vvar_update(vvar, expr.reg_offset - vvar.reg_offset, value, orig_tags)

    def _replace_def_tmp(self, expr: Tmp, value: Expression, orig_tags: TaggedObject) -> Assignment:
        if not self.rewrite_tmps:
            return Assignment(orig_tags.idx, expr, value, **orig_tags.tags)
        vvar = self._handle_expr_Tmp(expr)
        assert vvar is not None
        return self._vvar_update(vvar, 0, value, orig_tags)

    #
    # Utils
    #

    def _expr_to_vvar(self, expr: Def, def_is_implicit: bool) -> VirtualVariable:
        # is this a use, not a def?
        if (udef := self.def_to_udef.get(expr, None)) is None:
            # in case of emergency, raise keyerror
            if isinstance(expr, StackBaseOffset):
                assert isinstance(expr.offset, int)
                if self._fail_fast or expr.offset in self.state.stackvars:
                    return self.state.stackvars[expr.offset]
            elif isinstance(expr, Register):
                if self._fail_fast or expr.reg_offset in self.state.registers:
                    return self.state.registers[expr.reg_offset]
            else:
                raise TypeError(expr)

            # we got here because expr refers to a non-existent stack offset or register offset.
            # raise a KeyError if fail_fast is specified because something else has gone wrong at this point.
            if self._fail_fast:
                raise KeyError(expr)
            # otherwise, we try our best to guesstimate the udef here
            kind = "stack" if isinstance(expr, StackBaseOffset) else "reg"
            offset = expr.offset if isinstance(expr, StackBaseOffset) else expr.reg_offset
            if kind == "stack":
                next_off = min((o for o in self.state.stackvars if o >= offset), default=offset + 4)
            else:
                # kind == "reg"
                next_off = min((o for o in self.state.registers if o >= offset), default=offset + 4)
            size = next_off - offset
        else:
            # unpack udef
            kind, offset, size = udef

        if (varid := self.def_to_vvid_cache.get(expr, None)) is None:
            varid = self.def_to_vvid_cache[expr] = self._current_vvar_id
            self._current_vvar_id += 1
        idx = self.ail_manager.next_atom()
        # TODO replace these str kinds with VirtualVariableCategory I guess
        if kind == "stack":
            category = VirtualVariableCategory.STACK
            oident = offset
        elif kind == "reg":
            category = VirtualVariableCategory.REGISTER
            oident = offset
        else:
            raise TypeError(expr)

        if kind == "stack" and size >= MAX_STACK_VAR_SIZE:
            # limit the stack variable size
            size = MAX_STACK_VAR_SIZE

        vvar = VirtualVariable(idx, varid, size * 8, category, oident, **(expr.tags | {"ins_addr": self.ins_addr}))
        if def_is_implicit:
            if kind == "stack":
                for suboff in range(offset, offset + size):
                    self.state.stackvars[suboff] = vvar
            elif kind == "reg":
                for suboff in range(offset, offset + size):
                    self.state.registers[suboff] = vvar
        return vvar

    def _vvar_extract(
        self, vvar: VirtualVariable, size: int, offset: int, orig_tags: TaggedObject
    ) -> Extract | VirtualVariable | BinaryOp:
        assert offset >= 0
        if size == vvar.size:
            return vvar
        endness = (
            self.project.arch.memory_endness
            if vvar.was_stack or (vvar.was_parameter and vvar.parameter_category == VirtualVariableCategory.STACK)
            else self.project.arch.register_endness
        )
        if size > vvar.size:
            if self._fail_fast:
                assert False, "Invariant failure: we generated a vvar which is smaller than one of its uses"
            remainder = Const(None, None, 0, size * 8 - vvar.bits, uninitalized=True)
            order = [vvar, remainder] if endness == archinfo.Endness.LE else [remainder, vvar]
            return BinaryOp(
                self.ail_manager.next_atom(),
                "Concat",
                order,
                bits=size * 8,
            )
        return Extract(
            self.ail_manager.next_atom(), size * 8, vvar, Const(None, None, offset, 64), endness, **orig_tags.tags
        )

    def _vvar_update(
        self, vvar: VirtualVariable, offset: int, value: Expression, orig_tags: TaggedObject
    ) -> Assignment:
        assert offset >= 0
        if value.bits == vvar.bits:
            combined = value
        else:
            if vvar.category == VirtualVariableCategory.STACK:
                base = self.state.stackvars.get(vvar.stack_offset, None)
            elif vvar.category == VirtualVariableCategory.REGISTER:
                base = self.state.registers.get(vvar.reg_offset, None)
            else:
                raise TypeError(vvar.category)
            if base is None:
                base = Const(None, None, 0, vvar.bits, uninitialized=True)
            if base.bits < vvar.bits:
                base = BinaryOp(
                    self.ail_manager.next_atom(),
                    "Concat",
                    [base, Const(None, None, 0, vvar.bits - base.bits, uninitialized=True)],
                    bits=vvar.bits,
                )
            endness = (
                self.project.arch.memory_endness
                if vvar.was_stack or (vvar.was_parameter and vvar.parameter_category == VirtualVariableCategory.STACK)
                else self.project.arch.register_endness
            )
            combined = Insert(self.ail_manager.next_atom(), base, Const(None, None, offset, 64), value, endness)
            if combined.bits > vvar.bits:
                combined = Extract(
                    self.ail_manager.next_atom(), vvar.bits, combined, Const(None, None, offset, 64), endness
                )

        if vvar.category == VirtualVariableCategory.STACK:
            for suboff in range(vvar.stack_offset, vvar.stack_offset + vvar.size):
                self.state.stackvars[suboff] = vvar
        elif vvar.category == VirtualVariableCategory.REGISTER:
            for suboff in range(vvar.reg_offset, vvar.reg_offset + vvar.size):
                self.state.registers[suboff] = vvar
        return Assignment(self.ail_manager.next_atom(), vvar, combined, **orig_tags.tags)

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
    _handle_binop_CmpORD = _unreachable
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
