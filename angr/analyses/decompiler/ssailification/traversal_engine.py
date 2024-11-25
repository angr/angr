from __future__ import annotations
from collections import OrderedDict

from ailment.statement import Assignment, Call, Store, ConditionalJump
from ailment.expression import Register, BinaryOp, StackBaseOffset, ITE, VEXCCallExpression, Tmp, DirtyExpression

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin
from angr.utils.ssa import get_reg_offset_base
from angr.utils.orderedset import OrderedSet
from angr.calling_conventions import default_cc
from .traversal_state import TraversalState


class SimEngineSSATraversal(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine collects all register and stack variable locations and links them to the block of their creation.
    """

    state: TraversalState

    def __init__(
        self,
        arch,
        simos,
        sp_tracker=None,
        bp_as_gpr: bool = False,
        def_to_loc=None,
        loc_to_defs=None,
        stackvars: bool = False,
        tmps: bool = False,
    ):
        super().__init__()

        self.arch = arch
        self.simos = simos
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.stackvars = stackvars
        self.tmps = tmps

        self.def_to_loc = def_to_loc if def_to_loc is not None else []
        self.loc_to_defs = loc_to_defs if loc_to_defs is not None else OrderedDict()

    def _handle_Assignment(self, stmt: Assignment):
        if isinstance(stmt.dst, Register):
            codeloc = self._codeloc()
            self.def_to_loc.append((stmt.dst, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.dst)

            base_off = get_reg_offset_base(stmt.dst.reg_offset, self.arch)
            self.state.live_registers.add(base_off)

        self._expr(stmt.src)

    def _handle_Store(self, stmt: Store):
        self._expr(stmt.addr)
        self._expr(stmt.data)
        if stmt.guard is not None:
            self._expr(stmt.guard)

        if self.stackvars and isinstance(stmt.addr, StackBaseOffset) and isinstance(stmt.addr.offset, int):
            codeloc = self._codeloc()
            self.def_to_loc.append((stmt, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt)

            self.state.live_stackvars.add((stmt.addr.offset, stmt.size))

    def _handle_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
        if stmt.true_target is not None:
            self._expr(stmt.true_target)
        if stmt.false_target is not None:
            self._expr(stmt.false_target)

    def _handle_Call(self, stmt: Call):

        # kill caller-saved registers
        cc = (
            default_cc(self.arch.name, platform=self.simos.name if self.simos is not None else None)
            if stmt.calling_convention is None
            else stmt.calling_convention
        )
        for reg_name in cc.CALLER_SAVED_REGS:
            reg_offset = self.arch.registers[reg_name][0]
            base_off = get_reg_offset_base(reg_offset, self.arch)
            self.state.live_registers.discard(base_off)

        if stmt.ret_expr is not None and isinstance(stmt.ret_expr, Register):
            codeloc = self._codeloc()
            self.def_to_loc.append((stmt.ret_expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.ret_expr)

            base_off = get_reg_offset_base(stmt.ret_expr.reg_offset, self.arch)
            self.state.live_registers.add(base_off)

        super()._ail_handle_Call(stmt)

    _handle_CallExpr = _handle_Call

    def _handle_Register(self, expr: Register):
        base_offset = get_reg_offset_base(expr.reg_offset, self.arch)

        if base_offset not in self.state.live_registers:
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)

            self.state.live_registers.add(base_offset)

    def _handle_Tmp(self, expr: Tmp):
        if self.tmps:
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)

            self.state.live_tmps.add(expr.tmp_idx)

    def _handle_Cmp(self, expr: BinaryOp):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    _handle_CmpLE = _handle_Cmp
    _handle_CmpLT = _handle_Cmp
    _handle_CmpGE = _handle_Cmp
    _handle_CmpGT = _handle_Cmp
    _handle_CmpEQ = _handle_Cmp
    _handle_CmpNE = _handle_Cmp

    def _handle_UnaryOp(self, expr):
        self._expr(expr.operand)

    def _handle_BinaryOp(self, expr):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    def _handle_TernaryOp(self, expr):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])
        self._expr(expr.operands[2])

    def _handle_ITE(self, expr: ITE):
        self._expr(expr.cond)
        self._expr(expr.iftrue)
        self._expr(expr.iffalse)

    def _handle_VEXCCallExpression(self, expr: VEXCCallExpression):
        for operand in expr.operands:
            self._expr(operand)

    def _handle_DirtyExpression(self, expr: DirtyExpression):
        for operand in expr.operands:
            self._expr(operand)
        if expr.guard is not None:
            self._expr(expr.guard)
        if expr.maddr is not None:
            self._expr(expr.maddr)

    def _handle_Dummy(self, expr):
        pass

    _handle_VirtualVariable = _handle_Dummy
    _handle_Phi = _handle_Dummy
