from __future__ import annotations
from collections import OrderedDict
from claripy.utils.orderedset import OrderedSet

from ailment.statement import Assignment, Call, Store, ConditionalJump
from ailment.expression import Register, BinaryOp

from angr.engines.light import SimEngineLight, SimEngineLightAILMixin
from angr.utils.ssa import get_reg_offset_base
from .traversal_state import TraversalState


class SimEngineSSATraversal(
    SimEngineLightAILMixin,
    SimEngineLight,
):
    """
    This engine collects all register and stack variable locations and links them to the block of their creation.
    """

    state: TraversalState

    def __init__(self, arch, sp_tracker=None, bp_as_gpr: bool = False, def_to_loc=None, loc_to_defs=None):
        super().__init__()

        self.arch = arch
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr

        self.def_to_loc = def_to_loc if def_to_loc is not None else OrderedDict()
        self.loc_to_defs = loc_to_defs if loc_to_defs is not None else OrderedDict()

    def _handle_Assignment(self, stmt: Assignment):
        if isinstance(stmt.dst, Register):
            codeloc = self._codeloc()
            self.def_to_loc[stmt.dst] = codeloc
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.dst)

            base_off = get_reg_offset_base(stmt.dst.reg_offset, self.arch)
            self.state.live_registers.add(base_off)

        self._expr(stmt.src)

    def _handle_Store(self, stmt: Store):
        self._expr(stmt.addr)
        self._expr(stmt.data)

    def _handle_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
        if stmt.true_target is not None:
            self._expr(stmt.true_target)
        if stmt.false_target is not None:
            self._expr(stmt.false_target)

    def _handle_Call(self, stmt: Call):
        if stmt.ret_expr is not None and isinstance(stmt.ret_expr, Register):
            codeloc = self._codeloc()
            self.def_to_loc[stmt.ret_expr] = codeloc
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.ret_expr)

            base_off = get_reg_offset_base(stmt.ret_expr.reg_offset, self.arch)
            self.state.live_registers.add(base_off)

        super()._ail_handle_Call(stmt)

    def _handle_Register(self, expr: Register):
        base_offset = get_reg_offset_base(expr.reg_offset, self.arch)

        if base_offset not in self.state.live_registers:
            codeloc = self._codeloc()
            self.def_to_loc[expr] = codeloc
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)

            self.state.live_registers.add(base_offset)

    def _handle_Cmp(self, expr: BinaryOp):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    _handle_CmpLE = _handle_Cmp
    _handle_CmpLT = _handle_Cmp
    _handle_CmpGE = _handle_Cmp
    _handle_CmpGT = _handle_Cmp
    _handle_CmpEQ = _handle_Cmp
    _handle_CmpNE = _handle_Cmp
