from __future__ import annotations
from collections import OrderedDict

from angr.ailment.statement import Call, Store, ConditionalJump, CAS
from angr.ailment.expression import (
    Register,
    BinaryOp,
    StackBaseOffset,
    ITE,
    VEXCCallExpression,
    Tmp,
    DirtyExpression,
    Load,
)

from angr.engines.light import SimEngineLightAIL
from angr.project import Project
from angr.utils.ssa import get_reg_offset_base
from angr.utils.orderedset import OrderedSet
from angr.calling_conventions import default_cc
from .traversal_state import TraversalState


class SimEngineSSATraversal(SimEngineLightAIL[TraversalState, None, None, None]):
    """
    This engine collects all register and stack variable locations and links them to the block of their creation.
    """

    def __init__(
        self,
        project: Project,
        simos,
        sp_tracker=None,
        bp_as_gpr: bool = False,
        def_to_loc=None,
        loc_to_defs=None,
        stackvars: bool = False,
        use_tmps: bool = False,
    ):
        super().__init__(project)
        self.simos = simos
        self.sp_tracker = sp_tracker
        self.bp_as_gpr = bp_as_gpr
        self.stackvars = stackvars
        self.use_tmps = use_tmps

        self.def_to_loc = def_to_loc if def_to_loc is not None else []
        self.loc_to_defs = loc_to_defs if loc_to_defs is not None else OrderedDict()

    def _is_top(self, expr):
        return True

    def _top(self, bits):
        return None

    def _process_block_end(self, block, stmt_data, whitelist):
        pass

    def _handle_stmt_Assignment(self, stmt):
        if isinstance(stmt.dst, Register):
            codeloc = self._codeloc()
            self.def_to_loc.append((stmt.dst, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(stmt.dst)

            base_off = get_reg_offset_base(stmt.dst.reg_offset, self.arch)
            self.state.live_registers.add(base_off)

        self._expr(stmt.src)

    def _handle_stmt_WeakAssignment(self, stmt):
        self._expr(stmt.src)
        self._expr(stmt.dst)

    def _handle_stmt_CAS(self, stmt: CAS):
        self._expr(stmt.addr)
        self._expr(stmt.data_lo)
        if stmt.data_hi is not None:
            self._expr(stmt.data_hi)
        self._expr(stmt.expd_lo)
        if stmt.expd_hi is not None:
            self._expr(stmt.expd_hi)

    def _handle_stmt_Store(self, stmt: Store):
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

    def _handle_stmt_ConditionalJump(self, stmt: ConditionalJump):
        self._expr(stmt.condition)
        if stmt.true_target is not None:
            self._expr(stmt.true_target)
        if stmt.false_target is not None:
            self._expr(stmt.false_target)

    def _handle_stmt_Call(self, stmt: Call):

        # kill caller-saved registers
        cc = (
            default_cc(self.arch.name, platform=self.simos.name if self.simos is not None else None)
            if stmt.calling_convention is None
            else stmt.calling_convention
        )
        assert cc is not None
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

    def _handle_stmt_Dummy(self, stmt):
        pass

    def _handle_stmt_DirtyStatement(self, stmt):
        self._expr(stmt.dirty)

    def _handle_stmt_Jump(self, stmt):
        self._expr(stmt.target)

    _handle_stmt_Label = _handle_stmt_Dummy

    def _handle_stmt_Return(self, stmt):
        for expr in stmt.ret_exprs:
            self._expr(expr)

    def _handle_expr_Register(self, expr: Register):
        base_offset = get_reg_offset_base(expr.reg_offset, self.arch)

        if base_offset not in self.state.live_registers:
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)

            self.state.live_registers.add(base_offset)

    def _handle_expr_Load(self, expr: Load):
        self._expr(expr.addr)
        if (
            self.stackvars
            and isinstance(expr.addr, StackBaseOffset)
            and isinstance(expr.addr.offset, int)
            and (expr.addr.offset, expr.size) not in self.state.live_stackvars
        ):
            # we must create this stack variable on the fly; we did not see its creation before it is first used
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)
            self.state.live_stackvars.add((expr.addr.offset, expr.size))

    def _handle_expr_StackBaseOffset(self, expr: StackBaseOffset):
        # we don't know the size, so we assume the size is 1 for now...
        sz = 1
        if isinstance(expr.offset, int) and (expr.offset, sz) not in self.state.live_stackvars:
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)
            self.state.live_stackvars.add((expr.offset, sz))

    def _handle_expr_Tmp(self, expr: Tmp):
        if self.use_tmps:
            codeloc = self._codeloc()
            self.def_to_loc.append((expr, codeloc))
            if codeloc not in self.loc_to_defs:
                self.loc_to_defs[codeloc] = OrderedSet()
            self.loc_to_defs[codeloc].add(expr)

            self.state.live_tmps.add(expr.tmp_idx)

    def _handle_binop_Default(self, expr: BinaryOp):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    _handle_binop_CmpLE = _handle_binop_Default
    _handle_binop_CmpLT = _handle_binop_Default
    _handle_binop_CmpGE = _handle_binop_Default
    _handle_binop_CmpGT = _handle_binop_Default
    _handle_binop_CmpEQ = _handle_binop_Default
    _handle_binop_CmpNE = _handle_binop_Default
    _handle_binop_Add = _handle_binop_Default
    _handle_binop_AddF = _handle_binop_Default
    _handle_binop_AddV = _handle_binop_Default
    _handle_binop_And = _handle_binop_Default
    _handle_binop_Carry = _handle_binop_Default
    _handle_binop_CmpF = _handle_binop_Default
    _handle_binop_Concat = _handle_binop_Default
    _handle_binop_Div = _handle_binop_Default
    _handle_binop_DivF = _handle_binop_Default
    _handle_binop_DivV = _handle_binop_Default
    _handle_binop_LogicalAnd = _handle_binop_Default
    _handle_binop_LogicalOr = _handle_binop_Default
    _handle_binop_Mod = _handle_binop_Default
    _handle_binop_Mul = _handle_binop_Default
    _handle_binop_Mull = _handle_binop_Default
    _handle_binop_MulF = _handle_binop_Default
    _handle_binop_MulV = _handle_binop_Default
    _handle_binop_MulHiV = _handle_binop_Default
    _handle_binop_Or = _handle_binop_Default
    _handle_binop_Rol = _handle_binop_Default
    _handle_binop_Ror = _handle_binop_Default
    _handle_binop_SBorrow = _handle_binop_Default
    _handle_binop_SCarry = _handle_binop_Default
    _handle_binop_Sar = _handle_binop_Default
    _handle_binop_Shl = _handle_binop_Default
    _handle_binop_Shr = _handle_binop_Default
    _handle_binop_Sub = _handle_binop_Default
    _handle_binop_SubF = _handle_binop_Default
    _handle_binop_SubV = _handle_binop_Default
    _handle_binop_Xor = _handle_binop_Default
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

    def _handle_unop_Default(self, expr):
        self._expr(expr.operand)

    _handle_unop_BitwiseNeg = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_Neg = _handle_unop_Default
    _handle_unop_Not = _handle_unop_Default
    _handle_unop_Reference = _handle_unop_Default
    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default

    def _handle_expr_UnaryOp(self, expr):
        self._expr(expr.operand)

    def _handle_expr_BinaryOp(self, expr):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    def _handle_expr_ITE(self, expr: ITE):
        self._expr(expr.cond)
        self._expr(expr.iftrue)
        self._expr(expr.iffalse)

    def _handle_expr_VEXCCallExpression(self, expr: VEXCCallExpression):
        for operand in expr.operands:
            self._expr(operand)

    def _handle_expr_DirtyExpression(self, expr: DirtyExpression):
        for operand in expr.operands:
            self._expr(operand)
        if expr.guard is not None:
            self._expr(expr.guard)
        if expr.maddr is not None:
            self._expr(expr.maddr)

    _handle_expr_Convert = _handle_unop_Default
    _handle_expr_Reinterpret = _handle_unop_Default

    def _handle_Dummy(self, expr):
        pass

    _handle_expr_VirtualVariable = _handle_Dummy
    _handle_expr_Phi = _handle_Dummy
    _handle_expr_Const = _handle_Dummy
    _handle_expr_MultiStatementExpression = _handle_Dummy
    _handle_expr_BasePointerOffset = _handle_Dummy
    _handle_expr_Call = _handle_Dummy
