# pylint:disable=arguments-renamed,too-many-boolean-expressions,no-self-use,unused-argument
from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any, NamedTuple

import archinfo
from archinfo import Endness

from angr import claripy
from angr.ailment import AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    Register,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Store
from angr.code_location import CodeLocation
from angr.engines.light import SimEngineNostmtAIL
from angr.errors import SimMemoryMissingError
from angr.storage.memory_mixins import (
    DefaultFillerMixin,
    PagedMemoryMixin,
    SimpleInterfaceMixin,
    UltraPagesMixin,
)
from angr.utils.bits import zeroextend_on_demand
from angr.utils.ssa import get_vvar_uselocs

from .optimization_pass import OptimizationPass, OptimizationPassStage


def _make_binop(compute: Callable[[claripy.ast.BV, claripy.ast.BV], claripy.ast.BV]):
    def inner(self, expr: BinaryOp) -> claripy.ast.BV | None:
        a, b = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if a is None or b is None:
            return None
        try:
            return compute(a, b)
        except (ZeroDivisionError, claripy.ClaripyZeroDivisionError):
            return None

    return inner


class FasterMemory(
    SimpleInterfaceMixin,
    DefaultFillerMixin,
    UltraPagesMixin,
    PagedMemoryMixin,
):
    """
    A fast memory model used in InlinedStringTransformationState.
    """


class StackAccess(NamedTuple):
    """
    A byte-sized stack access recorded by InlinedStringTransformationAILEngine. For stores, ``deps`` holds the stack
    addresses that the stored value was computed from.
    """

    kind: str
    codeloc: CodeLocation
    value: claripy.ast.BV
    deps: frozenset[int] = frozenset()


class InlinedStringTransformationState:
    """
    The abstract state used in InlinedStringTransformationAILEngine.
    """

    def __init__(self, project):
        self.arch = project.arch
        self.project = project

        self.registers = FasterMemory(memory_id="reg")
        self.memory = FasterMemory(memory_id="mem")
        self.virtual_variables = {}
        # varids of register vvars holding a pointer derived from the stack base
        self.stack_pointer_vvars: set[int] = set()
        # varid -> stack addresses the value of this register vvar was computed from
        self.vvar_deps: dict[int, frozenset[int]] = {}
        # memory bytes overwritten with unknown values
        self.erased_bytes: set[int] = set()

        self.registers.set_state(self)
        self.memory.set_state(self)

    def _get_weakref(self):
        return self

    def reg_store(self, reg: Register, value: claripy.ast.BV) -> None:
        self.registers.store(
            reg.reg_offset, value, size=value.size() // self.arch.byte_width, endness=str(self.arch.register_endness)
        )

    def reg_load(self, reg: Register) -> claripy.ast.BV | None:
        try:
            return self.registers.load(
                reg.reg_offset, size=reg.size, endness=self.arch.register_endness, fill_missing=False
            )
        except SimMemoryMissingError:
            return None

    def mem_store(self, addr: int, value: claripy.ast.Bits, endness: str) -> None:
        size = value.size() // self.arch.byte_width
        self.memory.store(addr, value, size=size, endness=endness)
        self.erased_bytes.difference_update(range(addr, addr + size))

    def mem_erase(self, addr: int, size: int) -> None:
        self.erased_bytes.update(range(addr, addr + size))

    def mem_load(self, addr: int, size: int, endness) -> claripy.ast.BV | None:
        if self.erased_bytes and not self.erased_bytes.isdisjoint(range(addr, addr + size)):
            return None
        try:
            return self.memory.load(addr, size=size, endness=str(endness), fill_missing=False)
        except SimMemoryMissingError:
            return None

    def vvar_store(self, vvar: VirtualVariable, value: claripy.ast.Bits | None, is_stack_pointer: bool) -> None:
        self.virtual_variables[vvar.varid] = value
        if is_stack_pointer:
            self.stack_pointer_vvars.add(vvar.varid)
        else:
            self.stack_pointer_vvars.discard(vvar.varid)

    def vvar_load(self, vvar: VirtualVariable) -> claripy.ast.BV | None:
        if vvar.varid in self.virtual_variables:
            return self.virtual_variables[vvar.varid]
        return None


class InlinedStringTransformationAILEngine(
    SimEngineNostmtAIL[InlinedStringTransformationState, claripy.ast.BV | None, None, None],
):
    """
    A simple AIL execution engine
    """

    def __init__(self, project, nodes: dict[int, Any], start: int, end: int, step_limit: int):
        super().__init__(project)
        self.nodes: dict[int, Any] = nodes
        self.start: int = start
        self.end: int = end
        self.step_limit: int = step_limit

        self.STACK_BASE = 0x7FFF_FFF0 if self.arch.bits == 32 else 0x7FFF_FFFF_F000
        self.MASK = 0xFFFF_FFFF if self.arch.bits == 32 else 0xFFFF_FFFF_FFFF_FFFF

        state = InlinedStringTransformationState(project)
        self.stack_accesses: defaultdict[int, list[StackAccess]] = defaultdict(list)
        # stack addresses read while evaluating the current statement
        self._reads: set[int] = set()
        # block address -> kinds of side effects that removing or re-executing the block would not preserve
        self.effects: defaultdict[int, set[str]] = defaultdict(set)
        self.finished: bool = False
        self.final_state = state

        i = 0
        self.last_pc = None
        self.pc = self.start
        while i < self.step_limit:
            if self.pc not in self.nodes:
                # jumped to a node that we do not know about
                break
            block = self.nodes[self.pc]
            self.process(state, block=block, whitelist=None)
            if self.pc is None:
                # not sure where to jump...
                break
            if self.pc == self.end:
                # we reach the end of execution!
                self.finished = True
                break
            i += 1

    def _top(self, bits):
        assert False, "Should not be reachable"

    def _is_top(self, expr):
        assert False, "Should not be reachable"

    def _process_block_end(self, block, stmt_data, whitelist):
        pass

    def _is_stack_pointer(self, expr: Expression) -> bool:
        """
        Whether the value of ``expr`` is derived from the stack base. Only stack-derived values may be used as stack
        addresses; concrete values that happen to fall into the stack range are not.
        """
        if isinstance(expr, StackBaseOffset):
            return True
        if isinstance(expr, UnaryOp):
            return expr.op == "Reference" and isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack
        if isinstance(expr, VirtualVariable):
            return expr.was_reg and expr.varid in self.state.stack_pointer_vvars
        if isinstance(expr, Phi):
            for src, vvar in expr.src_and_vvars:
                if src[0] == self.last_pc and vvar is not None:
                    return self._is_stack_pointer(vvar)
            return False
        if isinstance(expr, BinaryOp):
            if expr.op == "Add":
                return self._is_stack_pointer(expr.operands[0]) != self._is_stack_pointer(expr.operands[1])
            if expr.op == "Sub":
                return self._is_stack_pointer(expr.operands[0]) and not self._is_stack_pointer(expr.operands[1])
        return False

    def _process_address(self, addr: Expression) -> tuple[int, str] | None:
        v = self._expr(addr)
        if not isinstance(v, claripy.ast.BV) or not v.concrete:
            return None
        return v.concrete_value & self.MASK, "stack" if self._is_stack_pointer(addr) else "mem"

    def _record_effect(self, kind: str) -> None:
        self.effects[self.block.addr].add(kind)

    def _handle_stmt_Assignment(self, stmt):
        dst = stmt.dst
        self._reads = set()
        if isinstance(dst, Tmp):
            val = self._expr(stmt.src)
            if isinstance(val, claripy.ast.Bits):
                self.tmps[dst.tmp_idx] = val
        elif isinstance(dst, VirtualVariable) and dst.was_reg:
            val = self._expr(stmt.src)
            self.state.vvar_store(
                dst, val if isinstance(val, claripy.ast.Bits) else None, self._is_stack_pointer(stmt.src)
            )
            self.state.vvar_deps[dst.varid] = frozenset(self._reads)
        elif isinstance(dst, VirtualVariable) and dst.was_stack:
            addr = (dst.stack_offset + self.STACK_BASE) & self.MASK
            val = self._expr(stmt.src)
            if isinstance(val, claripy.ast.BV):
                self._store_stack(addr, val, self.arch.memory_endness)
            else:
                self._erase_stack(addr, dst.size)
        else:
            self._record_effect("unsupported_stmt")

    def _handle_stmt_Store(self, stmt: Store):
        addr_and_type = self._process_address(stmt.addr)
        if addr_and_type is None:
            # this store may alias any stack byte
            self._record_effect("unresolved_write")
            return
        addr, addr_type = addr_and_type
        if addr_type != "stack":
            self._record_effect("global_write")
            return
        self._reads = set()
        val = self._expr(stmt.data)
        if isinstance(val, claripy.ast.BV):
            self._store_stack(addr, val, stmt.endness)
        else:
            self._erase_stack(addr, stmt.size)

    def _erase_stack(self, addr: int, size: int) -> None:
        self._record_effect("unknown_stack_value")
        self.state.mem_erase(addr, size)

    def _store_stack(self, addr: int, val: claripy.ast.BV, endness) -> None:
        self.state.mem_store(addr, val, endness)
        deps = frozenset(self._reads)
        size = val.size() // self.arch.byte_width
        for i in range(size):
            byte_off = size - i - 1 if endness == Endness.LE else i
            self.stack_accesses[addr + i].append(StackAccess("store", self._codeloc(), val.get_byte(byte_off), deps))

    def _log_stack_load(self, addr: int, v: claripy.ast.BV | None, size: int, endness) -> None:
        self._reads.update(range(addr, addr + size))
        if v is not None:
            for i in range(size):
                byte_off = size - i - 1 if endness == Endness.LE else i
                self.stack_accesses[addr + i].append(StackAccess("load", self._codeloc(), v.get_byte(byte_off)))

    def _handle_stmt_Jump(self, stmt):
        self.last_pc = self.pc
        if isinstance(stmt.target, Const):
            self.pc = stmt.target.value
        else:
            self.pc = None

    def _handle_stmt_ConditionalJump(self, stmt):
        self.last_pc = self.pc
        self.pc = None
        if isinstance(stmt.true_target, Const) and isinstance(stmt.false_target, Const):
            cond = self._expr(stmt.condition)
            if cond is not None:
                if isinstance(cond, claripy.ast.Bits) and cond.concrete_value == 1:
                    self.pc = stmt.true_target.value
                elif isinstance(cond, claripy.ast.Bits) and cond.concrete_value == 0:
                    self.pc = stmt.false_target.value

    def _handle_expr_Const(self, expr):
        if isinstance(expr.value, int):
            return claripy.BVV(expr.value, expr.bits)
        return None

    def _handle_expr_Extract(self, expr):
        v = self._expr(expr.base)
        off = self._expr(expr.offset)
        if off is None or not off.concrete or v is None:
            return None
        if expr.endness == archinfo.Endness.BE:
            r = v[len(v) - 1 - off.concrete_value * 8 : len(v) - off.concrete_value * 8 - expr.bits]
        else:
            r = v[expr.bits + off.concrete_value * 8 - 1 : off.concrete_value * 8]
        assert len(r) == expr.bits
        return r

    def _handle_expr_Insert(self, expr):
        v = self._expr(expr.value)
        off = self._expr(expr.offset)
        base = self._expr(expr.base)
        if off is None or not off.concrete or v is None or base is None:
            return None
        if expr.endness == archinfo.Endness.BE:
            r = claripy.Concat(
                (
                    base[len(base) - 1 : len(base) - off.concrete_value * 8]
                    if off.concrete_value != 0
                    else claripy.BVV(b"")
                ),
                v,
                (
                    base[len(base) - off.concrete_value * 8 - len(v) - 1 : 0]
                    if off.concrete_value * 8 + len(v) != len(base)
                    else claripy.BVV(b"")
                ),
            )
        else:
            r = claripy.Concat(
                (
                    base[len(base) - 1 : off.concrete_value * 8 + len(v)]
                    if off.concrete_value * 8 + len(v) != len(base)
                    else claripy.BVV(b"")
                ),
                v,
                base[off.concrete_value * 8 - 1 : 0] if off.concrete_value != 0 else claripy.BVV(b""),
            )
        assert len(r) == expr.bits
        return r

    def _handle_expr_Load(self, expr: Load):
        addr_and_type = self._process_address(expr.addr)
        if addr_and_type is not None and addr_and_type[1] == "stack":
            addr, _ = addr_and_type
            v = self.state.mem_load(addr, expr.size, expr.endness)
            self._log_stack_load(addr, v, expr.size, expr.endness)
            return v
        return None

    def _handle_expr_Register(self, expr: Register):
        return self.state.reg_load(expr)

    def _handle_expr_VirtualVariable(self, expr: VirtualVariable):
        if expr.was_stack:
            addr = (expr.stack_offset + self.STACK_BASE) & self.MASK
            v = self.state.mem_load(addr, expr.size, self.arch.memory_endness)
            self._log_stack_load(addr, v, expr.size, self.arch.memory_endness)
            return v
        if expr.was_reg:
            self._reads |= self.state.vvar_deps.get(expr.varid, frozenset())
            return self.state.vvar_load(expr)
        return None

    def _handle_expr_Phi(self, expr: Phi):
        for src, vvar in expr.src_and_vvars:
            if src[0] == self.last_pc and vvar is not None:
                return self._expr(vvar)
        return None

    def _handle_unop_Neg(self, expr: UnaryOp):
        v = self._expr(expr.operand)
        if isinstance(v, claripy.ast.Bits):
            return -v
        return None

    def _handle_unop_Not(self, expr: UnaryOp):
        v = self._expr(expr.operand)
        if isinstance(v, claripy.ast.Bits):
            return ~v
        return None

    def _handle_unop_BitwiseNeg(self, expr: UnaryOp):
        v = self._expr(expr.operand)
        if isinstance(v, claripy.ast.Bits):
            return ~v
        return None

    def _handle_unop_Abs(self, expr: UnaryOp):
        self._expr(expr.operand)

    def _handle_unop_Default(self, expr: UnaryOp):
        return None

    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default

    def _handle_unop_Reference(self, expr: UnaryOp):
        if isinstance(expr.operand, VirtualVariable) and expr.operand.was_stack:
            return claripy.BVV((expr.operand.stack_offset + self.STACK_BASE) & self.MASK, expr.bits)
        return None

    _handle_unop_GetMSBs = _handle_unop_Default
    _handle_unop_unpack = _handle_unop_Default
    _handle_unop_Sqrt = _handle_unop_Default
    _handle_unop_RSqrtEst = _handle_unop_Default

    def _handle_expr_Convert(self, expr: Convert):
        v = self._expr(expr.operand)
        if isinstance(v, claripy.ast.Bits):
            if expr.to_bits > expr.from_bits:
                if not expr.is_signed:
                    return claripy.ZeroExt(expr.to_bits - expr.from_bits, v)
                return claripy.SignExt(expr.to_bits - expr.from_bits, v)
            if expr.to_bits < expr.from_bits:
                return claripy.Extract(expr.to_bits - 1, 0, v)
            return v
        return None

    def _handle_binop_CmpEQ(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value == op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpNE(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value != op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpLT(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value < op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpLE(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value <= op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpGT(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value > op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpGE(self, expr):
        op0, op1 = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if isinstance(op0, claripy.ast.Bits) and isinstance(op1, claripy.ast.Bits) and op0.concrete and op1.concrete:
            return claripy.BVV(1, 1) if op0.concrete_value >= op1.concrete_value else claripy.BVV(0, 1)
        return None

    def _handle_binop_CmpORD(self, expr):
        return None

    def _handle_stmt_SideEffectStatement(self, stmt):
        self._expr(stmt.expr)

    def _handle_stmt_DirtyStatement(self, stmt):
        self._record_effect("unresolved_write")

    def _handle_stmt_CAS(self, stmt):
        self._record_effect("unresolved_write")

    def _handle_stmt_WeakAssignment(self, stmt):
        self._record_effect("unsupported_stmt")

    def _handle_stmt_Return(self, stmt):
        self._record_effect("unsupported_stmt")

    def _handle_expr_Call(self, expr: Call):
        self._record_effect("call")
        if expr.args and any(self._is_stack_pointer(arg) for arg in expr.args):
            # the callee may write to the stack through this pointer
            self._record_effect("unresolved_write")

    def _handle_expr_BasePointerOffset(self, expr):
        return None

    def _handle_expr_DirtyExpression(self, expr):
        self._record_effect("unsupported_stmt")

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_MultiStatementExpression(self, expr):
        return None

    def _handle_expr_Reinterpret(self, expr):
        return None

    def _handle_expr_StackBaseOffset(self, expr: StackBaseOffset):
        return claripy.BVV((expr.offset + self.STACK_BASE) & self.MASK, expr.bits)

    def _handle_expr_Tmp(self, expr):
        try:
            return self.tmps[expr.tmp_idx]
        except KeyError:
            return None

    def _handle_expr_VEXCCallExpression(self, expr):
        return None

    def _handle_binop_Default(self, expr):
        self._expr(expr.operands[0])
        self._expr(expr.operands[1])

    _handle_binop_Add = _make_binop(lambda a, b: a + b)
    _handle_binop_And = _make_binop(lambda a, b: a & b)
    _handle_binop_Concat = _make_binop(lambda a, b: a.concat(b))
    _handle_binop_Div = _make_binop(lambda a, b: a // b)
    _handle_binop_LogicalAnd = _make_binop(lambda a, b: a & b)
    _handle_binop_LogicalOr = _make_binop(lambda a, b: a | b)
    _handle_binop_Mod = _make_binop(lambda a, b: a % b)
    _handle_binop_Mul = _make_binop(lambda a, b: a * b)
    _handle_binop_Or = _make_binop(lambda a, b: a | b)
    _handle_binop_Rol = _make_binop(lambda a, b: claripy.RotateLeft(a, zeroextend_on_demand(a, b)))
    _handle_binop_Ror = _make_binop(lambda a, b: claripy.RotateRight(a, zeroextend_on_demand(a, b)))
    _handle_binop_Sar = _make_binop(lambda a, b: a >> zeroextend_on_demand(a, b))
    _handle_binop_Shl = _make_binop(lambda a, b: a << zeroextend_on_demand(a, b))
    _handle_binop_Shr = _make_binop(lambda a, b: a.LShR(zeroextend_on_demand(a, b)))
    _handle_binop_Sub = _make_binop(lambda a, b: a - b)
    _handle_binop_Xor = _make_binop(lambda a, b: a ^ b)

    def _handle_binop_Mull(self, expr):
        a, b = self._expr(expr.operands[0]), self._expr(expr.operands[1])
        if a is None or b is None:
            return None
        xt = a.size()
        if expr.signed:
            return a.sign_extend(xt) * b.sign_extend(xt)
        return a.zero_extend(xt) * b.zero_extend(xt)

    _handle_binop_AddF = _handle_binop_Default
    _handle_binop_AddV = _handle_binop_Default
    _handle_binop_Carry = _handle_binop_Default
    _handle_binop_CmpF = _handle_binop_Default
    _handle_binop_DivF = _handle_binop_Default
    _handle_binop_DivV = _handle_binop_Default
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
    _handle_binop_MulF = _handle_binop_Default
    _handle_binop_MulV = _handle_binop_Default
    _handle_binop_MulHiV = _handle_binop_Default
    _handle_binop_SBorrow = _handle_binop_Default
    _handle_binop_SCarry = _handle_binop_Default
    _handle_binop_SubF = _handle_binop_Default
    _handle_binop_SubV = _handle_binop_Default
    _handle_binop_MinV = _handle_binop_Default
    _handle_binop_MaxV = _handle_binop_Default
    _handle_binop_HAddV = _handle_binop_Default
    _handle_binop_QAddV = _handle_binop_Default
    _handle_binop_QSubV = _handle_binop_Default
    _handle_binop_QNarrowBinV = _handle_binop_Default
    _handle_binop_PermV = _handle_binop_Default
    _handle_binop_Set = _handle_binop_Default


class _MemoryReadNotification(Exception):
    """Abort the walk on the first potential memory read."""


class _HasMemoryReadWalker(AILBlockViewer):
    """
    Raises ``_MemoryReadNotification`` on the first expression that InlinedStringTransformationAILEngine could turn
    into a "load" stack-access record: a Load, or a virtual variable that lives on the stack.
    """

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        raise _MemoryReadNotification

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):  # pylint:disable=unused-argument
        if expr.was_stack:
            raise _MemoryReadNotification


_HAS_MEMORY_READ_WALKER = _HasMemoryReadWalker()


def _may_transform_stack_bytes(block) -> bool:
    """
    A descriptor needs the loop body to load a stack byte and to store a value derived from it, possibly through
    register vvars in other statements. This is a cheap syntactic over-approximation of that: the block must contain
    both a memory read and a memory write.
    """
    has_read = has_write = False
    for stmt in block.statements:
        if isinstance(stmt, Store) or (
            isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack
        ):
            has_write = True
        if not has_read:
            try:
                _HAS_MEMORY_READ_WALKER.walk_statement(stmt)
            except _MemoryReadNotification:
                has_read = True
        if has_read and has_write:
            return True
    return False


class InlineStringTransformationDescriptor:
    """
    Describes an instance of inline string transformation.
    """

    def __init__(
        self,
        store_block,
        loop_body,
        stack_accesses: list[list[StackAccess]],
        beginning_stack_offset: int,
        removable_stmt_indices: set[int],
        live_out_values: list[tuple[VirtualVariable, int, bool]],
    ):
        self.store_block = store_block
        self.loop_body = loop_body
        self.stack_accesses = stack_accesses
        self.beginning_stack_offset = beginning_stack_offset
        # indices of statements in store_block that only initialize bytes in the transformed region
        self.removable_stmt_indices = removable_stmt_indices
        # (vvar, final value, whether the value is a stack pointer) for loop-defined vvars used after the loop
        self.live_out_values = live_out_values


class InlinedStringTransformationSimplifier(OptimizationPass):
    """
    Simplifies inlined string transformation routines.
    """

    ARCHES = None
    PLATFORMS = None
    # must be before stack ssa
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL1_TRANSFORMATION
    NAME = "Simplify string transformations"
    DESCRIPTION = "Simplify string transformations that are commonly used in obfuscated functions."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analyze()

    def _check(self):
        string_transformation_descs = self._find_string_transformation_loops()

        return bool(string_transformation_descs), {"descs": string_transformation_descs}

    def _analyze(self, cache=None):
        if not cache or "descs" not in cache:
            return

        for desc in cache["descs"]:
            desc: InlineStringTransformationDescriptor
            assert self._graph is not None
            if self.out_graph is not None and (
                desc.store_block not in self.out_graph or desc.loop_body not in self.out_graph
            ):
                # an earlier rewrite has replaced one of the blocks
                continue

            pred = desc.store_block
            succ = next(iter(nn for nn in self._graph.successors(desc.loop_body) if nn is not desc.loop_body))

            new_statements = [
                stmt for idx, stmt in enumerate(pred.statements) if idx not in desc.removable_stmt_indices
            ]

            # the final values of the transformed bytes
            ins_addr = pred.addr + pred.original_size - 1
            new_tail = []
            for off, stack_accesses in enumerate(desc.stack_accesses):
                new_value = Const(
                    self.manager.next_atom(), stack_accesses[-1].value.concrete_value, self.project.arch.byte_width
                )
                new_tail.append(
                    Store(
                        self.manager.next_atom(),
                        StackBaseOffset(
                            self.manager.next_atom(), self.project.arch.bits, desc.beginning_stack_offset + off
                        ),
                        new_value,
                        new_value.size,
                        self.project.arch.memory_endness,
                        ins_addr=ins_addr,
                    )
                )
            # the final values of loop-defined vvars that are used after the loop
            for vvar, value, is_stack_pointer in desc.live_out_values:
                if is_stack_pointer:
                    src = StackBaseOffset(self.manager.next_atom(), vvar.bits, value)
                else:
                    src = Const(self.manager.next_atom(), value, vvar.bits)
                new_tail.append(Assignment(self.manager.next_atom(), vvar, src, ins_addr=ins_addr))

            if new_statements and isinstance(new_statements[-1], (ConditionalJump, Jump)):
                last_stmt = new_statements[-1]
                new_statements = [
                    *new_statements[:-1],
                    *new_tail,
                    Jump(
                        self.manager.next_atom(),
                        Const(self.manager.next_atom(), succ.addr, self.project.arch.bits),
                        succ.idx,
                        **last_stmt.tags,
                    ),
                ]
            else:
                new_statements += new_tail

            new_pred = pred.copy(statements=new_statements)
            self._update_block(pred, new_pred)

            # the loop node has exactly one external predecessor and one external successor
            assert self.out_graph is not None
            self.out_graph.remove_node(desc.loop_body)
            self.out_graph.add_edge(new_pred, succ)

    def _find_string_transformation_loops(self):
        # find self loops
        self_loops = []
        assert self._graph is not None
        for node in self._graph.nodes:
            preds = list(self._graph.predecessors(node))
            succs = list(self._graph.successors(node))
            if len(preds) == 2 and len(succs) == 2 and node in preds and node in succs:
                pred = next(iter(nn for nn in preds if nn is not node))
                succ = next(iter(nn for nn in succs if nn is not node))
                if (self._graph.out_degree[pred] == 1 and self._graph.in_degree[succ] == 1) or (
                    self._graph.out_degree[pred] == 2
                    and self._graph.in_degree[succ] == 2
                    and self._graph.has_edge(pred, succ)
                ):
                    # found it
                    self_loops.append(node)

        if not self_loops:
            return []

        descs = []
        for loop_node in self_loops:
            pred = next(iter(nn for nn in self._graph.predecessors(loop_node) if nn is not loop_node))
            succ = next(iter(nn for nn in self._graph.successors(loop_node) if nn is not loop_node))
            if not _may_transform_stack_bytes(loop_node):
                # the loop body cannot transform stack bytes; skip the (expensive) execution entirely
                continue
            engine = InlinedStringTransformationAILEngine(
                self.project, {pred.addr: pred, loop_node.addr: loop_node}, pred.addr, succ.addr, 1024
            )
            if not engine.finished:
                continue
            desc = self._make_descriptor(engine, pred, loop_node)
            if desc is not None:
                descs.append(desc)

        return descs

    def _make_descriptor(
        self, engine: InlinedStringTransformationAILEngine, pred, loop_node
    ) -> InlineStringTransformationDescriptor | None:
        # the loop body must not have any effect beyond register vvars and the transformed stack bytes, and nothing in
        # the predecessor may write to unknown locations
        if engine.effects.get(loop_node.addr) or "unresolved_write" in engine.effects.get(pred.addr, ()):
            return None

        # find the longest slide where the last stack accesses of each byte are like the following:
        #   "store" in the predecessor
        #   "load" in the loop body
        #   "store" in the loop body, whose value is computed from the loaded byte
        candidate_stack_addrs = []
        loop_stored_addrs = set()
        for stack_addr in sorted(engine.stack_accesses.keys()):
            stack_accesses = engine.stack_accesses[stack_addr]
            if any(acc.kind == "store" and acc.codeloc.block_addr == loop_node.addr for acc in stack_accesses):
                loop_stored_addrs.add(stack_addr)
            if len(stack_accesses) >= 3:
                *_, item0, item1, item2 = stack_accesses
                if (
                    item0.kind == "store"
                    and item0.codeloc.block_addr == pred.addr
                    and item1.kind == "load"
                    and item1.codeloc.block_addr == loop_node.addr
                    and item2.kind == "store"
                    and item2.codeloc.block_addr == loop_node.addr
                    and stack_addr in item2.deps
                ):
                    candidate_stack_addrs.append(stack_addr)

        if not (
            len(candidate_stack_addrs) >= 2
            and candidate_stack_addrs[-1] == candidate_stack_addrs[0] + len(candidate_stack_addrs) - 1
            and loop_stored_addrs == set(candidate_stack_addrs)
        ):
            return None
        candidates = set(candidate_stack_addrs)

        # the predecessor must not read the bytes whose initialization we remove
        stmt_bytes: defaultdict[int, set[int]] = defaultdict(set)
        for stack_addr, stack_accesses in engine.stack_accesses.items():
            for acc in stack_accesses:
                if acc.codeloc.block_addr != pred.addr:
                    continue
                if acc.kind == "load" and stack_addr in candidates:
                    return None
                if acc.kind == "store":
                    assert acc.codeloc.stmt_idx is not None
                    stmt_bytes[acc.codeloc.stmt_idx].add(stack_addr)
        # statements that also initialize bytes outside the region are kept; the new stores override them
        removable_stmt_indices = {idx for idx, addrs in stmt_bytes.items() if addrs <= candidates}

        live_out_values = self._live_out_values(engine, loop_node)
        if live_out_values is None:
            return None

        filtered_stack_accesses = [engine.stack_accesses[a] for a in candidate_stack_addrs]
        stack_offset = candidate_stack_addrs[0] - engine.STACK_BASE
        return InlineStringTransformationDescriptor(
            pred, loop_node, filtered_stack_accesses, stack_offset, removable_stmt_indices, live_out_values
        )

    def _live_out_values(
        self, engine: InlinedStringTransformationAILEngine, loop_node
    ) -> list[tuple[VirtualVariable, int, bool]] | None:
        """
        Collect the final values of vvars that are defined in the loop body and used elsewhere. Returns None if any of
        them does not have a concrete final value.
        """
        loop_defs: dict[int, VirtualVariable] = {
            stmt.dst.varid: stmt.dst
            for stmt in loop_node.statements
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)
        }
        assert self._graph is not None
        used_varids = get_vvar_uselocs(nn for nn in self._graph if nn is not loop_node).keys() & loop_defs.keys()

        state = engine.final_state
        live_out_values = []
        for varid in sorted(used_varids):
            vvar = loop_defs[varid]
            value = state.virtual_variables.get(varid)
            if not vvar.was_reg or value is None or not value.concrete:
                return None
            if varid in state.stack_pointer_vvars:
                offset = (value.concrete_value - engine.STACK_BASE) & engine.MASK
                if offset > engine.MASK // 2:
                    offset -= engine.MASK + 1
                live_out_values.append((vvar, offset, True))
            else:
                live_out_values.append((vvar, value.concrete_value, False))
        return live_out_values
