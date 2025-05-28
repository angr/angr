# pylint:disable=arguments-renamed,too-many-boolean-expressions,no-self-use,unused-argument
from __future__ import annotations
from typing import Any
from collections.abc import Callable
from collections import defaultdict

from archinfo import Endness
from angr.ailment.expression import (
    Const,
    Register,
    Expression,
    StackBaseOffset,
    Convert,
    BinaryOp,
    VirtualVariable,
    Phi,
    UnaryOp,
    VirtualVariableCategory,
)
from angr.ailment.statement import ConditionalJump, Jump, Assignment
import claripy

from angr.utils.bits import zeroextend_on_demand
from angr.engines.light import SimEngineNostmtAIL
from angr.storage.memory_mixins import (
    SimpleInterfaceMixin,
    DefaultFillerMixin,
    PagedMemoryMixin,
    UltraPagesMixin,
)
from angr.code_location import CodeLocation
from angr.errors import SimMemoryMissingError
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
        self.memory.store(addr, value, size=value.size() // self.arch.byte_width, endness=endness)

    def mem_load(self, addr: int, size: int, endness) -> claripy.ast.BV | None:
        try:
            return self.memory.load(addr, size=size, endness=str(endness), fill_missing=False)
        except SimMemoryMissingError:
            return None

    def vvar_store(self, vvar: VirtualVariable, value: claripy.ast.Bits | None) -> None:
        self.virtual_variables[vvar.varid] = value

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
        self.stack_accesses: defaultdict[int, list[tuple[str, CodeLocation, claripy.ast.Bits]]] = defaultdict(list)
        self.finished: bool = False

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

    def _process_address(self, addr: Expression) -> tuple[int, str] | None:
        if isinstance(addr, Const):
            assert isinstance(addr.value, int)
            return addr.value, "mem"
        if isinstance(addr, StackBaseOffset):
            return (addr.offset + self.STACK_BASE) & self.MASK, "stack"
        if (
            isinstance(addr, UnaryOp)
            and addr.op == "Reference"
            and isinstance(addr.operand, VirtualVariable)
            and addr.operand.was_stack
        ):
            return (addr.operand.stack_offset + self.STACK_BASE) & self.MASK, "stack"
        if (
            isinstance(addr, BinaryOp)
            and addr.op in {"Add", "Sub"}
            and isinstance(addr.operands[0], (StackBaseOffset, UnaryOp, Const))
        ):
            v0_and_type = self._process_address(addr.operands[0])
            if v0_and_type is not None:
                v0 = v0_and_type[0]
                v1 = self._expr(addr.operands[1])
                if isinstance(v1, claripy.ast.Bits) and v1.concrete:
                    if addr.op == "Add":
                        return (v0 + v1.concrete_value) & self.MASK, "stack"
                    if addr.op == "Sub":
                        return (v0 - v1.concrete_value) & self.MASK, "stack"
                    raise NotImplementedError("Unreachable")
        return None

    def _handle_stmt_Assignment(self, stmt):
        if isinstance(stmt.dst, VirtualVariable):
            if stmt.dst.was_reg:
                val = self._expr(stmt.src)
                if isinstance(val, claripy.ast.Bits):
                    self.state.vvar_store(stmt.dst, val)
            elif stmt.dst.was_stack:
                addr = (stmt.dst.stack_offset + self.STACK_BASE) & self.MASK
                val = self._expr(stmt.src)
                if isinstance(val, claripy.ast.BV):
                    self.state.mem_store(addr, val, self.arch.memory_endness)
                    # log it
                    for i in range(val.size() // self.arch.byte_width):
                        byte_off = i
                        if self.arch.memory_endness == Endness.LE:
                            byte_off = val.size() // self.arch.byte_width - i - 1
                        self.stack_accesses[addr + i].append(("store", self._codeloc(), val.get_byte(byte_off)))

    def _handle_stmt_Store(self, stmt):
        addr_and_type = self._process_address(stmt.addr)
        if addr_and_type is not None:
            addr, addr_type = addr_and_type
            val = self._expr(stmt.data)
            if isinstance(val, claripy.ast.BV):
                self.state.mem_store(addr, val, stmt.endness)
                # log it
                if addr_type == "stack":
                    for i in range(val.size() // self.arch.byte_width):
                        byte_off = i
                        if self.arch.memory_endness == Endness.LE:
                            byte_off = val.size() // self.arch.byte_width - i - 1
                        self.stack_accesses[addr + i].append(("store", self._codeloc(), val.get_byte(byte_off)))

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

    def _handle_expr_Load(self, expr):
        addr_and_type = self._process_address(expr.addr)
        if addr_and_type is not None:
            addr, addr_type = addr_and_type
            v = self.state.mem_load(addr, expr.size, expr.endness)
            # log it
            if addr_type == "stack" and isinstance(v, claripy.ast.BV):
                for i in range(expr.size):
                    byte_off = i
                    if self.arch.memory_endness == Endness.LE:
                        byte_off = expr.size - i - 1
                    self.stack_accesses[addr + i].append(("load", self._codeloc(), v.get_byte(byte_off)))
            return v
        return None

    def _handle_expr_Register(self, expr: Register):
        return self.state.reg_load(expr)

    def _handle_expr_VirtualVariable(self, expr: VirtualVariable):
        if expr.was_stack:
            addr = (expr.stack_offset + self.STACK_BASE) & self.MASK
            v = self.state.mem_load(addr, expr.size, self.arch.memory_endness)
            if v is not None:
                # log it
                for i in range(expr.size):
                    byte_off = i
                    if self.arch.memory_endness == Endness.LE:
                        byte_off = expr.size - i - 1
                    self.stack_accesses[addr + i].append(("load", self._codeloc(), v.get_byte(byte_off)))
            return v
        if expr.was_reg:
            return self.state.vvar_load(expr)
        return None

    def _handle_expr_Phi(self, expr: Phi):
        for src, vvar in expr.src_and_vvars:
            if src[0] == self.last_pc and vvar is not None:
                return self.state.vvar_load(vvar)
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

    def _handle_unop_Default(self, expr: UnaryOp):
        return None

    _handle_unop_Clz = _handle_unop_Default
    _handle_unop_Ctz = _handle_unop_Default
    _handle_unop_Dereference = _handle_unop_Default
    _handle_unop_Reference = _handle_unop_Default
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

    def _handle_stmt_Call(self, stmt):
        pass

    def _handle_expr_Call(self, expr):
        pass

    def _handle_expr_BasePointerOffset(self, expr):
        return None

    def _handle_expr_DirtyExpression(self, expr):
        return None

    def _handle_expr_ITE(self, expr):
        return None

    def _handle_expr_MultiStatementExpression(self, expr):
        return None

    def _handle_expr_Reinterpret(self, expr):
        return None

    def _handle_expr_StackBaseOffset(self, expr):
        return None

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
    _handle_binop_QAddV = _handle_binop_Default
    _handle_binop_QNarrowBinV = _handle_binop_Default
    _handle_binop_PermV = _handle_binop_Default
    _handle_binop_Set = _handle_binop_Default


class InlineStringTransformationDescriptor:
    """
    Describes an instance of inline string transformation.
    """

    def __init__(self, store_block, loop_body, stack_accesses, beginning_stack_offset):
        self.store_block = store_block
        self.loop_body = loop_body
        self.stack_accesses = stack_accesses
        self.beginning_stack_offset = beginning_stack_offset


class InlinedStringTransformationSimplifier(OptimizationPass):
    """
    Simplifies inlined string transformation routines.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.AFTER_GLOBAL_SIMPLIFICATION
    NAME = "Simplify string transformations"
    DESCRIPTION = "Simplify string transformations that are commonly used in obfuscated functions."

    def __init__(self, func, **kwargs):
        super().__init__(func, **kwargs)
        self.analyze()

    def _check(self):
        string_transformation_descs = self._find_string_transformation_loops()

        return bool(string_transformation_descs), {"descs": string_transformation_descs}

    def _analyze(self, cache=None):
        if not cache or "descs" not in cache:
            return

        for desc in cache["descs"]:
            desc: InlineStringTransformationDescriptor

            # remove the original statements
            skip_stmt_indices = set()
            for stack_accesses in desc.stack_accesses:
                # the first element is the initial storing statement
                codeloc = stack_accesses[0][1]
                assert codeloc.block_addr == desc.store_block.addr
                skip_stmt_indices.add(codeloc.stmt_idx)
            new_statements = [
                stmt for idx, stmt in enumerate(desc.store_block.statements) if idx not in skip_stmt_indices
            ]

            # add new statements
            store_statements = []
            for off, stack_accesses in enumerate(desc.stack_accesses):
                # the last element is the final storing statement
                new_value_ast = stack_accesses[-1][2]
                new_value = Const(None, None, new_value_ast.concrete_value, self.project.arch.byte_width)
                stmt = Assignment(
                    None,
                    VirtualVariable(
                        None,
                        self.vvar_id_start,
                        self.project.arch.bits,
                        category=VirtualVariableCategory.STACK,
                        oident=desc.beginning_stack_offset + off,
                        ins_addr=desc.store_block.addr + desc.store_block.original_size - 1,
                    ),
                    new_value,
                    ins_addr=desc.store_block.addr + desc.store_block.original_size - 1,
                )
                self.vvar_id_start += 1
                store_statements.append(stmt)
            if new_statements and isinstance(new_statements[-1], (ConditionalJump, Jump)):
                new_statements = new_statements[:-1] + store_statements + new_statements[-1:]
            else:
                new_statements += store_statements

            new_store_block = desc.store_block.copy(statements=new_statements)
            self._update_block(desc.store_block, new_store_block)

            # remote the loop node
            # since the loop node has exactly one external predecessor and one external successor, we can get rid of it
            assert self.out_graph is not None
            pred = next(iter(nn for nn in self.out_graph.predecessors(desc.loop_body) if nn is not desc.loop_body))
            succ = next(iter(nn for nn in self.out_graph.successors(desc.loop_body) if nn is not desc.loop_body))

            self.out_graph.remove_node(desc.loop_body)
            self.out_graph.add_edge(pred, succ)

            if pred.statements and isinstance(pred.statements[-1], ConditionalJump):
                pred.statements[-1] = Jump(
                    None,
                    Const(None, None, succ.addr, self.project.arch.bits),
                    succ.idx,
                    **pred.statements[-1].tags,
                )

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
            engine = InlinedStringTransformationAILEngine(
                self.project, {pred.addr: pred, loop_node.addr: loop_node}, pred.addr, succ.addr, 1024
            )
            if engine.finished:
                # find the longest slide where the stack accesses are like the following:
                #   "store", code_location_a, value_a
                #   "load", code_location_b, value_a
                #   "store", code_location_b, value_b
                # where value_a and value_b may be the same
                candidate_stack_addrs = []
                for stack_addr in sorted(engine.stack_accesses.keys()):
                    stack_accesses = engine.stack_accesses[stack_addr]
                    if len(stack_accesses) == 3:
                        item0, item1, item2 = stack_accesses
                        if (
                            item0[0] == "store"
                            and item1[0] == "load"
                            and item2[0] == "store"
                            and item0[1] != item1[1]
                            and item1[1] == item2[1]
                            and item0[2] is item1[2]
                        ):
                            # found one!
                            candidate_stack_addrs.append(stack_addr)

                if (
                    len(candidate_stack_addrs) >= 2
                    and candidate_stack_addrs[-1] == candidate_stack_addrs[0] + len(candidate_stack_addrs) - 1
                ):
                    filtered_stack_accesses = [engine.stack_accesses[a] for a in candidate_stack_addrs]
                    stack_offset = candidate_stack_addrs[0] - engine.STACK_BASE
                    info = InlineStringTransformationDescriptor(pred, loop_node, filtered_stack_accesses, stack_offset)
                    descs.append(info)

        return descs
