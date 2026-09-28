from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import networkx
import pyvex

from angr import claripy
from angr.analyses.reaching_definitions import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.rd_initializer import RDAStateInitializer
from angr.analyses.stack_pointer_tracker import StackPointerTracker
from angr.calling_conventions import SimCCCdecl
from angr.codenode import BlockNode
from angr.errors import SimEngineError, SimMemoryMissingError
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER

if TYPE_CHECKING:
    from angr.knowledge_base import KnowledgeBase
    from angr.knowledge_plugins.functions import Function
    from angr.project import Project

l = logging.getLogger(__name__)


def _stack_address(expr: pyvex.expr.IRExpr, stack_tmps: set[int], sp_offset: int) -> bool:
    if isinstance(expr, pyvex.expr.RdTmp):
        return expr.tmp in stack_tmps
    if isinstance(expr, pyvex.expr.Get):
        return expr.offset == sp_offset and expr.ty == "Ity_I32"
    if isinstance(expr, pyvex.expr.Binop) and expr.op in {"Iop_Add32", "Iop_Sub32"}:
        left, right = expr.args
        if isinstance(right, pyvex.expr.Const):
            return _stack_address(left, stack_tmps, sp_offset)
        if expr.op == "Iop_Add32" and isinstance(left, pyvex.expr.Const):
            return _stack_address(right, stack_tmps, sp_offset)
    return False


def get_x86_return_range(project: Project, function: Function, kb: KnowledgeBase) -> tuple[int, int] | None:
    """
    Bound AL at every return of a small, closed, acyclic x86 leaf using ReachingDefinitions.

    Only direct stack loads are allowed: RDA may otherwise use initial loader bytes, which are not a
    context-independent memory invariant. Calls, stores, special effects and non-return SP writes are
    rejected, as are writes to callee-saved registers that the caller's constant propagation may preserve.
    These checks are an applicability policy, not a second instruction-semantics engine.
    """
    if project.arch.name != "X86" or function.is_simprocedure:
        return None
    graph = function.graph
    if not 0 < len(graph) <= 8 or not networkx.is_directed_acyclic_graph(graph):
        return None
    if len({node.addr for node in graph}) != len(graph):
        return None
    entry = next((node for node in graph if node.addr == function.addr), None)
    if entry is None or len(networkx.descendants(graph, entry)) + 1 != len(graph):
        return None

    arch = project.arch
    sp_offset = arch.sp_offset
    if sp_offset is None:
        return None
    flag_registers = {"cc_op", "cc_dep1", "cc_dep2", "cc_ndep"}
    writable_registers = set(SimCCCdecl.CALLER_SAVED_REGS) | flag_registers | {"esp", "eip"}
    readable_bytes = set()
    writable_bytes = set()
    for register in arch.register_list:
        if register.general_purpose or register.name in flag_registers | {"eip"}:
            offset, size = arch.registers[register.name]
            readable_bytes.update(range(offset, offset + size))
            if register.name in writable_registers:
                writable_bytes.update(range(offset, offset + size))
    returns = {}
    statement_count = 0
    for node in graph:
        if not isinstance(node, BlockNode) or not 0 < node.size <= 256 or project.is_hooked(node.addr):
            return None
        block = project.factory.block(node.addr, size=node.size, opt_level=1, cross_insn_opt=False)
        irsb = block.vex
        if irsb.size != node.size or irsb.jumpkind not in {"Ijk_Boring", "Ijk_Ret"}:
            return None
        statement_count += len(irsb.statements)
        if statement_count > 256 or not block.instruction_addrs:
            return None
        targets = set()
        stack_tmps = set()
        ins_addr = None
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                ins_addr = stmt.addr
            elif isinstance(stmt, pyvex.stmt.WrTmp):
                if _stack_address(stmt.data, stack_tmps, sp_offset):
                    stack_tmps.add(stmt.tmp)
            elif isinstance(stmt, pyvex.stmt.Put):
                size = stmt.data.result_size(irsb.tyenv) // arch.byte_width
                written = set(range(stmt.offset, stmt.offset + size))
                if not written <= writable_bytes:
                    return None
                if written.intersection(range(sp_offset, sp_offset + arch.bytes)) and (
                    irsb.jumpkind != "Ijk_Ret" or ins_addr != block.instruction_addrs[-1]
                ):
                    return None
            elif isinstance(stmt, pyvex.stmt.Exit):
                if stmt.jumpkind != "Ijk_Boring":
                    return None
                targets.add(stmt.dst.value)
            elif not isinstance(stmt, (pyvex.stmt.NoOp, pyvex.stmt.AbiHint)):
                return None
            for expr in stmt.expressions:
                if isinstance(expr, pyvex.expr.Load) and not _stack_address(expr.addr, stack_tmps, sp_offset):
                    return None
                if isinstance(expr, pyvex.expr.GetI):
                    return None
                if isinstance(expr, pyvex.expr.Get):
                    size = expr.result_size(irsb.tyenv) // arch.byte_width
                    if not set(range(expr.offset, expr.offset + size)) <= readable_bytes:
                        return None
        if irsb.jumpkind == "Ijk_Ret":
            returns[node.addr] = block.instruction_addrs[-1]
        elif isinstance(irsb.next, pyvex.expr.Const):
            targets.add(irsb.next.con.value)
        else:
            return None
        if targets != {successor.addr for successor in graph.successors(node)}:
            return None
    if not returns:
        return None

    tracker = project.analyses[StackPointerTracker].prep(kb=kb)(
        function, {sp_offset}, track_memory=False, cross_insn_opt=False
    )
    if any(
        tracker.offset_before(ins_addr, sp_offset) != 0 or tracker.offset_after(ins_addr, sp_offset) != arch.bytes
        for ins_addr in returns.values()
    ):
        return None
    try:
        rda = project.analyses[ReachingDefinitionsAnalysis].prep(kb=kb, fail_fast=True)(
            function,
            observation_points=[("node", addr, OP_AFTER) for addr in returns],
            state_initializer=RDAStateInitializer(arch),
            # More iterations than the number of paths to any node in this bounded DAG.
            max_iterations=1 << len(graph),
            dep_graph=False,
            track_liveness=False,
        )
    except SimEngineError:
        l.debug("Unsupported reaching-definition semantics in return summary for %#x", function.addr, exc_info=True)
        return None
    if rda.errors or rda.visited_blocks != set(graph):
        return None
    bounds = []
    solver = claripy.SolverVSA()
    offset, size = arch.registers["al"]
    for addr in returns:
        live = rda.observed_results.get(("node", addr, OP_AFTER))
        if live is None:
            return None
        try:
            values = live.registers.load(offset, size=size)
        except SimMemoryMissingError:
            return None
        if values.count() != 1 or 0 not in values or not values[0]:
            return None
        for value in values[0]:
            if not isinstance(value, claripy.ast.BV) or value.size() != 8:
                return None
            bounds.append((solver.min(value), solver.max(value)))
    return min(bound[0] for bound in bounds), max(bound[1] for bound in bounds)
