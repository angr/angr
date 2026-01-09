from __future__ import annotations
from collections import defaultdict
from typing import Any, TypeAlias
from collections.abc import Callable, MutableMapping

import networkx

from angr import ailment
import angr
from angr.ailment.block_walker import AILBlockRewriter, AILBlockWalker
from angr.ailment.expression import UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment
from angr.knowledge_plugins.functions.function import Function
from angr.sim_type import SimTypePointer, PointerDisposition
from angr.code_location import AILCodeLocation
from angr.analyses.decompiler.ssailification.ssailification import Ssailification


def new_vars_for_killing_references(
    project: angr.Project,
    func: Function,
    ail_manager: ailment.Manager,
    ail_graph: networkx.DiGraph[ailment.Block],
    entry_block: ailment.Block,
    next_vvar: int,
) -> tuple[int, networkx.DiGraph[ailment.Block]]:
    finder = FindKillingReferences()
    traverse_in_order(ail_graph, entry_block, finder.walk)

    if finder.confirmed_redefine:
        rewriter = ChangeKillingReferences()
        for varid, (loc, bits) in finder.confirmed_redefine.items():
            stack_offset, stack_size = None, None
            if bits is not None and (offset := finder.stack_vars.get(varid, None)) is not None:
                stack_offset, stack_size = offset, bits // 8
            rewriter.pending_replacements[loc].append((varid, next_vvar, stack_offset, stack_size))
            next_vvar += 1
        traverse_in_order(ail_graph, entry_block, rewriter.walk)

        if rewriter.rewrite_vvars:
            # houuuuuuuuuuugh
            sail = project.analyses[Ssailification].prep()(
                func,
                ail_graph,
                entry_block,
                ail_manager=ail_manager,
                rewrite_vvars=rewriter.rewrite_vvars,
                vvar_id_start=next_vvar,
            )
            assert sail.out_graph is not None
            return sail.max_vvar_id, sail.out_graph

    return next_vvar, ail_graph


def traverse_in_order(
    ail_graph: networkx.DiGraph[ailment.Block], entry_block: ailment.Block, visitor: Callable[[ailment.Block], Any]
):
    seen = {entry_block}
    pending = [entry_block]
    last_pending = set(pending)
    forcing = set()

    # walk this graph in a special order to make sure we see defs of ssa variables before their uses
    while pending:
        stack = pending
        pending = set()

        while stack:
            block = stack.pop()
            if block in forcing or all(pred in seen for pred in ail_graph.pred[block]):
                # process it!
                visitor(block)

                news = set(ail_graph.succ[block])
                news -= seen
                stack.extend(sorted(news))
                seen.update(news)
            else:
                pending.add(block)

        if last_pending == pending:
            forcing.update(last_pending)
            last_pending = set()
        else:
            last_pending = set(pending)
        pending = sorted(pending)


# (varid referenced | None (indicates offset is const value), offset)
State: TypeAlias = "set[tuple[int | None, int]]"


class FindKillingReferences(AILBlockWalker[State, None, None]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.vvar_state: dict[int, State] = {}
        self.stack_vars: dict[int, int] = {}
        self.potential_redefine: dict[int, AILCodeLocation] = {}
        self.phi_uses: MutableMapping[int, set[int]] = defaultdict(set)
        self.confirmed_redefine: dict[int, tuple[AILCodeLocation, int | None]] = {}

    def _top(self, expr_idx: int, expr, stmt_idx: int, stmt, block):
        return set()

    def _stmt_top(self, stmt_idx: int, stmt, block):
        return None

    def _handle_block_end(self, stmt_results, block):
        return None

    def _handle_VirtualVariable(self, expr_idx: int, expr, stmt_idx: int, stmt, block):
        for varid in self.phi_uses[expr.varid]:
            self.potential_redefine.pop(varid, None)
        self.potential_redefine.pop(expr.varid, None)
        return self.vvar_state.get(expr.varid, set())

    def _handle_UnaryOp(self, expr_idx: int, expr, stmt_idx: int, stmt, block) -> State:
        assert block is not None
        assert stmt is not None
        if expr.op == "Reference" and isinstance(expr.operand, VirtualVariable):
            self.potential_redefine[expr.operand.varid] = AILCodeLocation(
                block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr", block.addr)
            )
            if expr.operand.was_stack:
                self.stack_vars[expr.operand.varid] = expr.operand.stack_offset
            return {(expr.operand.varid, 0)}
        self._handle_expr(0, expr.operand, stmt_idx, stmt, block)
        return set()

    def _handle_Const(self, expr_idx: int, expr, stmt_idx: int, stmt, block) -> State:
        if isinstance(expr.value, int):
            return {(None, expr.value)}
        return set()

    def _handle_BinaryOp(self, expr_idx: int, expr, stmt_idx, stmt, block) -> State:
        arg0l = self._handle_expr(0, expr.operands[0], stmt_idx, stmt, block)
        arg1l = self._handle_expr(1, expr.operands[1], stmt_idx, stmt, block)

        if expr.op not in ("Add", "Sub"):
            return set()
        sign = 1 if expr.op == "Add" else -1
        result: State = set()
        for arg0 in arg0l:
            for arg1 in arg1l:
                if (arg0[0] is None or arg1[0] is None) and (arg0[1] is not None and arg1[1] is not None):
                    result.add((arg0[0] or arg1[0], arg0[1] + sign * arg1[1]))
        return result

    def _kill_reference(self, ptr: State, bits: int | None):
        for val in ptr:
            if (
                val[0] is not None and val[1] == 0 and (loc := self.potential_redefine.pop(val[0], None)) is not None
            ):  # relax the second condition?
                self.confirmed_redefine[val[0]] = (loc, bits)

    def _handle_Assignment(self, stmt_idx: int, stmt, block):
        val = self._handle_expr(0, stmt.src, stmt_idx, stmt, block)

        if isinstance(stmt.dst, VirtualVariable):
            self.potential_redefine.pop(stmt.dst.varid, None)
            self.vvar_state[stmt.dst.varid] = val
        elif isinstance(stmt.dst, UnaryOp) and stmt.dst.op == "Dereference":
            self._kill_reference(self._handle_expr(0, stmt.dst.operand, stmt_idx, stmt, block), None)
        return None

    def _handle_Phi(self, expr_idx: int, expr, stmt_idx, stmt, block):
        result = set()
        assert isinstance(stmt, Assignment) and stmt.src is expr and isinstance(stmt.dst, VirtualVariable)
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.phi_uses[stmt.dst.varid].add(vvar.varid)
                result.update(self.vvar_state.get(vvar.varid, set()))
        return result

    def _handle_Call(self, stmt_idx: int, stmt, block):
        self._handle_CallExpr(0, stmt, stmt_idx, stmt, block)

    def _handle_CallExpr(self, expr_idx: int, expr, stmt_idx, stmt, block) -> State:
        if expr.prototype is not None:
            for arg, ty in zip(expr.args or [], expr.prototype.args):
                val = self._handle_expr(0, arg, stmt_idx, stmt, block)
                if isinstance(ty, SimTypePointer) and ty.disposition == PointerDisposition.OUT:
                    self._kill_reference(val, ty.pts_to.size)
        return set()


class ChangeKillingReferences(AILBlockRewriter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_replacements: MutableMapping[AILCodeLocation, list[tuple[int, int, int | None, int | None]]] = (
            defaultdict(list)
        )
        self.replacements: dict[int, int] = {}
        self.new_stack_sizes: dict[int, tuple[int, int]] = {}
        self.rewrite_vvars: set[int] = set()
        self._extra_defs: list[int] = []

    def _handle_stmt(self, stmt_idx: int, stmt, block):
        assert block is not None
        loc = AILCodeLocation(block.addr, block.idx, stmt_idx, stmt.tags.get("ins_addr", block.addr))
        replacements = self.pending_replacements.pop(loc, None)
        if replacements is not None:
            self._extra_defs = [b for _, b, _, _ in replacements]
            for oldv, newv, stack_offset, stack_size in replacements:
                self.replacements[oldv] = newv
                if stack_offset is not None and stack_size is not None:
                    self.new_stack_sizes[stack_offset] = (newv, stack_size)
        else:
            self._extra_defs = []

        result = super()._handle_stmt(stmt_idx, stmt, block)
        if replacements is not None:
            result.tags["extra_defs"] = self._extra_defs
        return result

    def _handle_VirtualVariable(self, expr_idx: int, expr, stmt_idx: int, stmt, block):
        if expr.was_stack:
            stack_offset = expr.stack_offset
            for offset, (repl, size) in self.new_stack_sizes.items():
                if offset <= stack_offset < offset + size:
                    if repl == expr.varid:
                        break
                    vvar = VirtualVariable(None, repl, size * 8, VirtualVariableCategory.STACK, offset, **expr.tags)
                    if vvar.size == expr.size:
                        return vvar
                    return ailment.expression.Extract(
                        None, expr.bits, vvar, ailment.expression.Const(None, None, stack_offset - offset, 64)
                    )
        if expr.varid in self.replacements:
            repl = self.replacements[expr.varid]
            return VirtualVariable(None, repl, expr.bits, expr.category, expr.oident, **expr.tags)
        return super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_UnaryOp(self, expr_idx: int, expr: UnaryOp, stmt_idx: int, stmt, block):
        assert stmt is not None
        result = super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)
        if (
            result is not expr
            and isinstance(result, UnaryOp)
            and result.op == "Reference"
            and isinstance(expr.operand, VirtualVariable)
        ):
            if isinstance(result.operand, ailment.expression.Extract) and isinstance(
                result.operand.base, ailment.expression.VirtualVariable
            ):
                assert isinstance(result.operand.offset, ailment.expression.Const)
                result.operand.offset.bits = result.bits
                refs = ailment.expression.UnaryOp(None, "Reference", result.operand.base, bits=result.bits)
                if result.operand.base.varid in self._extra_defs:
                    refs.tags["extra_def"] = True
                if result.operand.offset.value != 0:
                    refs = ailment.expression.BinaryOp(None, "Add", [refs, result.operand.offset], bits=result.bits)
                return refs
            if result.operand.varid in self._extra_defs:
                result.tags["extra_def"] = True
        return result

    def _handle_Assignment(self, stmt_idx: int, stmt: Assignment, block) -> ailment.Statement:
        dst = self._handle_expr(0, stmt.dst, stmt_idx, stmt, block)
        if isinstance(dst, ailment.expression.Extract):
            # okay... need a new vvar for the replaced struct
            assert isinstance(dst.base, VirtualVariable)
            inserted = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
            new_src = ailment.expression.Insert(None, dst.base, dst.offset, inserted)
            new_dst = ailment.expression.VirtualVariable(
                None, dst.base.varid, dst.base.bits, dst.base.category, dst.base.oident
            )
            self.rewrite_vvars.add(dst.base.varid)
            # I don't think this needs to be optimized...
            for offset, (varid, size) in self.new_stack_sizes.items():
                if varid == new_dst.varid:
                    self.new_stack_sizes[offset] = (new_dst.varid, size)
            for k, v in self.replacements.items():
                if v == new_dst.varid:
                    self.replacements[k] = new_dst.varid
            return ailment.statement.Assignment(stmt.idx, new_dst, new_src, **stmt.tags)
        return super()._handle_Assignment(stmt_idx, stmt, block)
