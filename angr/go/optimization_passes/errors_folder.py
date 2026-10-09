"""
Fold the inlined parts of ``fmt.Errorf`` and ``errors.New`` back into calls.

Since CL 708836 (go1.27) ``fmt.Errorf(format, a...)`` is split so it inlines into its callers::

    if err = errorf(format, a...); err != nil { return err }
    return errors.New(format)      // &errorString{format}

The caller keeps the ``errorf`` call, a nil check of its itab word and a fallback arm that allocates an
``errors.errorString`` holding the format. The fallback is dropped and the call becomes ``fmt.Errorf``. A remaining
``new(errors.errorString)`` whose string field is stored right away is an inlined ``errors.New(s)``.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from typing import TYPE_CHECKING, cast

from angr.ailment.block import Block
from angr.ailment.expression import BinaryOp, Call, Const, Expression, Phi, StringLiteral, Struct, VirtualVariable
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, Statement, Store
from angr.go.analyses.block_scan import allocator

# module import: builtin_rewriter imports this module at its top
from . import builtin_rewriter

if TYPE_CHECKING:
    from .builtin_rewriter import GoBuiltinRewriter

l = logging.getLogger(__name__)

ERROR_STRING = "errors.errorString"
# the name a call is printed under instead of its target's
CALLEE_NAME_TAG = "go_callee_name"
_MAX_FALLBACK_BLOCKS = 4


class ErrorsFolder:
    """Run by :class:`GoBuiltinRewriter` before its call rewriting (allocations are still runtime calls)."""

    def __init__(self, pass_: GoBuiltinRewriter):
        self.p = pass_
        self.graph = pass_._graph
        self.ws = pass_.project.arch.bytes

    def run(self) -> bool:
        changed = False
        for block in list(self.graph.nodes):
            if block in self.graph and self._fold_errorf(block):
                changed = True
        for block in list(self.graph.nodes):
            while self._fold_errors_new(block):
                changed = True
        return changed

    #
    # fmt.Errorf
    #

    def _fold_errorf(self, block: Block) -> bool:
        for i, stmt in enumerate(block.statements):
            if not (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Call)
                and self.p.callee_name(stmt.src) == "fmt.errorf"
            ):
                continue
            call = stmt.src
            combo = stmt.dst
            if not combo.reg_vvars or len(combo.reg_vvars) != 2 or not call.args:
                continue
            check = self._nil_check_block(block, i)
            if check is None:
                continue
            arms = self._check_arms(check, combo)
            if arms is None:
                continue
            fallback, join = arms
            found = self._fallback_chain(fallback, join)
            if found is None:
                continue
            chain, join_copy = found
            if not self._is_errors_new_of(chain, call.args[0]):
                continue
            self._drop_fallback(check, chain + ([join_copy] if join_copy is not None else []), join)
            # keep the target (prototype, variadic args); only the printed name changes
            tags = {**call.tags, CALLEE_NAME_TAG: "fmt.Errorf"}
            block.statements[i] = Assignment(
                stmt.idx, combo, Call(call.idx, call.target, list(call.args), bits=call.bits, **tags), **stmt.tags
            )
            return True
        return False

    def _nil_check_block(self, block: Block, call_idx: int) -> Block | None:
        """The block ending in the nil check: the call's own block or its only successor (a call ends a block)."""
        if call_idx == len(block.statements) - 2 and isinstance(block.statements[-1], ConditionalJump):
            return block
        if call_idx != len(block.statements) - 1 and not (
            call_idx == len(block.statements) - 2 and isinstance(block.statements[-1], Jump)
        ):
            return None
        succs = list(self.graph.successors(block))
        if len(succs) != 1 or self.graph.in_degree(succs[0]) != 1:
            return None
        succ = succs[0]
        body = [s for s in succ.statements if not isinstance(s, Label)]
        if len(body) == 1 and isinstance(body[0], ConditionalJump):
            return succ
        return None

    def _check_arms(self, check: Block, combo: VirtualVariable) -> tuple[Block, Block] | None:
        """(nil arm, non-nil arm) of ``if err.tab == nil``."""
        cond_jump = cast(ConditionalJump, check.statements[-1])  # see _nil_check_block
        cond = cond_jump.condition
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        a, b = cond.operands
        if isinstance(a, Const):
            a, b = b, a
        if not (isinstance(b, Const) and b.value_int == 0 and isinstance(a, VirtualVariable)):
            return None
        word_ids = {combo.varid, *(v.varid for v in cast("list[VirtualVariable]", combo.reg_vvars))}  # a 2-word combo
        a = self.p.values.resolve(a)
        if not (isinstance(a, VirtualVariable) and a.varid in word_ids):
            return None
        if not (isinstance(cond_jump.true_target, Const) and isinstance(cond_jump.false_target, Const)):
            return None
        t = self.p._block_by_addr_and_idx.get((cond_jump.true_target.value_int, cond_jump.true_target_idx))
        f = self.p._block_by_addr_and_idx.get((cond_jump.false_target.value_int, cond_jump.false_target_idx))
        if t is None or f is None or t is f:
            return None
        return (t, f) if cond.op == "CmpEQ" else (f, t)

    def _fallback_chain(self, start: Block, join: Block) -> tuple[list[Block], Block | None] | None:
        """
        The fallback blocks from ``start`` to ``join``, plus the copy of ``join`` the chain ends in when the join was
        duplicated (a phi-less copy only the chain reaches).
        """
        chain = []
        block = start
        while block is not join:
            if self._is_copy_of(block, join):
                return (chain, block) if chain else None
            if len(chain) >= _MAX_FALLBACK_BLOCKS or self.graph.in_degree(block) != 1:
                return None
            chain.append(block)
            succs = list(self.graph.successors(block))
            if len(succs) != 1:
                return None
            block = succs[0]
        return (chain, None) if chain else None

    def _is_copy_of(self, block: Block, join: Block) -> bool:
        if block.addr != join.addr or self.graph.in_degree(block) != 1 or self.graph.out_degree(block) != 0:
            return False
        body = [s for s in block.statements if not isinstance(s, Label)]
        other = [s for s in join.statements if not isinstance(s, Label)]
        return (
            len(body) == len(other)
            and not any(isinstance(s, Assignment) and isinstance(s.src, Phi) for s in body + other)
            and all(a.likes(b) for a, b in zip(body, other))
        )

    def _is_errors_new_of(self, chain: list[Block], fmt) -> bool:
        """The chain only builds ``&errorString{fmt}`` and its itab."""
        found = self._errors_new_in(chain)
        if found is None:
            return False
        ptr, length, others = found
        if others:
            return False
        if isinstance(fmt, StringLiteral):
            lit = self.p.values.literal(ptr, length)
            return lit is not None and lit.data == fmt.data
        s = self.p.values.string(ptr, length)
        return s is not None and self.p.values.same(s, fmt)

    def _errors_new_in(self, blocks: list[Block]) -> tuple[Expression, Expression, list[Statement]] | None:
        """
        (string ptr, string len, other statements) of the one errorString allocation in ``blocks``, with its two
        field stores; other statements are anything not part of that or a constant assignment / jump.
        """
        alloc = None
        stores: dict[int, Expression] = {}
        others = []
        for block in blocks:
            for stmt in block.statements:
                if isinstance(stmt, (Label, Jump)):
                    continue
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    if alloc is None and isinstance(stmt.src, Call) and self._is_error_string_alloc(stmt.src):
                        alloc = stmt.dst
                        continue
                    if isinstance(stmt.src, Const) or (
                        alloc is not None and isinstance(stmt.src, VirtualVariable) and stmt.src.varid == alloc.varid
                    ):
                        continue
                if isinstance(stmt, Store) and alloc is not None:
                    off = self._offset_from(stmt.addr, alloc)
                    if off is not None and off in (0, self.ws) and off not in stores and stmt.size == self.ws:
                        stores[off] = stmt.data
                        continue
                others.append(stmt)
        if alloc is None or len(stores) != 2:
            return None
        return stores[0], stores[self.ws], others

    def _is_error_string_alloc(self, call: Call) -> bool:
        rule = allocator(self.p.callee_name(call))
        if rule is None or rule[0] != "*" or rule[1] is None or not call.args or len(call.args) <= rule[1]:
            return False
        return self.p.type_name(call.args[rule[1]]) == ERROR_STRING

    @staticmethod
    def _offset_from(addr, base: VirtualVariable) -> int | None:
        if isinstance(addr, VirtualVariable):
            return 0 if addr.varid == base.varid else None
        if isinstance(addr, BinaryOp) and addr.op == "Add":
            x, k = addr.operands
            if isinstance(x, Const):
                x, k = k, x
            if isinstance(x, VirtualVariable) and x.varid == base.varid and isinstance(k, Const):
                return k.value_int
        return None

    def _drop_fallback(self, check: Block, chain: list[Block], join: Block) -> None:
        self.p.remove_jump_target(check, chain[0].addr, chain[0].idx)
        last = chain[-1]
        for dead in chain:
            self.graph.remove_node(dead)
            self.p._block_by_addr_and_idx.pop((dead.addr, dead.idx), None)
        gone = (last.addr, last.idx)
        replacements: dict[int, Expression] = {}
        new_stmts = []
        for stmt in join.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                entries = [(src, v) for src, v in stmt.src.src_and_vvars if src != gone]
                if len(entries) != len(stmt.src.src_and_vvars):
                    if len(entries) == 1 and entries[0][1] is not None:
                        replacements[cast(VirtualVariable, stmt.dst).varid] = entries[0][1]
                        continue
                    stmt = Assignment(
                        stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags), **stmt.tags
                    )
            new_stmts.append(stmt)
        join.statements = new_stmts
        if replacements:
            subst = builtin_rewriter._VVarSubstituter(replacements)
            for blk in self.graph.nodes:
                subst.walk(blk)

    #
    # errors.New
    #

    def _fold_errors_new(self, block: Block) -> bool:
        for i, stmt in enumerate(block.statements):
            if not (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and isinstance(stmt.src, Call)
                and self._is_error_string_alloc(stmt.src)
            ):
                continue
            # the field stores follow the allocation, in its block or (the call ending the block) the next one
            window = [(block, j) for j in range(i + 1, len(block.statements))]
            succs = list(self.graph.successors(block))
            if i >= len(block.statements) - 2 and len(succs) == 1 and self.graph.in_degree(succs[0]) == 1:
                window += [(succs[0], j) for j in range(len(succs[0].statements))]
            stores: dict[int, tuple[Block, int]] = {}
            for blk, j in window:
                s = blk.statements[j]
                if isinstance(s, Store):
                    off = self._offset_from(s.addr, stmt.dst)
                    if off is not None and off in (0, self.ws) and off not in stores and s.size == self.ws:
                        stores[off] = (blk, j)
                        if len(stores) == 2:
                            break
                        continue
                    break
                if isinstance(s, (Label, Jump)) or (
                    isinstance(s, Assignment) and isinstance(s.src, (Const, VirtualVariable))
                ):
                    continue
                break
            if len(stores) != 2:
                continue
            (pb, pj), (lb, lj) = stores[0], stores[self.ws]
            ptr, length = cast(Store, pb.statements[pj]).data, cast(Store, lb.statements[lj]).data
            s = self.p.values.string(ptr, length)
            if s is None:
                s = Struct(
                    self.p.manager.next_atom(),
                    "string",
                    OrderedDict(((0, ptr), (self.ws, length))),
                    OrderedDict((("ptr", 0), ("len", self.ws))),
                    2 * self.p.project.arch.bits,
                    **ptr.tags,
                )
            new = self.p.builtin(stmt.src, "errors.New", [s], go_result_type=f"*{ERROR_STRING}", arg_types=["string"])
            block.statements[i] = Assignment(stmt.idx, stmt.dst, new, **stmt.tags)
            for blk, j in sorted(stores.values(), key=lambda x: -x[1]):
                blk.statements = blk.statements[:j] + blk.statements[j + 1 :]
            return True
        return False
