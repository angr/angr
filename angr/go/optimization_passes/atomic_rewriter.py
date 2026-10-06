"""
Fold the atomic instruction sequences the Go compiler emits back into the ``sync/atomic`` calls they came from.

On arm64 below GOARM64=v8.1 every atomic intrinsic is a dispatch on ``runtime.arm64HasATOMICS`` between an LSE
instruction and an LL/SC retry loop. libVEX lifts the LSE instruction as an alignment-fault exit, fences and a
compare-and-swap with a retry exit, all of which the structurer keeps as gotos. This pass drops the LL/SC arm, folds
the LSE sequence into one call and strips the fault exits and fences from atomic loads and stores. On x86 the
``lock xadd``, ``xchg`` and ``lock cmpxchg`` forms lift to the same compare-and-swap shape without the dispatch.
"""

from __future__ import annotations

import logging
from collections import defaultdict

import networkx

from angr.ailment import AILBlockRewriter, AILBlockViewer, Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Register,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import (
    CAS,
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Statement,
    Store,
)
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction

l = logging.getLogger(__name__)

_FENCE = "MBusEvent-Imbe_Fence"
_LLSC = ("LDle-Linked", "STle-Cond")
_ALIGN_MASKS = frozenset({1, 3, 7, 15})
# sync/atomic names by operation and width; And/Or take a mask, so they get the unsigned flavors
_NAMES = {
    ("add", 32): "atomic.AddInt32",
    ("add", 64): "atomic.AddInt64",
    ("swap", 32): "atomic.SwapInt32",
    ("swap", 64): "atomic.SwapInt64",
    ("swap", 8): "atomic.Swap8",
    ("and", 32): "atomic.AndUint32",
    ("and", 64): "atomic.AndUint64",
    ("and", 8): "atomic.And8",
    ("or", 32): "atomic.OrUint32",
    ("or", 64): "atomic.OrUint64",
    ("or", 8): "atomic.Or8",
}
# the compare-and-swap keeps returning the old value until GoAtomicCasFolder sees how the value is compared
CAS_OLD = "atomic_compare_exchange"


def _result_type(name: str, bits: int) -> str:
    if "Uint" in name or bits == 8:
        return f"uint{bits}"
    return f"int{bits}"


def _children(expr: Expression) -> list[Expression]:
    if isinstance(expr, (Convert, UnaryOp)):
        return [expr.operand]
    if isinstance(expr, BinaryOp):
        return list(expr.operands)
    if isinstance(expr, Load):
        return [expr.addr]
    if isinstance(expr, ITE):
        return [expr.cond, expr.iftrue, expr.iffalse]
    if isinstance(expr, Call):
        return list(expr.args or [])
    return []


def _const_value(expr) -> int | None:
    return expr.value if isinstance(expr, Const) else None


class _TmpReplacer(AILBlockRewriter):
    """Replace every read of one tmp by an expression."""

    def __init__(self, tmp_idx: int, replacement: Expression):
        super().__init__(update_block=False)
        self._tmp_idx = tmp_idx
        self._replacement = replacement

    def _handle_Tmp(self, expr_idx, expr, stmt_idx, stmt, block):
        return self._replacement if expr.tmp_idx == self._tmp_idx else expr


class _Values:
    """
    Values of tmps and registers inside one raw-AIL block, by statement position: a tmp is defined once, a register
    holds the last write before the reading statement, so a value found through a register is resolved at the
    position of that write (x86 copies the add operand through a register the instruction then overwrites).
    """

    _COPIES = (Convert, Tmp, Register)

    def __init__(self, stmts: list[Statement]):
        self.stmts = stmts
        self.tmp_def: dict[int, int] = {}
        self.reg_writes: dict[int, list[int]] = defaultdict(list)
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, Assignment):
                if isinstance(stmt.dst, Tmp):
                    self.tmp_def[stmt.dst.tmp_idx] = i
                elif isinstance(stmt.dst, Register):
                    self.reg_writes[stmt.dst.reg_offset].append(i)

    def _step(self, expr: Expression, pos: int, copies_only: bool) -> tuple[Expression, int] | None:
        if isinstance(expr, Convert):
            return expr.operand, pos
        if isinstance(expr, Tmp):
            i = self.tmp_def.get(expr.tmp_idx)
        elif isinstance(expr, Register):
            i = next((w for w in reversed(self.reg_writes.get(expr.reg_offset, ())) if w < pos), None)
        else:
            return None
        if i is None:
            return None
        src = self.stmts[i].src
        if copies_only and not isinstance(src, self._COPIES):
            return None
        return src, i

    def resolve(self, expr: Expression, pos: int) -> tuple[Expression, int]:
        """The expression producing the value of ``expr`` read at statement ``pos``, and where it lives."""
        for _ in range(64):
            nxt = self._step(expr, pos, False)
            if nxt is None:
                break
            expr, pos = nxt
        return expr, pos

    def is_tmp(self, expr: Expression, pos: int, tmp: Tmp) -> bool:
        """``expr`` read at ``pos`` is ``tmp``, possibly through conversions and tmp or register copies."""
        for _ in range(64):
            if isinstance(expr, Tmp) and expr.tmp_idx == tmp.tmp_idx:
                return True
            nxt = self._step(expr, pos, True)
            if nxt is None:
                return False
            expr, pos = nxt
        return False

    def mentions_tmp(self, expr: Expression, tmp: Tmp) -> bool:
        stack = [expr]
        seen = set()
        while stack:
            e = stack.pop()
            if isinstance(e, Tmp):
                if e.tmp_idx == tmp.tmp_idx:
                    return True
                if e.tmp_idx in self.tmp_def and e.tmp_idx not in seen:
                    seen.add(e.tmp_idx)
                    stack.append(self.stmts[self.tmp_def[e.tmp_idx]].src)
                continue
            stack.extend(_children(e))
        return False

    def same(self, a: Expression, pos_a: int, b: Expression, pos_b: int) -> bool:
        return self.same_resolved(self.resolve(a, pos_a), self.resolve(b, pos_b))

    @staticmethod
    def same_resolved(a: tuple[Expression, int], b: tuple[Expression, int], negated: bool = False) -> bool:
        """``negated``: b must be the negation of a (a subtraction of the operand)."""
        (ra, pa), (rb, pb) = a, b
        if isinstance(ra, Const) and isinstance(rb, Const):
            mask = (1 << min(ra.bits, rb.bits)) - 1
            vb = -rb.value if negated else rb.value
            return (ra.value & mask) == (vb & mask)
        if negated:
            return False
        if pa == pb and ra.likes(rb):
            # the same expression at the same place (an address computed once for the load and the swap)
            return True
        if isinstance(ra, Register) and isinstance(rb, Register):
            # both are the value the register held on block entry
            return ra.reg_offset == rb.reg_offset and ra.bits == rb.bits
        if isinstance(ra, Tmp) and isinstance(rb, Tmp):
            return ra.tmp_idx == rb.tmp_idx
        return False


class GoAtomicRewriter(OptimizationPass, CFGTransformationMixin):
    """
    See the module docstring. Runs on the raw AIL, where the lifted shape of every instruction is exact.
    """

    ARCHES = ["AARCH64", "AMD64", "X86"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Fold atomic instruction sequences into sync/atomic calls"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        # the Go pass list is not filtered by ARCHES
        return self.project.is_go_binary and self.project.arch.name in self.ARCHES, None

    def _analyze(self, cache=None):
        changed = self._drop_llsc_arms() if self.project.arch.name == "AARCH64" else False
        for block in list(self._graph.nodes):
            if self._rewrite_block(block):
                changed = True
        if changed:
            self.out_graph = self._graph

    #
    # the arm64HasATOMICS dispatch
    #

    def _drop_llsc_arms(self) -> bool:
        entry = self._block_by_addr_and_idx.get((self._func.addr, None))
        if entry is None:
            return False
        before = networkx.descendants(self._graph, entry) | {entry}
        dropped = False
        for block in list(self._graph.nodes):
            if not block.statements or not isinstance(block.statements[-1], ConditionalJump):
                continue
            if not self._is_flag_test(block.statements):
                continue
            succs = list(self._graph.successors(block))
            if len(succs) != 2:
                continue
            kinds = {self._arm_kind(succ): succ for succ in succs}
            if set(kinds) != {"llsc", "lse"}:
                continue
            llsc = kinds["llsc"]
            if self.remove_jump_target(block, llsc.addr, llsc.idx):
                l.debug("Dropped the LL/SC arm at %#x of %s", llsc.addr, self._func.name)
                dropped = True
        if dropped:
            after = networkx.descendants(self._graph, entry) | {entry}
            for node in [n for n in before if n not in after and n in self._graph]:
                self._graph.remove_node(node)
                self._block_by_addr_and_idx.pop((node.addr, node.idx), None)
        return dropped

    @staticmethod
    def _is_flag_test(stmts: list[Statement]) -> bool:
        # tbz on a loaded byte: (Conv(8->64, Load(size=1)) & 1) == 0; the arms say whether it is the LSE flag
        values = _Values(stmts)
        cond, pos = values.resolve(stmts[-1].condition, len(stmts))
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE") and _const_value(cond.operands[1]) == 0):
            return False
        test, pos = values.resolve(cond.operands[0], pos)
        if not (isinstance(test, BinaryOp) and test.op == "And" and _const_value(test.operands[1]) == 1):
            return False
        loaded, _ = values.resolve(test.operands[0], pos)
        return isinstance(loaded, Load) and loaded.size == 1

    def _arm_kind(self, start: Block) -> str | None:
        seen = {start}
        frontier = [start]
        for _ in range(3):
            nxt = []
            for block in frontier:
                for stmt in block.statements:
                    if isinstance(stmt, CAS):
                        return "lse"
                    if isinstance(stmt, DirtyStatement) and any(m in stmt.dirty.callee for m in _LLSC):
                        return "llsc"
                for succ in self._graph.successors(block):
                    if succ not in seen:
                        seen.add(succ)
                        nxt.append(succ)
            frontier = nxt
        return None

    #
    # the LSE sequence
    #

    def _rewrite_block(self, block: Block) -> bool:
        stmts = list(block.statements)
        values = _Values(stmts)
        if not any(
            isinstance(s, CAS) or self._is_fence(s) or self._is_align_check(s, i, values) for i, s in enumerate(stmts)
        ):
            return False
        k = 0
        while k < len(stmts):
            if isinstance(stmts[k], CAS):
                folded = self._fold_cas(stmts, k)
                if folded is not None:
                    stmts = folded
            k += 1
        values = _Values(stmts)
        stmts = [s for i, s in enumerate(stmts) if not self._is_fence(s) and not self._is_align_check(s, i, values)]
        block.statements = stmts
        # the fault and retry exits were the only jumps back to the block itself
        if self._graph.has_edge(block, block) and not self._jumps_to(stmts, block.addr):
            self._graph.remove_edge(block, block)
        return True

    def _fold_cas(self, stmts: list[Statement], k: int) -> list[Statement] | None:
        cas = stmts[k]
        assert isinstance(cas, CAS)
        if cas.old_hi is not None or not isinstance(cas.old_lo, Tmp):
            return None
        values = _Values(stmts)
        bits = cas.bits
        tags = dict(cas.tags)
        expd, expd_pos = values.resolve(cas.expd_lo, k)
        new = list(stmts)
        if (
            isinstance(expd, Load)
            and isinstance(cas.expd_lo, Tmp)
            and stmts[expd_pos].tags.get("ins_addr") == tags.get("ins_addr")
            and values.same(expd.addr, expd_pos, cas.addr, k)
        ):
            # read-modify-write: the instruction itself loaded the expected value (a compare-and-swap loop the
            # compiler wrote out loads it in an earlier instruction and stays a compare-and-swap)
            kind, operand, operand_pos = self._classify(cas, k, values)
            name = _NAMES.get((kind, bits)) if kind is not None else None
            if name is None or operand is None:
                return None
            if kind == "and":
                operand = self._undo_double_negation(operand, operand_pos, values)
            operand_value = values.resolve(operand, operand_pos)
            operand = self._to_bits(operand, bits)
            call = Call(
                self.manager.next_atom(),
                name,
                [cas.addr, operand],
                bits=bits,
                go_result_type=_result_type(name, bits),
                go_atomic=kind,
                is_prototype_guessed=False,
                **tags,
            )
            # after a successful swap the loaded value and the old slot are the same; arm64 reads the result from
            # the slot and x86 from the load, so the loaded value's uses after the swap read the slot instead
            new[k] = Assignment(cas.idx, cas.old_lo, call, **tags)
            replacer = _TmpReplacer(cas.expd_lo.tmp_idx, cas.old_lo)
            for j in range(k + 1, len(new)):
                new[j] = replacer.walk_statement(new[j], None, j)
            if kind == "add" and not self._fold_add_result(new, k, cas.old_lo, operand_value):
                # no following add, so the old value is wanted while the Go call returns the new one
                new[k] = Assignment(
                    cas.idx,
                    cas.old_lo,
                    BinaryOp(self.manager.next_atom(), "Sub", [call, operand], False, bits=bits, **tags),
                    **tags,
                )
        else:
            call = Call(
                self.manager.next_atom(),
                CAS_OLD,
                [cas.addr, self._to_bits(cas.expd_lo, bits), self._to_bits(cas.data_lo, bits)],
                bits=bits,
                go_result_type=_result_type(CAS_OLD, bits),
                go_atomic="cas",
                is_prototype_guessed=False,
                **tags,
            )
            new[k] = Assignment(cas.idx, cas.old_lo, call, **tags)
        return [s for j, s in enumerate(new) if j == k or not self._is_retry_exit(s, cas)]

    @staticmethod
    def _classify(cas: CAS, k: int, values: _Values) -> tuple[str | None, Expression | None, int]:
        """The operation and its operand (with the position the operand expression lives at)."""
        data, pos = values.resolve(cas.data_lo, k)
        if isinstance(data, BinaryOp) and data.op in ("Add", "And", "Or"):
            a, b = data.operands
            if values.is_tmp(a, pos, cas.expd_lo):
                return data.op.lower(), b, pos
            if values.is_tmp(b, pos, cas.expd_lo):
                return data.op.lower(), a, pos
            return None, None, pos
        if not values.mentions_tmp(cas.data_lo, cas.expd_lo):
            return "swap", cas.data_lo, k
        return None, None, k

    @staticmethod
    def _undo_double_negation(operand: Expression, pos: int, values: _Values) -> Expression:
        # LDCLR clears the bits of ~mask; the compiler emits MVN for it, so ~~mask reads as the mask again
        outer, pos = values.resolve(operand, pos)
        if isinstance(outer, UnaryOp) and outer.op in ("Not", "BitwiseNeg"):
            inner, _ = values.resolve(outer.operand, pos)
            if (
                isinstance(inner, UnaryOp)
                and inner.op in ("Not", "BitwiseNeg")
                and not isinstance(inner.operand, Register)
            ):
                return inner.operand
        return operand

    def _fold_add_result(self, stmts: list[Statement], k: int, old: Tmp, operand: tuple[Expression, int]) -> bool:
        """
        Go follows the fetch-and-add (LDADDAL, lock xadd) with an add of the same operand in the next instruction:
        the register ends up holding what atomic.Add returns, so that add becomes a copy of the call's value.
        """
        ins_addr = stmts[k].tags.get("ins_addr")
        if ins_addr is None:
            return False
        values = _Values(stmts)
        next_ins = None
        for j in range(k + 1, len(stmts)):
            stmt = stmts[j]
            addr = stmt.tags.get("ins_addr", ins_addr)
            if addr != ins_addr:
                if next_ins is None:
                    next_ins = addr
                elif addr != next_ins:
                    break
            src = _strip_converts(stmt.src) if isinstance(stmt, Assignment) else None
            if not (isinstance(src, BinaryOp) and src.op in ("Add", "Sub")):
                continue
            a, b = src.operands
            for x, y in ((a, b), (b, a)) if src.op == "Add" else ((a, b),):
                if values.is_tmp(x, j, old) and values.same_resolved(
                    values.resolve(y, j), operand, negated=src.op == "Sub"
                ):
                    stmts[j] = Assignment(stmt.idx, stmt.dst, self._to_bits(x, stmt.dst.bits), **stmt.tags)
                    return True
        return False

    #
    # statement predicates
    #

    @staticmethod
    def _is_fence(stmt: Statement) -> bool:
        return isinstance(stmt, DirtyStatement) and stmt.dirty.callee == _FENCE

    @staticmethod
    def _is_align_check(stmt: Statement, pos: int, values: _Values) -> bool:
        # if (addr & mask) != 0 goto <this instruction>: the SIGBUS exit of an aligned-only access
        if not isinstance(stmt, ConditionalJump) or _const_value(stmt.true_target) != stmt.tags.get("ins_addr"):
            return False
        cond, pos = values.resolve(stmt.condition, pos)
        if not (isinstance(cond, BinaryOp) and cond.op == "CmpNE" and _const_value(cond.operands[1]) == 0):
            return False
        test, _ = values.resolve(cond.operands[0], pos)
        return isinstance(test, BinaryOp) and test.op == "And" and _const_value(test.operands[1]) in _ALIGN_MASKS

    @staticmethod
    def _is_retry_exit(stmt: Statement, cas: CAS) -> bool:
        if not isinstance(stmt, ConditionalJump) or stmt.tags.get("ins_addr") != cas.tags.get("ins_addr"):
            return False
        return _const_value(stmt.true_target) == cas.tags.get("ins_addr")

    @staticmethod
    def _jumps_to(stmts: list[Statement], addr: int) -> bool:
        for stmt in stmts:
            if isinstance(stmt, Jump) and _const_value(stmt.target) == addr:
                return True
            if isinstance(stmt, ConditionalJump) and addr in (
                _const_value(stmt.true_target),
                _const_value(stmt.false_target),
            ):
                return True
        return False

    def _to_bits(self, expr: Expression, bits: int) -> Expression:
        if expr.bits == bits:
            return expr
        return Convert(self.manager.next_atom(), expr.bits, bits, False, expr, **expr.tags)


def _cas_call(expr: Expression) -> Call | None:
    call = _strip_converts(expr)
    if isinstance(call, Call) and call.tags.get("go_atomic") == "cas" and len(call.args or ()) == 3:
        return call
    return None


class _CasUseCensus(AILBlockViewer):
    """
    Old values assigned to a vvar (``v = atomic_compare_exchange(p, old, new)``): which of those vvars are only ever
    compared against the expected value, so the assignment can hold the bool instead.
    """

    def __init__(self, calls: dict[int, Call]):
        super().__init__()
        self.calls = calls
        self.uses: dict[int, int] = defaultdict(int)
        self.cmp_uses: dict[int, int] = defaultdict(int)

    @staticmethod
    def assigned_calls(graph) -> dict[int, Call]:
        # the old value may be widened onto the register (Conv(32->64, call))
        calls = {}
        for block in graph.nodes:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    call = _cas_call(stmt.src)
                    if call is not None:
                        calls[stmt.dst.varid] = call
        return calls

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in self.calls:
            return None
        return super()._handle_Assignment(stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.uses[expr.varid] += 1

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.op in ("CmpEQ", "CmpNE"):
            a, b = expr.operands
            for side, other in ((a, b), (b, a)):
                vvar = _strip_converts(side)
                if (
                    isinstance(vvar, VirtualVariable)
                    and vvar.varid in self.calls
                    and _same_operand(other, self.calls[vvar.varid].args[1])
                ):
                    self.cmp_uses[vvar.varid] += 1
        return super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def foldable(self) -> set[int]:
        return {v for v in self.calls if self.uses[v] > 0 and self.uses[v] == self.cmp_uses[v]}


class _CasFolder(AILBlockRewriter):
    """Comparisons of the old value against the expected one become the bool the Go call returns."""

    def __init__(self, owner: GoAtomicCasFolder, assigned: dict[int, Call], single_use: set[int]):
        super().__init__()
        self._o = owner
        self._assigned = assigned
        # a vvar compared exactly once: the call goes into the comparison and the assignment is dropped
        self._single_use = single_use
        self.changed = False

    def _handle_Assignment(self, stmt_idx, stmt, block):
        if (
            isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.varid in self._assigned
            and stmt.dst.varid not in self._single_use
            and _cas_call(stmt.src) is not None
            and _cas_call(stmt.src).idx == self._assigned[stmt.dst.varid].idx
        ):
            # the vvar holds the bool, widened to its own size
            self.changed = True
            call = self._assigned[stmt.dst.varid]
            folded = self._o.cas_bool(call)
            src = Convert(self._o.manager.next_atom(), 1, stmt.dst.bits, False, folded, **call.tags)
            return Assignment(stmt.idx, stmt.dst, src, **stmt.tags)
        return super()._handle_Assignment(stmt_idx, stmt, block)

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        cmp = new_expr if new_expr is not None else expr
        if cmp.op not in ("CmpEQ", "CmpNE"):
            return new_expr
        a, b = cmp.operands
        for side, other in ((a, b), (b, a)):
            call = _cas_call(side)
            if call is not None and _same_operand(other, call.args[1]):
                self.changed = True
                folded = self._o.cas_bool(call)
                if cmp.op == "CmpEQ":
                    return folded
                return UnaryOp(self._o.manager.next_atom(), "Not", folded, bits=1, **cmp.tags)
            vvar = _strip_converts(side)
            if (
                isinstance(vvar, VirtualVariable)
                and vvar.varid in self._assigned
                and _same_operand(other, self._assigned[vvar.varid].args[1])
            ):
                self.changed = True
                if vvar.varid in self._single_use:
                    test = self._o.cas_bool(self._assigned[vvar.varid])
                else:
                    # the vvar now holds the bool: equal to the expected value means it is set (a conversion, so
                    # the rewritten test is not matched again)
                    test = Convert(self._o.manager.next_atom(), vvar.bits, 1, False, vvar, **cmp.tags)
                if cmp.op == "CmpEQ":
                    return test
                return UnaryOp(self._o.manager.next_atom(), "Not", test, bits=1, **cmp.tags)
        return new_expr

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        call = new_expr if new_expr is not None else expr
        if call.tags.get("go_atomic") is not None:
            self._o.set_prototype(call)
        return new_expr

    def _handle_SideEffectStatement(self, stmt_idx, stmt, block):
        # x86 has no atomic store: it is an xchg whose old value nobody reads, which is a store in the source
        new_stmt = super()._handle_SideEffectStatement(stmt_idx, stmt, block)
        cur = new_stmt if new_stmt is not None else stmt
        call = cur.expr
        if (
            isinstance(call, Call)
            and call.tags.get("go_atomic") == "swap"
            and cur.ret_expr is None
            and len(call.args or ()) == 2
        ):
            self.changed = True
            tags = {k: v for k, v in call.tags.items() if not k.startswith("go_") and k != "is_prototype_guessed"}
            return Store(
                cur.idx, call.args[0], call.args[1], call.bits // 8, self._o.project.arch.memory_endness, **tags
            )
        return new_stmt


def _strip_converts(expr: Expression) -> Expression:
    while isinstance(expr, Convert):
        expr = expr.operand
    return expr


def _same_operand(a: Expression, b: Expression) -> bool:
    a, b = _strip_converts(a), _strip_converts(b)
    if isinstance(a, Const) and isinstance(b, Const):
        mask = (1 << min(a.bits, b.bits)) - 1
        return (a.value & mask) == (b.value & mask)
    return a.likes(b)


class GoAtomicCasFolder(OptimizationPass):
    """
    Turn ``atomic_compare_exchange(p, old, new) == old`` into ``atomic.CompareAndSwap*(p, old, new)`` once the
    comparison is explicit, and give every synthesized atomic call its prototype.
    """

    ARCHES = ["AARCH64", "AMD64", "X86"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Fold compare-and-swap results into their bool"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        # the Go pass list is not filtered by ARCHES
        return self.project.is_go_binary and self.project.arch.name in self.ARCHES, None

    def _analyze(self, cache=None):
        census = _CasUseCensus(_CasUseCensus.assigned_calls(self._graph))
        for block in self._graph.nodes:
            census.walk(block)
        assigned = {v: census.calls[v] for v in census.foldable()}
        single_use = {v for v in assigned if census.uses[v] == 1}
        folder = _CasFolder(self, assigned, single_use)
        for block in list(self._graph.nodes):
            folder.walk(block)
        if single_use:
            for block in self._graph.nodes:
                kept = [
                    st
                    for st in block.statements
                    if not (
                        isinstance(st, Assignment)
                        and isinstance(st.dst, VirtualVariable)
                        and st.dst.varid in single_use
                    )
                ]
                if len(kept) != len(block.statements):
                    block.statements = kept
        if folder.changed:
            self.out_graph = self._graph

    @staticmethod
    def cas_bool(call: Call) -> Call:
        bits = call.bits
        tags = {k: v for k, v in call.tags.items() if k not in ("go_atomic", "go_result_type")}
        return Call(
            call.idx,
            f"atomic.CompareAndSwapInt{bits}",
            list(call.args),
            bits=1,
            go_atomic="cas_bool",
            go_elem_type=_result_type(CAS_OLD, bits),
            go_result_type="bool",
            **tags,
        )

    def set_prototype(self, call: Call) -> None:
        kind = call.tags.get("go_atomic")
        elem = call.tags.get("go_elem_type") or call.tags.get("go_result_type")
        result = call.tags.get("go_result_type")
        if elem is None or result is None:
            return
        try:
            types = self.kb.go_signatures
            argtys = [types.type(f"*{elem}")] + [types.type(elem)] * (2 if kind in ("cas", "cas_bool") else 1)
            proto = GoSimTypeFunction(argtys, types.type(result)).with_arch(self.project.arch)
            variable_map_of(self.manager).set_prototype(call, proto)
        except Exception:  # pylint:disable=broad-exception-caught
            l.debug("Could not type %s", call, exc_info=True)
