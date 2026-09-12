"""
Fold the arm64 atomic sequences the Go compiler emits back into the ``sync/atomic`` calls they were compiled from.

Below GOARM64=v8.1 every atomic intrinsic is a dispatch on ``runtime.arm64HasATOMICS`` between an LSE instruction
and an LL/SC retry loop. libVEX lifts the LSE instruction as an alignment-fault exit, fences and a compare-and-swap
with a retry exit, all of which the structurer keeps as gotos. This pass drops the LL/SC arm, folds the LSE sequence
into one call and strips the fault exits and fences from atomic loads and stores.
"""

from __future__ import annotations

import logging

import networkx

from angr.ailment import AILBlockRewriter, Block
from angr.ailment.expression import ITE, BinaryOp, Call, Const, Convert, Expression, Load, Register, Tmp, UnaryOp
from angr.ailment.statement import CAS, Assignment, ConditionalJump, DirtyStatement, Jump, Statement
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
        return [a for a in (expr.args or [])]
    return []


def _const_value(expr) -> int | None:
    return expr.value if isinstance(expr, Const) else None


class GoAtomicRewriter(OptimizationPass, CFGTransformationMixin):
    """
    See the module docstring. Runs on the raw AIL, where the lifted shape of every instruction is exact.
    """

    ARCHES = ["AARCH64"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_SSA_LEVEL0_TRANSFORMATION
    NAME = "Fold arm64 atomic sequences into sync/atomic calls"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        # the Go pass list is not filtered by ARCHES
        return self.project.is_go_binary and self.project.arch.name == "AARCH64", None

    def _analyze(self, cache=None):
        changed = self._drop_llsc_arms()
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

    def _is_flag_test(self, stmts: list[Statement]) -> bool:
        # tbz on a loaded byte: (Conv(8->64, Load(size=1)) & 1) == 0; the arms say whether it is the LSE flag
        cond = stmts[-1].condition
        defs, regs = self._tmp_defs(stmts), self._reg_defs(stmts, len(stmts))
        cond = self._resolve(cond, defs, regs)
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE") and _const_value(cond.operands[1]) == 0):
            return False
        test = self._resolve(cond.operands[0], defs, regs)
        if not (isinstance(test, BinaryOp) and test.op == "And" and _const_value(test.operands[1]) == 1):
            return False
        loaded = self._resolve(test.operands[0], defs, regs)
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
        defs = self._tmp_defs(stmts)
        if not any(isinstance(s, CAS) or self._is_fence(s) or self._is_align_check(s, defs) for s in stmts):
            return False
        k = 0
        while k < len(stmts):
            if isinstance(stmts[k], CAS):
                folded = self._fold_cas(stmts, k)
                if folded is not None:
                    stmts = folded
            k += 1
        stmts = [s for s in stmts if not self._is_fence(s) and not self._is_align_check(s, defs)]
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
        defs = self._tmp_defs(stmts[:k])
        bits = cas.bits
        tags = dict(cas.tags)
        expd = self._resolve(cas.expd_lo, defs)
        new = list(stmts)
        if isinstance(expd, Load) and self._same_value(expd.addr, cas.addr, defs):
            # read-modify-write: the expected value is what was just loaded
            kind, operand = self._classify(cas, defs)
            name = _NAMES.get((kind, bits)) if kind is not None else None
            if name is None or operand is None:
                return None
            if kind == "and":
                operand = self._undo_double_negation(operand, defs, self._reg_defs(stmts, k))
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
            new[k] = Assignment(cas.idx, cas.old_lo, call, **tags)
            if kind == "add" and not self._fold_add_result(new, k, cas.old_lo, operand):
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

    def _classify(self, cas: CAS, defs: dict[int, Expression]) -> tuple[str | None, Expression | None]:
        data = self._resolve(cas.data_lo, defs)
        if isinstance(data, BinaryOp) and data.op in ("Add", "And", "Or"):
            a, b = data.operands
            if self._is_tmp(a, cas.expd_lo, defs):
                return data.op.lower(), b
            if self._is_tmp(b, cas.expd_lo, defs):
                return data.op.lower(), a
            return None, None
        if not self._mentions_tmp(cas.data_lo, cas.expd_lo, defs):
            return "swap", cas.data_lo
        return None, None

    def _undo_double_negation(self, operand: Expression, defs, regs) -> Expression:
        # LDCLR clears the bits of ~mask; the compiler emits MVN for it, so ~~mask reads as the mask again
        outer = self._resolve(operand, defs, regs)
        if isinstance(outer, UnaryOp) and outer.op in ("Not", "BitwiseNeg"):
            inner = self._resolve(outer.operand, defs, regs)
            if (
                isinstance(inner, UnaryOp)
                and inner.op in ("Not", "BitwiseNeg")
                and not isinstance(inner.operand, Register)
            ):
                return inner.operand
        return operand

    def _fold_add_result(self, stmts: list[Statement], k: int, old: Tmp, operand: Expression) -> bool:
        # Go follows LDADDAL with `ADD Rs, Rt, Rt`: the register ends up holding what atomic.Add returns
        ins_addr = stmts[k].tags.get("ins_addr")
        defs = self._tmp_defs(stmts)
        operand = self._resolve(operand, defs, self._reg_defs(stmts, k))
        for j in range(k + 1, len(stmts)):
            stmt = stmts[j]
            if ins_addr is None or stmt.tags.get("ins_addr", ins_addr) > ins_addr + 4:
                break
            if not (isinstance(stmt, Assignment) and isinstance(stmt.src, BinaryOp) and stmt.src.op == "Add"):
                continue
            regs = self._reg_defs(stmts, j)
            a, b = stmt.src.operands
            for x, y in ((a, b), (b, a)):
                if self._is_tmp(x, old, defs, regs) and self._same_value(y, operand, defs, regs):
                    stmts[j] = Assignment(stmt.idx, stmt.dst, self._to_bits(x, stmt.dst.bits), **stmt.tags)
                    return True
        return False

    #
    # statement predicates
    #

    @staticmethod
    def _is_fence(stmt: Statement) -> bool:
        return isinstance(stmt, DirtyStatement) and stmt.dirty.callee == _FENCE

    def _is_align_check(self, stmt: Statement, defs: dict[int, Expression]) -> bool:
        # if (addr & mask) != 0 goto <this instruction>: the SIGBUS exit of an aligned-only access
        if not isinstance(stmt, ConditionalJump) or _const_value(stmt.true_target) != stmt.tags.get("ins_addr"):
            return False
        cond = self._resolve(stmt.condition, defs)
        if not (isinstance(cond, BinaryOp) and cond.op == "CmpNE" and _const_value(cond.operands[1]) == 0):
            return False
        test = self._resolve(cond.operands[0], defs)
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

    #
    # tmp resolution
    #

    @staticmethod
    def _tmp_defs(stmts) -> dict[int, Expression]:
        return {s.dst.tmp_idx: s.src for s in stmts if isinstance(s, Assignment) and isinstance(s.dst, Tmp)}

    @staticmethod
    def _reg_defs(stmts, upto: int) -> dict[int, Expression]:
        # the value each register holds right before statement `upto`
        regs: dict[int, Expression] = {}
        for stmt in stmts[:upto]:
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, Register):
                regs[stmt.dst.reg_offset] = stmt.src
        return regs

    @staticmethod
    def _resolve(
        expr: Expression, defs: dict[int, Expression], regs: dict[int, Expression] | None = None
    ) -> Expression:
        # look through conversions, tmps and in-block register copies to the expression that produces the value
        for _ in range(64):
            if isinstance(expr, Convert):
                expr = expr.operand
            elif isinstance(expr, Tmp) and expr.tmp_idx in defs:
                expr = defs[expr.tmp_idx]
            elif regs is not None and isinstance(expr, Register) and expr.reg_offset in regs:
                expr = regs[expr.reg_offset]
            else:
                break
        return expr

    @staticmethod
    def _is_tmp(
        expr: Expression, tmp: Tmp, defs: dict[int, Expression], regs: dict[int, Expression] | None = None
    ) -> bool:
        # the same tmp, possibly through conversions and tmp or register copies
        for _ in range(64):
            if isinstance(expr, Tmp) and expr.tmp_idx == tmp.tmp_idx:
                return True
            if isinstance(expr, Convert):
                expr = expr.operand
            elif isinstance(expr, Tmp) and isinstance(defs.get(expr.tmp_idx), (Convert, Tmp, Register)):
                expr = defs[expr.tmp_idx]
            elif (
                regs is not None
                and isinstance(expr, Register)
                and isinstance(regs.get(expr.reg_offset), (Convert, Tmp, Register))
            ):
                expr = regs[expr.reg_offset]
            else:
                return False
        return False

    def _mentions_tmp(self, expr: Expression, tmp: Tmp, defs: dict[int, Expression]) -> bool:
        stack = [expr]
        seen = set()
        while stack:
            e = stack.pop()
            if isinstance(e, Tmp):
                if e.tmp_idx == tmp.tmp_idx:
                    return True
                if e.tmp_idx in defs and e.tmp_idx not in seen:
                    seen.add(e.tmp_idx)
                    stack.append(defs[e.tmp_idx])
                continue
            stack.extend(_children(e))
        return False

    def _same_value(
        self, a: Expression, b: Expression, defs: dict[int, Expression], regs: dict[int, Expression] | None = None
    ) -> bool:
        ra, rb = self._resolve(a, defs, regs), self._resolve(b, defs, regs)
        if isinstance(ra, Register) and isinstance(rb, Register):
            return ra.reg_offset == rb.reg_offset and ra.bits == rb.bits
        if isinstance(ra, Const) and isinstance(rb, Const):
            return ra.value == rb.value
        if isinstance(ra, Tmp) and isinstance(rb, Tmp):
            return ra.tmp_idx == rb.tmp_idx
        return False

    def _to_bits(self, expr: Expression, bits: int) -> Expression:
        if expr.bits == bits:
            return expr
        return Convert(self.manager.next_atom(), expr.bits, bits, False, expr, **expr.tags)


class _CasFolder(AILBlockRewriter):
    """Comparisons of the old value against the expected one become the bool the Go call returns."""

    def __init__(self, owner: GoAtomicCasFolder):
        super().__init__()
        self._o = owner
        self.changed = False

    def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
        cmp = new_expr if new_expr is not None else expr
        if cmp.op not in ("CmpEQ", "CmpNE"):
            return new_expr
        a, b = cmp.operands
        for side, other in ((a, b), (b, a)):
            call = _strip_converts(side)
            if not (isinstance(call, Call) and call.tags.get("go_atomic") == "cas" and len(call.args or ()) == 3):
                continue
            if not _same_operand(other, call.args[1]):
                continue
            self.changed = True
            folded = self._o.cas_bool(call)
            if cmp.op == "CmpEQ":
                return folded
            return UnaryOp(self._o.manager.next_atom(), "Not", folded, bits=1, **cmp.tags)
        return new_expr

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        new_expr = super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)
        call = new_expr if new_expr is not None else expr
        if call.tags.get("go_atomic") is not None:
            self._o.set_prototype(call)
        return new_expr


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

    ARCHES = ["AARCH64"]
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Fold compare-and-swap results into their bool"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        self.analyze()

    def _check(self):
        # the Go pass list is not filtered by ARCHES
        return self.project.is_go_binary and self.project.arch.name == "AARCH64", None

    def _analyze(self, cache=None):
        folder = _CasFolder(self)
        for block in list(self._graph.nodes):
            folder.walk(block)
        if folder.changed:
            self.out_graph = self._graph

    def cas_bool(self, call: Call) -> Call:
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
