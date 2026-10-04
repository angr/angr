"""
Stack initializations the compiler expands inline.

``make(map[K]V)`` of a map that does not escape (go1.24+ swiss maps): the compiler places the ``maps.Map`` header and
one group on the stack, zeroes both, marks the group's control word empty, points ``dirPtr`` at the group and seeds
the hash with ``runtime.rand()``. The whole sequence becomes ``m := make(map[K]V)`` and ``&header`` becomes ``m``.

Large zero values are cleared by a loop over the variable (plus stores for the tail); that is one ``memset``.
"""

from __future__ import annotations

import contextlib
import logging
from typing import TYPE_CHECKING

import networkx

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import BinaryOp, Call, Const, Expression, Phi, UnaryOp, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, SideEffectStatement, Store
from angr.analyses.decompiler.mixins.cfg_transformation_mixin import CFGTransformationMixin
from angr.analyses.decompiler.optimization_passes.optimization_pass import OptimizationPass, OptimizationPassStage
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.go.sim_type import GoSimTypeFunction, GoSimTypeMap
from angr.go.utils.names import call_target_name
from angr.go.utils.types import go_type_at, go_type_name_at
from angr.utils.go_runtime import normalize_go_func_name

if TYPE_CHECKING:
    from angr.ailment.block import Block

l = logging.getLogger(__name__)

_CTRL_EMPTY = 0x8080808080808080
_HEADER_SIZE = 48  # internal/runtime/maps.Map on 64-bit targets
_SLOT_INDIRECT = 128  # larger keys/elems are stored through a pointer


def _align(n: int, a: int) -> int:
    return (n + a - 1) // a * a if a > 1 else n


def _stack_ref(expr: Expression) -> VirtualVariable | None:
    if (
        isinstance(expr, UnaryOp)
        and expr.op == "Reference"
        and isinstance(expr.operand, VirtualVariable)
        and expr.operand.was_stack
    ):
        return expr.operand
    return None


class _Index(AILBlockViewer):
    """Use counts of every variable and the stack variables whose address is taken (with where)."""

    def __init__(self):
        super().__init__()
        self.counts: dict[int, int] = {}
        self.refs: dict[int, list] = {}  # varid -> [(block, stmt_idx)]
        self.calls: list[Call] = []

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        self.counts[expr.varid] = self.counts.get(expr.varid, 0) + 1

    def _handle_Phi(self, expr_idx, expr: Phi, stmt_idx, stmt, block):
        for _, vvar in expr.src_and_vvars:
            if vvar is not None:
                self.counts[vvar.varid] = self.counts.get(vvar.varid, 0) + 1

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        ref = _stack_ref(expr)
        if ref is not None:
            self.refs.setdefault(ref.varid, []).append((block, stmt_idx))
        super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        self.calls.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


class _RefReplacer(AILBlockRewriter):
    def __init__(self, varids: set[int], new: VirtualVariable):
        super().__init__()
        self._varids = varids
        self._new = new

    def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
        ref = _stack_ref(expr)
        if ref is not None and ref.varid in self._varids:
            return self._new
        return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)


class _ZeroLoop:
    """A self-loop clearing ``iters * stride`` bytes from ``ptr0`` (``ptr_final`` points past them)."""

    __slots__ = ("body", "exit", "iters", "pred", "ptr0", "ptr_final", "stride")

    def __init__(self, body, pred, exit_, ptr0, ptr_final, stride, iters):
        self.body = body
        self.pred = pred
        self.exit = exit_
        self.ptr0 = ptr0
        self.ptr_final = ptr_final
        self.stride = stride
        self.iters = iters


class _StackScan:
    """Stack-variable definitions, use counts and the zero-filling loops of a function graph."""

    def __init__(self, pass_):
        self.p = pass_
        self.graph = pass_._graph
        self.defs: dict[int, tuple[Block, int, Assignment]] = {}
        self.index = _Index()

    def _reindex(self) -> None:
        self.defs = {}
        self.index = _Index()
        for block in self.graph.nodes:
            self.index.walk(block)
            for i, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self.defs[stmt.dst.varid] = (block, i, stmt)

    def _zero_loops(self):
        for block in list(self.graph.nodes):
            if self.graph.has_edge(block, block):
                loop = self._zero_loop(block)
                if loop is not None:
                    yield loop

    def _zero_loop(self, body: Block) -> _ZeroLoop | None:
        preds = [b for b in self.graph.predecessors(body) if b is not body]
        succs = [b for b in self.graph.successors(body) if b is not body]
        if len(preds) != 1 or len(succs) != 1 or self.graph.in_degree(body) != 2:
            return None
        pred, exit_ = preds[0], succs[0]
        last = pred.statements[-1] if pred.statements else None
        if not (isinstance(last, Jump) and isinstance(last.target, Const) and last.target.value_int == body.addr):
            return None
        phis = {}
        covered: list[tuple[int, int]] = []
        stmts = body.statements
        k = 0
        while k < len(stmts) and isinstance(stmts[k], Assignment) and isinstance(stmts[k].src, Phi):
            st = stmts[k]
            srcs = dict(st.src.src_and_vvars)
            if set(srcs) != {(pred.addr, pred.idx), (body.addr, body.idx)}:
                return None
            phis[st.dst.varid] = (srcs[(pred.addr, pred.idx)], srcs[(body.addr, body.idx)])
            k += 1
        if len(phis) != 2:
            return None
        offsets: dict[int, int] = {}  # pointer variables -> offset from the loop's pointer

        def ptr_off(e):
            if isinstance(e, VirtualVariable):
                return offsets.get(e.varid)
            base, off = _base_off(e)
            if base is e:
                return None
            inner = ptr_off(base)
            return None if inner is None else inner + off

        # the pointer is the phi whose next value is itself plus a constant
        ptr_phi = None
        for varid in phis:
            offsets = {varid: 0}
            for st in stmts[k:]:
                if isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable):
                    off = ptr_off(st.src)
                    if off is not None:
                        offsets[st.dst.varid] = off
            nxt = phis[varid][1]
            if nxt is not None and (offsets.get(nxt.varid) or 0) > 0:
                ptr_phi = varid
                break
        if ptr_phi is None:
            return None
        cnt_phi = next(v for v in phis if v != ptr_phi)
        offsets = {ptr_phi: 0}
        counts = {cnt_phi: 0}  # counter variables -> decrements so far
        cond = None
        for st in stmts[k:]:
            if isinstance(st, Label):
                continue
            if isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable):
                off = ptr_off(st.src)
                if off is not None:
                    offsets[st.dst.varid] = off
                    continue
                src = st.src
                if (
                    isinstance(src, BinaryOp)
                    and src.op == "Sub"
                    and isinstance(src.operands[0], VirtualVariable)
                    and src.operands[0].varid in counts
                    and _value(src.operands[1]) == 1
                ):
                    counts[st.dst.varid] = counts[src.operands[0].varid] + 1
                    continue
                return None
            if isinstance(st, Store) and _value(st.data) == 0:
                off = ptr_off(st.addr)
                if off is None:
                    return None
                covered.append((off, off + st.size))
                continue
            if isinstance(st, SideEffectStatement) and isinstance(st.expr, Call) and st.expr.target == "memset":
                args = list(st.expr.args or [])
                off = ptr_off(args[0]) if len(args) == 3 else None
                if off is None or _value(args[1]) != 0 or _value(args[2]) is None:
                    return None
                covered.append((off, off + _value(args[2])))
                continue
            if isinstance(st, ConditionalJump) and st is stmts[-1]:
                cond = st
                continue
            return None
        nxt_ptr, nxt_cnt = phis[ptr_phi][1], phis[cnt_phi][1]
        if nxt_ptr is None or nxt_cnt is None or counts.get(nxt_cnt.varid) != 1:
            return None
        stride = offsets.get(nxt_ptr.varid)
        if not stride or not _covers(covered, stride):
            return None
        # the trip count: the counter starts at a constant and the loop runs while counter != c
        cnt0_def = self.defs.get(phis[cnt_phi][0].varid) if phis[cnt_phi][0] is not None else None
        cnt0 = _value(cnt0_def[2].src) if cnt0_def is not None else None
        if cnt0 is None or cond is None:
            return None
        c = cond.condition
        if not (isinstance(c, BinaryOp) and c.op in ("CmpEQ", "CmpNE") and isinstance(c.operands[1], Const)):
            return None
        x = c.operands[0]
        if not (isinstance(x, VirtualVariable) and x.varid in counts):
            return None
        loops_on = cond.true_target if c.op == "CmpNE" else cond.false_target
        if not (isinstance(loops_on, Const) and loops_on.value_int == body.addr):
            return None
        iters = cnt0 - c.operands[1].value_int + (1 - counts[x.varid])
        if iters < 1:
            return None
        ptr0 = phis[ptr_phi][0]
        ptr0_def = self.defs.get(ptr0.varid) if ptr0 is not None else None
        ref = _stack_ref(ptr0_def[2].src) if ptr0_def is not None else None
        return _ZeroLoop(body, pred, exit_, (ptr0, ref), nxt_ptr, stride, iters)

    def _tail_stores(self, loop: _ZeroLoop) -> list[tuple[int, int, int]] | None:
        """
        The exit block's zero stores through the loop's final pointer, as (statement index, start, end) relative to
        the loop's first byte; None when the loop's variables are read in any other way after it.
        """
        out = []
        start = loop.iters * loop.stride
        final = loop.ptr_final.varid
        loop_vars = {
            st.dst.varid
            for st in loop.body.statements
            if isinstance(st, Assignment) and isinstance(st.dst, VirtualVariable)
        }
        for i, st in enumerate(loop.exit.statements):
            if isinstance(st, Store):
                base, off = _base_off(st.addr)
                if isinstance(base, VirtualVariable) and base.varid == final:
                    if _value(st.data) != 0:
                        return None
                    out.append((i, start + off, start + off + st.size))
        uses = sum(self.index.counts.get(v, 0) for v in loop_vars)
        inside = _Index()
        inside.walk(loop.body)
        uses -= sum(inside.counts.get(v, 0) for v in loop_vars)
        if uses != len(out):
            return None
        if any(isinstance(st, Assignment) and isinstance(st.src, Phi) for st in loop.exit.statements):
            return None
        return out

    def _remove_loop(self, loop: _ZeroLoop) -> None:
        p = self.p
        p.replace_jump_target(loop.pred, loop.body.addr, loop.body.idx, loop.exit.addr, loop.exit.idx)
        self.graph.remove_node(loop.body)
        p._block_by_addr_and_idx.pop((loop.body.addr, loop.body.idx), None)
        # the loop's pointer and counter set-up are dead now
        dead = {
            v.varid
            for st in loop.body.statements
            if isinstance(st, Assignment) and isinstance(st.src, Phi)
            for src, v in st.src.src_and_vvars
            if v is not None and src == (loop.pred.addr, loop.pred.idx)
        }
        idx = _Index()
        for b in self.graph.nodes:
            idx.walk(b)
        loop.pred.statements = [
            st
            for st in loop.pred.statements
            if not (
                isinstance(st, Assignment)
                and isinstance(st.dst, VirtualVariable)
                and st.dst.varid in dead
                and idx.counts.get(st.dst.varid, 0) == 1
            )
        ]


class SmallMapFolder(_StackScan):
    """See the module docstring."""

    def run(self) -> list[Block]:
        if self.p.project.arch.bytes != 8:
            return []
        touched: list[Block] = []
        while True:
            self._reindex()
            done = None
            for block, i, stmt in list(self._seed_candidates()):
                done = self._fold(block, i, stmt)
                if done:
                    break
            if not done:
                return touched
            touched.extend(b for b in done if b not in touched)

    def _seed_candidates(self):
        for block, i, stmt in list(self.defs.values()):
            if (
                stmt.dst.was_stack
                and stmt.dst.size == 8
                and isinstance(stmt.src, Call)
                and self.p.callee_name(stmt.src) == "runtime.rand"
            ):
                yield block, i, stmt

    def _stack_defs_in(self, lo: int, hi: int) -> list[tuple[Block, int, Assignment]]:
        return [
            d
            for d in self.defs.values()
            if d[2].dst.was_stack and lo <= d[2].dst.stack_offset and d[2].dst.stack_offset + d[2].dst.size <= hi
        ]

    def _overlapping_stack_vars(self, lo: int, hi: int) -> list[VirtualVariable]:
        out = []
        for _, _, stmt in self.defs.values():
            v = stmt.dst
            if v.was_stack and v.stack_offset < hi and lo < v.stack_offset + v.size:
                out.append(v)
        return out

    #
    # The fold
    #

    def _fold(self, seed_block: Block, seed_i: int, seed: Assignment) -> list[Block] | None:
        header = seed.dst.stack_offset - 8
        hdr_end = header + _HEADER_SIZE
        # dirPtr = &group, group.ctrl = empty
        dir_defs = [
            d
            for d in self._stack_defs_in(header + 16, header + 24)
            if d[2].dst.size == 8 and _stack_ref(d[2].src) is not None
        ]
        if len(dir_defs) != 1:
            return None
        dir_def = dir_defs[0][2]
        group_var = _stack_ref(dir_def.src)
        if group_var is None:
            return None
        group = group_var.stack_offset
        ctrl = self.defs.get(group_var.varid)
        if ctrl is None or not (isinstance(ctrl[2].src, Const) and ctrl[2].src.value == _CTRL_EMPTY):
            return None
        # every address taken inside the header is &header itself
        base_ids = set()
        for v in self._overlapping_stack_vars(header, hdr_end):
            if v.varid in self.index.refs:
                if v.stack_offset != header:
                    return None
                base_ids.add(v.varid)
        if not base_ids:
            return None
        found = self._map_type(base_ids)
        if found is None:
            return None
        map_name, map_ty = found
        gsize = self._group_size(map_ty)
        if gsize is None or not map_name:
            return None
        g_end = group + gsize
        if g_end > header and group < hdr_end:
            return None

        drop: dict[Block, set[int]] = {}  # block -> statement indexes to drop

        def mark(block, i):
            drop.setdefault(block, set()).add(i)

        # header: zeroed words, dirPtr and the seed; read only through &header
        for block, i, st in self._stack_defs_in(header, hdr_end):
            v = st.dst
            if v.varid == seed.dst.varid:
                continue
            if not (isinstance(st.src, Const) and st.src.value == 0) and v.varid != dir_def.dst.varid:
                return None
            if self.index.counts.get(v.varid, 0) - len(self.index.refs.get(v.varid, ())) != 1:
                return None
            mark(block, i)
        if self.index.counts.get(seed.dst.varid, 0) != 1:
            return None
        # the group: zeroed words or a clearing loop, then the control word; read only through dirPtr
        loop = self._group_loop(group, g_end)
        loop_ptr_def = None
        if loop is not None:
            ptr0_vvar = loop.ptr0[1]
            loop_ptr_def = self.defs.get(ptr0_vvar.varid) if ptr0_vvar is not None else None
        for v in self._overlapping_stack_vars(group, g_end):
            if v.stack_offset < group or v.stack_offset + v.size > g_end:
                return None
            refs = self.index.refs.get(v.varid, [])
            allowed = 0
            for rb, ri in refs:
                if (rb, ri) == (dir_defs[0][0], dir_defs[0][1]) or (
                    loop_ptr_def is not None and (rb, ri) == (loop_ptr_def[0], loop_ptr_def[1])
                ):
                    allowed += 1
            if allowed != len(refs) or self.index.counts.get(v.varid, 0) - len(refs) != 1:
                return None
            block, i, st = self.defs[v.varid]
            if not isinstance(st.src, Const) or (st.src.value != 0 and v.varid != group_var.varid):
                return None
            mark(block, i)
        # the m := make(...) at the seed must come before every use of &header
        if not self._dominates_refs(seed_block, seed_i, base_ids):
            return None

        touched = set(drop)
        if loop is not None:
            tail = self._tail_stores(loop)
            if tail is None or any(group + lo < group or group + hi > g_end for _, lo, hi in tail):
                return None
            for i, _, _ in tail:
                mark(loop.exit, i)
            touched.add(loop.exit)
            touched.add(loop.pred)
        m = self._make_call(seed, map_name)
        seed_block.statements[seed_i] = m
        for block, idxs in drop.items():
            block.statements = [st for k, st in enumerate(block.statements) if k not in idxs]
        if loop is not None:
            self._remove_loop(loop)
        replacer = _RefReplacer(base_ids, m.dst)
        for block in list(self.graph.nodes):
            replacer.walk(block)
        touched.add(seed_block)
        return [b for b in touched if b in self.graph]

    def _make_call(self, seed: Assignment, map_name: str) -> Assignment:
        p = self.p
        tags = {k: v for k, v in seed.src.tags.items() if not k.startswith("go_")}
        call = Call(
            seed.src.idx,
            "make",
            [],
            bits=64,
            go_type_args=[map_name],
            go_result_type=map_name,
            is_prototype_guessed=False,
            **{k: v for k, v in tags.items() if k != "is_prototype_guessed"},
        )
        with contextlib.suppress(Exception):
            proto = GoSimTypeFunction([], p.kb.go_signatures.type(map_name)).with_arch(p.project.arch)
            variable_map_of(p.manager).set_prototype(call, proto)
        rax, _ = p._result_registers()
        dst = VirtualVariable(p.manager.next_atom(), p._new_varid(), 64, VVC.REGISTER, oident=rax)
        return Assignment(seed.idx, dst, call, **seed.tags)

    def _map_type(self, base_ids: set[int]) -> tuple[str, GoSimTypeMap] | None:
        """The map's type: a map runtime call's descriptor, or the parameter type of a callee &header is passed to."""
        p = self.p
        for call in self.index.calls:
            args = list(call.args or [])
            positions = [k for k, a in enumerate(args) if (r := _stack_ref(a)) is not None and r.varid in base_ids]
            if not positions:
                continue
            name = p.callee_name(call)
            if name is not None and name.startswith("runtime.") and args and isinstance(args[0], Const):
                ty = go_type_at(p.project, args[0].value_int)
                if isinstance(ty, GoSimTypeMap):
                    return go_type_name_at(p.project, args[0].value_int), ty
            proto = p._callee_prototype(call)
            if proto is not None:
                ty = self._param_at(proto, args, positions[0])
                if isinstance(ty, GoSimTypeMap):
                    return ty.go_repr(), ty
        return None

    def _param_at(self, proto, args: list, k: int):
        """The parameter that AIL argument ``k`` passes: arguments and parameters are matched by machine word."""
        word = sum(max(a.bits // 64, 1) for a in args[:k])
        at = 0
        for ty in proto.args:
            try:
                size = ty.with_arch(self.p.project.arch).size
            except Exception:  # pylint:disable=broad-exception-caught
                return None
            if not isinstance(size, int) or size <= 0:
                return None
            if at == word:
                return ty
            at += (size + 63) // 64
            if at > word:
                return None
        return None

    def _group_size(self, ty: GoSimTypeMap) -> int | None:
        with contextlib.suppress(Exception):
            ty = ty.with_arch(self.p.project.arch)
        sizes = []
        for t in (ty.key_type, ty.elem_type):
            try:
                size, align = t.size // 8, t.alignment
            except Exception:  # pylint:disable=broad-exception-caught
                return None
            if not isinstance(size, int) or not isinstance(align, int):
                return None
            if size > _SLOT_INDIRECT:
                size, align = 8, 8
            sizes.append((size, max(align, 1)))
        (ks, ka), (vs, va) = sizes
        slot = _align(_align(ks, va) + vs, max(ka, va))
        return 8 + 8 * slot

    def _dominates_refs(self, seed_block: Block, seed_i: int, base_ids: set[int]) -> bool:
        entry = next((b for b in self.graph.nodes if self.graph.in_degree(b) == 0), None)
        if entry is None:
            return False
        idoms = networkx.immediate_dominators(self.graph, entry)
        for varid in base_ids:
            for block, stmt_idx in self.index.refs.get(varid, []):
                if block is seed_block:
                    if stmt_idx <= seed_i:
                        return False
                    continue
                b = block
                while b is not seed_block:
                    nxt = idoms.get(b)
                    if nxt is None or nxt is b:
                        return False
                    b = nxt
        return True

    #
    # The group's clearing loop
    #

    def _group_loop(self, group: int, g_end: int) -> _ZeroLoop | None:
        for loop in self._zero_loops():
            ref = loop.ptr0[1]
            if ref is not None and ref.stack_offset == group and group + loop.iters * loop.stride <= g_end:
                return loop
        return None


class StackClearFolder(_StackScan):
    """
    A loop clearing a stack variable ``stride`` bytes per trip, plus the stores clearing its tail, is one
    ``memset(&v, 0, size)``; the code generator spells a whole-variable clear as ``v = T{}``.
    """

    def run(self) -> bool:
        changed = False
        while True:
            self._reindex()
            for loop in self._zero_loops():
                if self._fold(loop):
                    changed = True
                    break
            else:
                return changed

    def _fold(self, loop: _ZeroLoop) -> bool:
        ptr0, ref = loop.ptr0
        if ref is None or ptr0 is None:
            return False
        tail = self._tail_stores(loop)
        if tail is None:
            return False
        # the loop and the tail clear one contiguous run from the variable's start
        end = loop.iters * loop.stride
        for _, lo, hi in sorted(tail, key=lambda t: t[1]):
            if lo < 0 or lo > end:
                return False
            end = max(end, hi)
        ptr_def = self.defs[ptr0.varid][2]
        bits = self.p.project.arch.bits
        p = self.p
        call = Call(
            p.manager.next_atom(),
            "memset",
            [
                ptr_def.src,
                Const(p.manager.next_atom(), 0, 8),
                Const(p.manager.next_atom(), end, bits),
            ],
            bits=bits,
            **ptr_def.tags,
        )
        stmt = SideEffectStatement(p.manager.next_atom(), call, **ptr_def.tags)
        tail_idxs = {i for i, _, _ in tail}
        loop.exit.statements = [st for k, st in enumerate(loop.exit.statements) if k not in tail_idxs]
        self._remove_loop(loop)
        pred = loop.pred
        pred.statements = [*pred.statements[:-1], stmt, pred.statements[-1]]
        return True


def _base_off(addr: Expression) -> tuple[Expression, int]:
    """``base + k`` / ``base - k`` -> (base, signed k)."""
    if isinstance(addr, BinaryOp) and addr.op in ("Add", "Sub") and isinstance(addr.operands[1], Const):
        k = addr.operands[1].value_int
        bits = addr.operands[1].bits
        if k >= 1 << (bits - 1):
            k -= 1 << bits
        return addr.operands[0], k if addr.op == "Add" else -k
    return addr, 0


def _value(expr) -> int | None:
    return expr.value_int if isinstance(expr, Const) else None


def _covers(intervals: list[tuple[int, int]], size: int) -> bool:
    """The intervals cover exactly ``[0, size)``."""
    if not intervals:
        return False
    end = 0
    for lo, hi in sorted(intervals):
        if lo > end or lo < 0:
            return False
        end = max(end, hi)
    return end == size


class GoSmallMapFolder(OptimizationPass, CFGTransformationMixin):
    """
    ``make(map[K]V)`` of a non-escaping map, inlined onto the stack (see the module docstring). Runs before the map
    accesses are rewritten, while their type descriptors still name the map type.
    """

    ARCHES = None
    PLATFORMS = None
    STAGE = OptimizationPassStage.BEFORE_VARIABLE_RECOVERY
    NAME = "Fold Go stack-allocated map initializations"

    def __init__(self, func, manager, **kwargs):
        super().__init__(func, manager, **kwargs)
        CFGTransformationMixin.__init__(self, self._graph)
        self.analyze()

    def _check(self):
        return self.project.is_go_binary, None

    def _analyze(self, cache=None):
        if SmallMapFolder(self).run():
            self.out_graph = self._graph

    def callee_name(self, call: Call) -> str | None:
        name = call_target_name(self.project, call)
        return normalize_go_func_name(name) if name is not None else None

    def _callee_prototype(self, call: Call):
        proto = variable_map_of(self.manager).prototype(call)
        if proto is None and isinstance(call.target, Const) and self.kb.functions.contains_addr(call.target.value_int):
            proto = self.kb.functions.get_by_addr(call.target.value_int).prototype
        if not isinstance(proto, GoSimTypeFunction):
            name = self.callee_name(call)
            with contextlib.suppress(Exception):
                proto = self.kb.go_signatures.prototype(name) if name is not None else None
        return proto

    def _result_registers(self) -> tuple[int, int]:
        regs = self.project.arch.registers
        names = ("rax", "rbx") if "rax" in regs else ("x0", "x1")
        return regs[names[0]][0], regs[names[1]][0]

    def _new_varid(self) -> int:
        varid = self.vvar_id_start
        self.vvar_id_start += 1
        return varid
