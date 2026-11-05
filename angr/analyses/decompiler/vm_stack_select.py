"""
A devirtualized VM branches by loading one of two stack slots through a computed offset:

    slot0 = A; slot1 = B; ...; x = *(S + &slot0)        with S in {0, d}, slot1 at slot0 + d

The load names no single slot, so SSA keeps slot1's definition without a use (and removes it) and nothing folds
through the selection. Rewritten as ``x = S == 0 ? slot0 : slot1`` it reads both slot variables; when the known bits
of S fix it, as a read of the one slot.

The slot definitions, the address computation and the load may sit in different blocks (a VM handler is split at
its junk branches), so definitions are looked up across the graph.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping

import networkx

from angr.ailment import Block
from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label, NoOp, Store
from angr.utils.ail import BlockDefs, GraphVVarDefs

from .peephole_optimizations.known_bits import block_defs_resolver, known_bits

# flag helpers the ccall rewriters emit; they read only their arguments
_PURE_CALLS = frozenset({"__CFADD__", "__CFSUB__", "__OFADD__", "__OFSUB__"})


class _ImpureCall(AILBlockViewer):
    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if not (isinstance(expr.target, str) and expr.target in _PURE_CALLS):
            self.found = True
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)


def _may_write_memory(stmt) -> bool:
    if isinstance(stmt, Store):
        return True
    if isinstance(stmt, (Assignment, Label, Jump, ConditionalJump, NoOp)):
        viewer = _ImpureCall()
        viewer.walk_statement(stmt)
        return viewer.found
    # calls, CAS, dirty statements, ...
    return True


def _movable(expr: Expression) -> bool:
    """Whether an expression reads only virtual variables and constants, so it means the same in any block."""
    if isinstance(expr, (VirtualVariable, Const)):
        return True
    if isinstance(expr, BinaryOp):
        return all(_movable(op) for op in expr.operands)
    if isinstance(expr, (UnaryOp, Convert)):
        return _movable(expr.operand)
    return False


def _vvars_in(expr: Expression, tmps: Mapping[int, Expression]) -> list[VirtualVariable]:
    """The variables an address reads through Add/Sub and the block's Tmps."""
    out = []
    work = [expr]
    while work:
        e = work.pop()
        if isinstance(e, VirtualVariable):
            out.append(e)
        elif isinstance(e, Tmp):
            src = tmps.get(e.tmp_idx)
            if src is not None:
                work.append(src)
        elif isinstance(e, BinaryOp) and e.op in ("Add", "Sub"):
            work.extend(e.operands)
    return out


def _is_affine_step(expr: Expression) -> bool:
    """A definition the address flattening looks through: a copy, a constant, a stack reference, or an Add/Sub."""
    if isinstance(expr, (VirtualVariable, Tmp, Const)):
        return True
    if isinstance(expr, BinaryOp):
        return expr.op in ("Add", "Sub")
    return isinstance(expr, UnaryOp) and expr.op == "Reference"


class _Sum:
    """An address as a sum: stack references + leaves + a constant (modulo 2**bits)."""

    __slots__ = ("bits", "const", "leaves", "refs")

    def __init__(self, bits: int):
        self.bits = bits
        self.const = 0
        self.refs: list[UnaryOp] = []
        self.leaves: list[Expression] = []

    def add(self, other: _Sum, negate_const: bool = False) -> None:
        self.refs += other.refs
        self.leaves += other.leaves
        self.const = (self.const + (-other.const if negate_const else other.const)) & ((1 << self.bits) - 1)

    def key(self):
        """Hashable identity, or None when a leaf is not a virtual variable."""
        if not all(isinstance(t, VirtualVariable) for t in self.leaves):
            return None
        return (
            tuple(sorted(r.operand.varid for r in self.refs)),
            tuple(sorted(t.varid for t in self.leaves)),
            self.const,
        )


class _GraphSelectFolder:
    def __init__(self, graph: networkx.DiGraph, ail_manager):
        self.graph = graph
        self.manager = ail_manager
        self.defs = GraphVVarDefs(graph)
        self.phis = self.defs.phi_sources()
        # varid -> the variable's value as a sum (see _vvar_sum)
        self._sums: dict[int, _Sum] = {}

    # address flattening

    def _flatten(self, expr: Expression, tmps: Mapping[int, Expression]) -> _Sum:
        """``expr`` as a sum; variables come from _vvar_sum (memoized, so shared definitions are walked once)."""
        s = _Sum(expr.bits)
        if isinstance(expr, Const) and isinstance(expr.value, int):
            s.const = expr.value_int & ((1 << expr.bits) - 1)
            return s
        if isinstance(expr, Tmp):
            src = tmps.get(expr.tmp_idx)
            if src is not None and src.bits == expr.bits:
                return self._flatten(src, tmps)
        elif isinstance(expr, BinaryOp) and len(expr.operands) == 2 and all(
            op.bits == expr.bits for op in expr.operands
        ):
            if expr.op == "Add":
                s.add(self._flatten(expr.operands[0], tmps))
                s.add(self._flatten(expr.operands[1], tmps))
                return s
            if expr.op == "Sub" and isinstance(expr.operands[1], Const) and isinstance(expr.operands[1].value, int):
                s.add(self._flatten(expr.operands[0], tmps))
                s.const = (s.const - expr.operands[1].value_int) & ((1 << expr.bits) - 1)
                return s
        elif (
            isinstance(expr, UnaryOp)
            and expr.op == "Reference"
            and isinstance(expr.operand, VirtualVariable)
            and expr.operand.was_stack
        ):
            s.refs.append(expr)
            return s
        elif isinstance(expr, VirtualVariable):
            r = self._sums.get(expr.varid)
            if r is not None:
                return r
        s.leaves.append(expr)
        return s

    def _vvar_deps(self, vvar: VirtualVariable) -> list[VirtualVariable]:
        """The variables _vvar_sum of ``vvar`` reads."""
        if vvar.varid in self.phis:
            bits, srcs = self.phis[vvar.varid]
            return [v for v in srcs if v is not None and v.bits == bits and v.varid != vvar.varid]
        d = self.defs.definition(vvar.varid)
        if d is None or d[0].bits != vvar.bits or not _is_affine_step(d[0]):
            return []
        out = []
        work = [d[0]]
        while work:
            e = work.pop()
            if isinstance(e, VirtualVariable):
                out.append(e)
            elif isinstance(e, Tmp):
                src = d[1].get(e.tmp_idx)
                if src is not None:
                    work.append(src)
            elif isinstance(e, BinaryOp) and e.op in ("Add", "Sub"):
                work.extend(e.operands)
        return out

    def _vvar_sum(self, vvar: VirtualVariable) -> None:
        """
        Fill self._sums for ``vvar`` and the variables its value is built from, in post-order without recursion (a VM
        stack pointer is a chain of thousands of definitions). A variable still being computed (a cycle through
        phis) stands for itself, which is exact.
        """
        stack = [vvar]
        active: set[int] = set()
        while stack:
            v = stack[-1]
            if v.varid in self._sums:
                stack.pop()
                continue
            if v.varid not in active:
                active.add(v.varid)
                stack.extend(d for d in self._vvar_deps(v) if d.varid not in self._sums and d.varid not in active)
                continue
            stack.pop()
            active.discard(v.varid)
            self._sums[v.varid] = self._compute_sum(v)

    def _compute_sum(self, vvar: VirtualVariable) -> _Sum:
        leaf = _Sum(vvar.bits)
        leaf.leaves.append(vvar)
        if vvar.varid in self.phis:
            r = self._flatten_phi(vvar)
            return r if r is not None else leaf
        d = self.defs.definition(vvar.varid)
        if d is None or d[0].bits != vvar.bits or not _is_affine_step(d[0]):
            return leaf
        s = self._flatten(d[0], d[1])
        # keep the variable when its definition does not split into movable terms
        return s if all(_movable(t) for t in s.leaves) else leaf

    def _flatten_phi(self, vvar: VirtualVariable) -> _Sum | None:
        """The sum every source of a phi is, ignoring a back-edge source that is the phi itself plus 0."""
        bits, srcs = self.phis[vvar.varid]
        rep = None
        for src in srcs:
            if src is None or src.bits != bits:
                return None
            if src.varid == vvar.varid:
                continue
            s = self._flatten(src, {})
            if not s.refs and s.const == 0 and len(s.leaves) == 1 and getattr(s.leaves[0], "varid", None) == vvar.varid:
                continue
            key = s.key()
            if key is None:
                return None
            if rep is None:
                rep = (key, s)
            elif rep[0] != key:
                return None
        return rep[1] if rep is not None else None

    # slot definitions

    @staticmethod
    def _scan_back(block: Block, end: int, offset: int, size: int, start: int = 0):
        """('def', vvar) | ('none', None) | ('fail', None), scanning block.statements[start:end] backwards."""
        for idx in range(end - 1, start - 1, -1):
            stmt = block.statements[idx]
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable) and stmt.dst.was_stack:
                dst = stmt.dst
                lo, hi = dst.stack_offset, dst.stack_offset + dst.size
                if lo == offset and dst.size == size:
                    return ("fail", None) if isinstance(stmt.src, Phi) else ("def", dst)
                if lo < offset + size and offset < hi:
                    # a partial overlap: the slot holds a mix
                    return "fail", None
            elif _may_write_memory(stmt):
                return "fail", None
        return "none", None

    def _slot_def(self, block: Block, stmt_idx: int, offset: int, size: int) -> VirtualVariable | None:
        """The one definition of exactly this stack slot that reaches (block, stmt_idx) on every path."""
        kind, v = self._scan_back(block, stmt_idx, offset, size)
        if kind != "none":
            return v
        found: VirtualVariable | None = None
        seen = {block}
        work = deque(self.graph.predecessors(block))
        if not work:
            return None
        while work:
            b = work.popleft()
            if b in seen:
                if b is block:
                    # around a loop: the part of the load's block after the load
                    kind, v = self._scan_back(block, len(block.statements), offset, size, start=stmt_idx + 1)
                    if kind == "fail" or (kind == "def" and found is not None and found.varid != v.varid):
                        return None
                    if kind == "def":
                        found = v
                continue
            seen.add(b)
            kind, v = self._scan_back(b, len(b.statements), offset, size)
            if kind == "fail":
                return None
            if kind == "def":
                if found is not None and found.varid != v.varid:
                    return None
                found = v
                continue
            preds = list(self.graph.predecessors(b))
            if not preds:
                # the function entry: the slot is not defined on this path
                return None
            work.extend(preds)
        return found

    # the rewrite

    def fold(self, load: Load, block: Block, stmt_idx: int, block_defs: BlockDefs) -> Expression | None:
        if load.guard is not None or load.endness != "Iend_LE":
            return None
        for v in _vvars_in(load.addr, block_defs.tmps):
            self._vvar_sum(v)
        addr = self._flatten(load.addr, block_defs.tmps)
        if len(addr.refs) != 1 or len(addr.leaves) != 1:
            return None
        ref, sel = addr.refs[0], addr.leaves[0]
        if not _movable(sel):
            return None
        zeros, ones = known_bits(sel, block_defs_resolver(block_defs), tmps=block_defs.tmps)
        full = (1 << sel.bits) - 1
        const = addr.const - (1 << addr.bits) if addr.const >> (addr.bits - 1) else addr.const
        offset = ref.operand.stack_offset + const
        if (zeros | ones) & full == full:
            # the index is a constant: the load reads one slot
            index = ones - (1 << sel.bits) if ones >> (sel.bits - 1) else ones
            v = self._slot_def(block, stmt_idx, offset + index, load.size)
            if v is None or v.bits != load.bits:
                return None
            return VirtualVariable(load.idx, v.varid, v.bits, category=v.category, oident=v.oident, **load.tags)
        delta = full & ~zeros
        # sel is 0 or delta
        if ones or not delta or delta & (delta - 1):
            return None
        slots = [
            self._slot_def(block, stmt_idx, offset, load.size),
            self._slot_def(block, stmt_idx, offset + delta, load.size),
        ]
        if None in slots or any(v.bits != load.bits for v in slots):
            return None
        reads = [
            VirtualVariable(self.manager.next_atom(), v.varid, v.bits, category=v.category, oident=v.oident, **v.tags)
            for v in slots
        ]
        cond = BinaryOp(
            self.manager.next_atom(), "CmpEQ", [sel, Const(self.manager.next_atom(), 0, sel.bits)], False, bits=1
        )
        return ITE(load.idx, cond, reads[0], reads[1], **load.tags)


def fold_stack_select_loads(graph: networkx.DiGraph, ail_manager) -> int:
    """Rewrite two-slot stack selections into ITEs in place. Returns the number of loads rewritten."""
    folder = _GraphSelectFolder(graph, ail_manager)
    count = 0

    for block in list(graph):
        block_defs = BlockDefs(block.statements, all_defs=folder.defs)

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)
                self.count = 0

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
                repl = folder.fold(rebuilt if rebuilt is not None else expr, block, stmt_idx, block_defs)
                if repl is None:
                    return rebuilt
                self.count += 1
                return repl

        rewriter = _Rewriter()
        new_block = rewriter.walk(block)
        if rewriter.count and new_block is not None:
            block.statements = list(new_block.statements)
            count += rewriter.count
    return count
