"""
String comparisons the Go compiler lowers to a length check plus little-endian word compares of the bytes.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import networkx

from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StringLiteral,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Label
from angr.utils.ail import find_call

if TYPE_CHECKING:
    from angr.ailment.block import Block

    from .builtin_rewriter import GoBuiltinRewriter

l = logging.getLogger(__name__)

_NEGATE = {"CmpEQ": "CmpNE", "CmpNE": "CmpEQ", "CmpLT": "CmpGE", "CmpGE": "CmpLT", "CmpLE": "CmpGT", "CmpGT": "CmpLE"}
_SWAP = {"CmpEQ": "CmpEQ", "CmpNE": "CmpNE", "CmpLT": "CmpGT", "CmpGT": "CmpLT", "CmpLE": "CmpGE", "CmpGE": "CmpLE"}


def _strip(expr: Expression) -> Expression:
    while isinstance(expr, Convert):
        expr = expr.operand
    return expr


def _cmp_with_const(cond: Expression) -> tuple[str, Expression, int] | None:
    """``x <op> c`` (either operand order) -> (op, x, c)."""
    cond = _strip(cond)
    if not isinstance(cond, BinaryOp) or cond.op not in _NEGATE:
        return None
    a, b = (_strip(o) for o in cond.operands)
    if isinstance(b, Const) and not isinstance(a, Const):
        return cond.op, a, b.value_int
    if isinstance(a, Const) and not isinstance(b, Const):
        return _SWAP[cond.op], b, a.value_int
    return None


def _text(data: bytes) -> str | None:
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return s if s and all(ch.isprintable() for ch in s) else None


class _Interval:
    __slots__ = ("excluded", "hi", "lo")

    def __init__(self):
        self.lo, self.hi = 0, None  # a length is never negative
        self.excluded: set[int] = set()

    def add(self, op: str, c: int) -> None:
        if op == "CmpEQ":
            self.lo, self.hi = max(self.lo, c), c if self.hi is None else min(self.hi, c)
        elif op == "CmpNE":
            self.excluded.add(c)
        elif op == "CmpLT":
            self.hi = c - 1 if self.hi is None else min(self.hi, c - 1)
        elif op == "CmpLE":
            self.hi = c if self.hi is None else min(self.hi, c)
        elif op == "CmpGT":
            self.lo = max(self.lo, c + 1)
        elif op == "CmpGE":
            self.lo = max(self.lo, c)

    def low(self) -> int:
        lo = self.lo
        while lo in self.excluded:
            lo += 1
        return lo

    def pinned(self) -> int | None:
        if self.hi is None or self.hi - self.lo > 64:
            return None
        left = [v for v in range(self.lo, self.hi + 1) if v not in self.excluded]
        return left[0] if len(left) == 1 else None


class LengthFacts:
    """What the dominating branches say about integer values (string lengths) at a block."""

    def __init__(self, rewriter: GoBuiltinRewriter):
        self._r = rewriter
        g = rewriter._graph
        entry = next((b for b in g if b.addr == rewriter._func.addr and g.in_degree(b) == 0), None)
        if entry is None:
            entry = next((b for b in g if g.in_degree(b) == 0), None)
        idom = networkx.immediate_dominators(g, entry) if entry is not None else {}
        # keyed by (addr, idx): rewriters may hand out other objects for the same block
        self._idom = {(b.addr, b.idx): (d.addr, d.idx) for b, d in idom.items()}
        self._cache: dict = {}

    def at(self, block: Block) -> list[tuple[Expression, _Interval]]:
        """(value, interval) pairs, nearest guard first."""
        key = (block.addr, block.idx)
        if key in self._cache:
            return self._cache[key]
        g = self._r._graph
        blocks = self._r._block_by_addr_and_idx
        facts: list[tuple[Expression, _Interval]] = []
        cur_key = key
        seen = set()
        while cur_key in self._idom and cur_key not in seen:
            seen.add(cur_key)
            dom_key = self._idom[cur_key]
            cur, dom = blocks.get(cur_key), blocks.get(dom_key)
            if dom_key == cur_key or cur is None or dom is None or cur not in g or dom not in g:
                break
            last = dom.statements[-1] if dom.statements else None
            if isinstance(last, ConditionalJump) and g.in_degree(cur) == 1:
                hit = _cmp_with_const(last.condition)
                targets = self._r.cond_targets(dom)
                if hit is not None and targets is not None and targets[0] is not targets[1] and cur in targets:
                    op, x, c = hit
                    if cur is targets[1]:
                        op = _NEGATE[op]
                    x = self._r.values.resolve(x)
                    for y, iv in facts:
                        if y.likes(x):
                            iv.add(op, c)
                            break
                    else:
                        iv = _Interval()
                        iv.add(op, c)
                        facts.append((x, iv))
            cur_key = dom_key
        self._cache[key] = facts
        return facts


class _WordCmp:
    __slots__ = ("block", "data", "match", "mismatch", "off", "ptr", "size")

    def __init__(self, block, ptr, off, size, data, match, mismatch):
        self.block, self.ptr, self.off, self.size, self.data = block, ptr, off, size, data
        self.match, self.mismatch = match, mismatch


class StringCompareFolder:
    """
    ``len(s) == n`` dominating a chain of word compares ``*(*uintK)(s.ptr + k) == c`` that together cover the n
    bytes of a printable string and all fail to the same place: the first compare becomes ``s == "..."`` and the
    rest become jumps. When the length check itself leads to the chain and fails to the same place, it becomes the
    string compare instead. "The same place" looks through jump-only blocks and constant branches.
    """

    def __init__(self, rewriter: GoBuiltinRewriter, facts: LengthFacts):
        self._r = rewriter
        self._facts = facts
        self._g = rewriter._graph
        self._endness = "little" if rewriter.project.arch.memory_endness == "Iend_LE" else "big"

    def fold(self) -> int:
        self._touched: list[Block] = []
        folded = self._fold_word_compares() + self._fold_memequal_branches()
        if self._touched:
            # the loads of the words compared are dead now
            self._r._drop_dead_defs([b for b in dict.fromkeys(self._touched) if b in self._g])
        return folded

    def _fold_memequal_branches(self) -> int:
        """``if memequal(p, "lit", n) != 0`` under a length guard pinning n: ``if s == "lit"``."""
        counts = self._r._use_counts()
        folded = 0
        for block in list(self._g):
            if not block.statements:
                continue
            asg_at = len(block.statements) - 1
            cj_block = block
            if isinstance(block.statements[-1], ConditionalJump) and len(block.statements) >= 2:
                asg_at -= 1
            elif isinstance(block.statements[-1], Assignment):
                # the call ends its block; the branch on its result opens the next one
                succs = list(self._g.successors(block))
                if len(succs) != 1 or self._g.in_degree(succs[0]) != 1:
                    continue
                cj_block = succs[0]
                if [st for st in cj_block.statements if not isinstance(st, Label)][:-1]:
                    continue
            else:
                continue
            asg = block.statements[asg_at]
            cj = cj_block.statements[-1] if cj_block.statements else None
            if not (
                isinstance(cj, ConditionalJump)
                and isinstance(asg, Assignment)
                and isinstance(asg.dst, VirtualVariable)
                and isinstance(asg.src, Call)
                and self._r.callee_name(asg.src) == "runtime.memequal"
                and counts[asg.dst.varid] == 2
            ):
                continue
            hit = _cmp_with_const(cj.condition)
            if hit is None or hit[0] not in ("CmpEQ", "CmpNE") or hit[2] != 0:
                continue
            if not (isinstance(hit[1], VirtualVariable) and hit[1].varid == asg.dst.varid):
                continue
            cmp = _strip(self._r._guarded_memequal(asg.src, list(asg.src.args or []), block) or asg.src)
            if not (isinstance(cmp, BinaryOp) and cmp.op == "CmpEQ"):
                continue
            op = "CmpEQ" if hit[0] == "CmpNE" else "CmpNE"
            cond = self._r.compare(op, cmp.operands[0], cmp.operands[1], None, cj.condition.tags)
            new_cj = ConditionalJump(
                cj.idx,
                cond,
                cj.true_target,
                cj.false_target,
                true_target_idx=cj.true_target_idx,
                false_target_idx=cj.false_target_idx,
                **cj.tags,
            )
            if cj_block is block:
                block.statements = [*block.statements[:asg_at], new_cj]
            else:
                block.statements = block.statements[:asg_at]
                cj_block.statements = [*cj_block.statements[:-1], new_cj]
            folded += 1
        return folded

    def _fold_word_compares(self) -> int:
        cmps = {}
        for block in self._g:
            wc = self._word_cmp(block)
            if wc is not None:
                cmps[block] = wc
        chains = {}
        linked = set()
        for block, wc in cmps.items():
            chain = [wc]
            while True:
                nxt = cmps.get(chain[-1].match)
                if nxt is None or nxt in chain or not self._continues(wc, nxt):
                    break
                chain.append(nxt)
            chains[block] = chain
            linked.update(w.block for w in chain[1:])
        folded = 0
        for block in sorted(chains, key=lambda b: (b.addr, b.idx or 0)):
            if block in linked:
                continue
            chain = chains[block]
            for k in range(len(chain), 0, -1):
                try:
                    if self._fold_chain(chain[:k]):
                        folded += 1
                        break
                except Exception:  # pylint:disable=broad-exception-caught
                    l.debug("Folding a string compare at %#x failed", block.addr, exc_info=True)
                    break
        return folded

    def _continues(self, head: _WordCmp, nxt: _WordCmp) -> bool:
        return (
            self._g.in_degree(nxt.block) == 1
            and nxt.ptr.likes(head.ptr)
            and self._follow(nxt.mismatch)[0] is self._follow(head.mismatch)[0]
        )

    def _hop(self, block: Block) -> Block | None:
        """Where a block that only jumps (possibly on a constant condition) goes."""
        stmts = [stmt for stmt in block.statements if not isinstance(stmt, Label)]
        if len(stmts) != 1:
            return None
        last = stmts[0]
        if isinstance(last, Jump):
            succs = list(self._g.successors(block))
            return succs[0] if len(succs) == 1 else None
        if isinstance(last, ConditionalJump) and isinstance(last.condition, Const):
            targets = self._r.cond_targets(block)
            return None if targets is None else targets[0 if last.condition.value_int else 1]
        return None

    def _follow(self, block: Block) -> tuple[Block, Block | None]:
        """The first block past the jump-only ones from ``block``, and the last jump-only block before it."""
        prev = None
        seen = set()
        while block not in seen:
            seen.add(block)
            nxt = self._hop(block)
            if nxt is None:
                break
            prev, block = block, nxt
        return block, prev

    def _word_cmp(self, block: Block) -> _WordCmp | None:
        last = block.statements[-1] if block.statements else None
        if not isinstance(last, ConditionalJump):
            return None
        hit = _cmp_with_const(last.condition)
        if hit is None or hit[0] not in ("CmpEQ", "CmpNE"):
            return None
        op, load, c = hit
        if isinstance(load, VirtualVariable):
            load = _strip(self._r.values.expand(load))
        if not isinstance(load, Load) or load.size not in (1, 2, 4, 8):
            return None
        targets = self._r.cond_targets(block)
        if targets is None or targets[0] is targets[1]:
            return None
        match, mismatch = targets if op == "CmpEQ" else targets[::-1]
        ptr, off = _addr_and_offset(load.addr)
        if ptr is None or off < 0:
            return None
        data = (c & ((1 << (8 * load.size)) - 1)).to_bytes(load.size, self._endness)
        return _WordCmp(block, self._r.values.resolve(ptr), off, load.size, data, match, mismatch)

    def _fold_chain(self, chain: list[_WordCmp]) -> bool:
        buf: dict[int, int] = {}
        for wc in chain:
            for i, byte in enumerate(wc.data):
                if buf.setdefault(wc.off + i, byte) != byte:
                    return False
        n = len(buf)
        if sorted(buf) != list(range(n)):
            return False
        text = _text(bytes(buf[i] for i in range(n)))
        if text is None:
            return False
        head = chain[0]
        hit = self._r.string_length(self._facts.at(head.block), head.ptr, n)
        if hit is None:
            return False
        length = hit[0]
        s = self._r.string_value(head.ptr, length)
        # the length check right before the chain, failing to the same place, goes too
        guard = self._guard(head, length, n)
        plan = (self._plan(chain, guard) if guard is not None else None) or self._plan(chain, None)
        if plan is None:
            return False
        top, top_mismatch, target, jumped = plan
        lit = StringLiteral(self._r.manager.next_atom(), text, self._r._string_bits, **head.block.statements[-1].tags)
        cj = top.statements[-1]
        op = "CmpEQ" if self._r.cond_targets(top)[0] is not top_mismatch else "CmpNE"
        cond = self._r.compare(op, s, lit, None, cj.condition.tags)
        top.statements[-1] = ConditionalJump(
            cj.idx,
            cond,
            cj.true_target,
            cj.false_target,
            true_target_idx=cj.true_target_idx,
            false_target_idx=cj.false_target_idx,
            **cj.tags,
        )
        self._touched += [top, *(wc.block for wc in jumped)]
        for wc in jumped:
            self._r.remove_jump_target(wc.block, wc.mismatch.addr, wc.mismatch.idx)
            self._drop_phi_sources(wc.mismatch, wc.block)
            self._remove_dead(wc.mismatch)
        self._settle_constant_branches(top_mismatch, target)
        return True

    def _settle_constant_branches(self, block: Block, target: Block) -> None:
        """Constant branches on the way from ``block`` to ``target`` become jumps."""
        seen = set()
        while block is not target and block not in seen and block in self._g:
            seen.add(block)
            nxt = self._hop(block)
            if nxt is None:
                return
            last = block.statements[-1]
            if isinstance(last, ConditionalJump):
                other = next((t for t in self._r.cond_targets(block) if t is not nxt), None)
                if other is not None:
                    self._r.remove_jump_target(block, other.addr, other.idx)
                    self._drop_phi_sources(other, block)
                    self._remove_dead(other)
            block = nxt

    def _plan(self, chain: list[_WordCmp], guard: Block | None):
        """(top block, its failure target, the shared failure target, compares that become jumps), or None."""
        head = chain[0]
        top = guard if guard is not None else head.block
        top_mismatch = head.mismatch if guard is None else self._guard_mismatch(guard)
        target, keep = self._follow(top_mismatch)
        keep = keep or top
        jumped = [wc for wc in chain if guard is not None or wc is not head]
        for wc in jumped:
            if not self._pure(wc.block):
                return None
            # a failing compare now fails at the top: the merge there must not tell the paths apart
            if not self._phis_agree(target, keep, self._follow(wc.mismatch)[1] or wc.block):
                return None
        return top, top_mismatch, target, jumped

    def _guard_mismatch(self, guard: Block) -> Block:
        hit = _cmp_with_const(guard.statements[-1].condition)
        targets = self._r.cond_targets(guard)
        return targets[1] if hit[0] == "CmpEQ" else targets[0]

    def _guard(self, head: _WordCmp, length: Expression, n: int) -> Block | None:
        preds = list(self._g.predecessors(head.block))
        if len(preds) != 1:
            return None
        guard = preds[0]
        last = guard.statements[-1] if guard.statements else None
        hit = _cmp_with_const(last.condition) if isinstance(last, ConditionalJump) else None
        if hit is None or hit[0] not in ("CmpEQ", "CmpNE") or hit[2] != n:
            return None
        if not self._r.values.resolve(hit[1]).likes(length):
            return None
        targets = self._r.cond_targets(guard)
        if targets is None or targets[0] is targets[1]:
            return None
        match, mismatch = targets if hit[0] == "CmpEQ" else targets[::-1]
        if match is not head.block or self._follow(mismatch)[0] is not self._follow(head.mismatch)[0]:
            return None
        return guard

    def _remove_dead(self, block: Block) -> None:
        """Drop jump-only blocks nothing reaches any more."""
        work = [block]
        while work:
            b = work.pop()
            if b not in self._g or self._g.in_degree(b) != 0 or b.addr == self._r._func.addr:
                continue
            if any(not isinstance(st, (Label, Jump, ConditionalJump)) for st in b.statements):
                continue
            succs = list(self._g.successors(b))
            self._g.remove_node(b)
            self._r._block_by_addr_and_idx.pop((b.addr, b.idx), None)
            for succ in succs:
                self._drop_phi_sources(succ, b)
                work.append(succ)

    @staticmethod
    def _pure(block: Block) -> bool:
        for stmt in block.statements[:-1]:
            if isinstance(stmt, Label):
                continue
            if not (isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable)):
                return False
            if isinstance(stmt.src, Phi) or find_call(stmt) is not None:
                return False
        return True

    @staticmethod
    def _phis_agree(block: Block, keep: Block, gone: Block) -> bool:
        """Every phi of ``block`` takes the same value from ``gone`` as from ``keep``."""
        keep_key, gone_key = (keep.addr, keep.idx), (gone.addr, gone.idx)
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                srcs = dict(stmt.src.src_and_vvars)
                if gone_key not in srcs:
                    continue
                if keep_key not in srcs:
                    return False
                a, b = srcs[keep_key], srcs[gone_key]
                if (a is None) != (b is None) or (a is not None and a.varid != b.varid):
                    return False
        return True

    @staticmethod
    def _drop_phi_sources(block: Block, gone: Block) -> None:
        key = (gone.addr, gone.idx)
        stmts = []
        changed = False
        for stmt in block.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                entries = [(k, v) for k, v in stmt.src.src_and_vvars if k != key]
                if len(entries) != len(stmt.src.src_and_vvars):
                    phi = Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags)
                    stmt = Assignment(stmt.idx, stmt.dst, phi, **stmt.tags)
                    changed = True
            stmts.append(stmt)
        if changed:
            block.statements = stmts


class _LitTest:
    __slots__ = ("block", "match", "mismatch", "text", "value")

    def __init__(self, block, value, text, match, mismatch):
        self.block, self.value, self.text, self.match, self.mismatch = block, value, text, match, mismatch


class StringSwitchFlattener:
    """
    A string switch dispatches on the length and on single bytes before comparing whole strings. Once those compares
    are ``s == "..."``, the dispatch only routes each literal to its own compare: it becomes a chain of the compares
    in address order, so the cases structure as one if/else-if chain over ``s``.
    """

    def __init__(self, rewriter: GoBuiltinRewriter):
        self._r = rewriter
        self._g = rewriter._graph
        self._endness = "little" if rewriter.project.arch.memory_endness == "Iend_LE" else "big"

    def flatten(self) -> int:
        self._counts = self._r._use_counts()
        tests = [t for t in (self._lit_test(b) for b in self._g) if t is not None]
        groups: list[list[_LitTest]] = []
        for t in tests:
            for group in groups:
                if group[0].value.likes(t.value):
                    group.append(t)
                    break
            else:
                groups.append([t])
        flattened = 0
        for group in groups:
            if len(group) < 2:
                continue
            base = self._r.values.base_of_value(group[0].value)
            if base is None:
                continue
            try:
                flattened += self._flatten_group(group, base)
            except Exception:  # pylint:disable=broad-exception-caught
                l.debug("Flattening a string switch failed", exc_info=True)
        return flattened

    def _lit_test(self, block: Block) -> _LitTest | None:
        stmts = [stmt for stmt in block.statements if not isinstance(stmt, Label)]
        if len(stmts) != 1 or not isinstance(stmts[0], ConditionalJump):
            return None
        cond = _strip(stmts[0].condition)
        if not (isinstance(cond, BinaryOp) and cond.op in ("CmpEQ", "CmpNE")):
            return None
        a, b = cond.operands
        if isinstance(a, StringLiteral):
            a, b = b, a
        if not isinstance(b, StringLiteral) or isinstance(a, StringLiteral):
            return None
        targets = self._r.cond_targets(block)
        if targets is None or targets[0] is targets[1]:
            return None
        match, mismatch = targets if cond.op == "CmpEQ" else targets[::-1]
        return _LitTest(block, a, b.data, match, mismatch)

    def _dispatch(self, block: Block, base, entry: bool = False) -> tuple | None:
        """
        A branch on the length of ``base`` (``("len", cmp)``) or on its bytes (``("bytes", cmp, off, size)``). The
        entry block keeps what it does before the branch.
        """
        stmts = [stmt for stmt in block.statements if not isinstance(stmt, Label)]
        if not stmts or not isinstance(stmts[-1], ConditionalJump):
            return None
        # copies nothing outside the block reads go with it
        local = None
        for stmt in [] if entry else stmts[:-1]:
            if not (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and not isinstance(stmt.src, (Call, Phi))
            ):
                return None
            if local is None:
                local = self._r.block_use_counts(block)
            if self._counts[stmt.dst.varid] != local[stmt.dst.varid]:
                return None
        cond = _strip(stmts[-1].condition)
        hit = _cmp_with_const(cond)
        if hit is None:
            return None
        x = hit[1]
        values = self._r.values
        if values.is_len_of(x, base):
            return "len", hit, cond.signed
        if isinstance(x, VirtualVariable):
            x = _strip(values.expand(x))
        if isinstance(x, Load):
            ptr, off = _addr_and_offset(x.addr)
            if ptr is not None and values.piece(ptr, base) == 0:
                return "bytes", hit, cond.signed, off, x.size
        return None

    def _jump_only(self, block: Block) -> bool:
        stmts = [stmt for stmt in block.statements if not isinstance(stmt, Label)]
        return (not stmts or (len(stmts) == 1 and isinstance(stmts[0], Jump))) and self._g.out_degree(block) == 1

    def _flatten_group(self, group: list[_LitTest], base) -> int:
        lits = {t.block: t for t in group}
        kinds: dict = dict.fromkeys(lits, "lit")

        def member(b) -> bool:
            if b not in kinds:
                kinds[b] = "lit" if b in lits else self._dispatch(b, base) or ("jump" if self._jump_only(b) else None)
            return kinds[b] is not None

        # everything that leads only to the compares, then everything it reaches short of a case body
        region = set(lits)
        work = list(lits)
        while work:
            b = work.pop()
            for pred in self._g.predecessors(b):
                if pred not in region and member(pred) and (pred not in lits or lits[pred].match is not b):
                    region.add(pred)
                    work.append(pred)
        work = list(region)
        while work:
            b = work.pop()
            for succ in self._succs_in_region(b, lits):
                if succ not in region and member(succ):
                    region.add(succ)
                    work.append(succ)
        entries = [
            b for b in region if self._g.in_degree(b) == 0 or any(p not in region for p in self._g.predecessors(b))
        ]
        while len(entries) > 1:
            # a branch above the entries that does more than branch heads the dispatch
            preds = {p for b in entries for p in self._g.predecessors(b)}
            if len(preds) != 1:
                return 0
            (head,) = preds
            kind = self._dispatch(head, base, entry=True)
            if kind is None or head in region or any(succ not in region for succ in self._g.successors(head)):
                return 0
            kinds[head] = kind
            region.add(head)
            entries = [head]
        if not entries:
            return 0
        entry = entries[0]
        while kinds.get(entry) == "jump":
            # jumps leading into the dispatch stay outside it
            region.discard(entry)
            entry = next(iter(self._g.successors(entry)))
            if entry not in region:
                return 0
        if entry in lits:
            return 0
        if any(p in region for p in self._g.predecessors(entry)):
            return 0
        default = None
        empties = []  # (block, target): `len(s) == 0` leading out of the dispatch, the case ""
        for b in region:
            for succ in self._g.successors(b):
                if succ in region or (b in lits and succ is lits[b].match):
                    continue
                if self._is_empty_edge(b, succ, kinds):
                    empties.append((b, succ))
                    continue
                if default is not None and succ is not default:
                    return 0
                default = succ
        if default is None:
            return 0
        for b, succ in empties:
            if succ is not default:
                other = next(t for t in self._r.cond_targets(b) if t is not succ)
                lits[b] = _LitTest(b, group[0].value, "", succ, other)
                kinds[b] = "lit"
        inside = [lits[b] for b in region if b in lits]
        if len(inside) < 2 or len({t.text for t in inside}) != len(inside):
            return 0
        if any(t.match in region or t.match is default for t in inside):
            return 0
        for t in inside:
            if self._route(entry, t.text, region, lits, kinds) is not t.block:
                return 0
        # the default merge must not tell the region's paths into it apart
        keys = {(b.addr, b.idx) for b in region}
        for stmt in default.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                vals = [v for k, v in stmt.src.src_and_vvars if k in keys]
                if any(v is None for v in vals) and any(v is not None for v in vals):
                    return 0
                resolved = [self._r.values.resolve(v) for v in vals if v is not None]
                if any(not v.likes(resolved[0]) for v in resolved[1:]):
                    return 0
        # cases sharing a body sit together, so they structure as one condition
        first_at: dict = {}
        for t in sorted(inside, key=lambda t: (t.block.addr, t.block.idx or 0)):
            first_at.setdefault(self._body(t.match), (t.block.addr, t.block.idx or 0))
        order = sorted(inside, key=lambda t: (first_at[self._body(t.match)], t.block.addr, t.block.idx or 0))
        self._rebuild(entry, order, region, default)
        return 1

    def _is_empty_edge(self, block: Block, succ: Block, kinds: dict) -> bool:
        kind = kinds.get(block)
        if not (isinstance(kind, tuple) and kind[0] == "len" and kind[1][2] == 0 and kind[1][0] in ("CmpEQ", "CmpNE")):
            return False
        targets = self._r.cond_targets(block)
        if targets is None or targets[0] is targets[1]:
            return False
        return succ is (targets[0] if kind[1][0] == "CmpEQ" else targets[1])

    def _body(self, block: Block) -> Block:
        seen = set()
        while block not in seen and self._jump_only(block):
            seen.add(block)
            block = next(iter(self._g.successors(block)))
        return block

    def _succs_in_region(self, block: Block, lits: dict) -> list:
        succs = list(self._g.successors(block))
        if block in lits:
            return [s for s in succs if s is not lits[block].match]
        return succs

    def _route(self, entry: Block, text: str, region: set, lits: dict, kinds: dict) -> Block | None:
        """The compare the dispatch sends the string ``text`` to."""
        data = text.encode("utf-8")
        cur = entry
        for _ in range(len(region) + 1):
            if cur not in region:
                return None
            kind = kinds[cur]
            if kind == "lit":
                if lits[cur].text == text:
                    return cur
                cur = lits[cur].mismatch
                continue
            if kind == "jump":
                cur = next(iter(self._g.successors(cur)))
                continue
            (op, _, c), signed = kind[1], kind[2]
            if kind[0] == "len":
                value = len(data)
            else:
                off, size = kind[3], kind[4]
                if off + size > len(data):
                    return None
                value = int.from_bytes(data[off : off + size], self._endness)
                if signed:
                    value = _signed(value, size * 8)
                    c = _signed(c & ((1 << (size * 8)) - 1), size * 8)
            taken = _eval_cmp(op, value, c)
            targets = self._r.cond_targets(cur)
            if targets is None:
                return None
            cur = targets[0] if taken else targets[1]
        return None

    def _rebuild(self, entry: Block, order: list[_LitTest], region: set, default: Block) -> None:
        r = self._r
        bits = r.project.arch.bits
        for b in list(self._g.successors(entry)):
            self._g.remove_edge(entry, b)
        first = order[0].block
        last = entry.statements[-1]
        entry.statements = [
            *entry.statements[:-1],
            Jump(last.idx, Const(0, first.addr, bits), first.idx, **last.tags),
        ]
        self._g.add_edge(entry, first)
        for i, t in enumerate(order):
            nxt = order[i + 1].block if i + 1 < len(order) else default
            cj = t.block.statements[-1]
            lit = next((o for o in getattr(_strip(cj.condition), "operands", ()) if isinstance(o, StringLiteral)), None)
            if lit is None or lit.data != t.text:
                lit = StringLiteral(r.manager.next_atom(), t.text, r._string_bits, **cj.tags)
            new_cond = r.compare("CmpEQ", t.value, lit, None, cj.condition.tags)
            t.block.statements = [
                *t.block.statements[:-1],
                ConditionalJump(
                    cj.idx,
                    new_cond,
                    Const(0, t.match.addr, bits),
                    Const(0, nxt.addr, bits),
                    true_target_idx=t.match.idx,
                    false_target_idx=nxt.idx,
                    **cj.tags,
                ),
            ]
            for b in list(self._g.successors(t.block)):
                self._g.remove_edge(t.block, b)
            self._g.add_edge(t.block, t.match)
            self._g.add_edge(t.block, nxt)
        kept = {entry, *(t.block for t in order)}
        for b in region - kept:
            self._g.remove_node(b)
            r._block_by_addr_and_idx.pop((b.addr, b.idx), None)
        # the default is now entered from the last compare only
        keys = {(b.addr, b.idx) for b in region}
        last_key = (order[-1].block.addr, order[-1].block.idx)
        stmts = []
        for stmt in default.statements:
            if isinstance(stmt, Assignment) and isinstance(stmt.src, Phi):
                entries = [(k, v) for k, v in stmt.src.src_and_vvars if k not in keys]
                inner = [v for k, v in stmt.src.src_and_vvars if k in keys]
                if inner:
                    entries.append((last_key, inner[0]))
                stmt = Assignment(
                    stmt.idx, stmt.dst, Phi(stmt.src.idx, stmt.src.bits, entries, **stmt.src.tags), **stmt.tags
                )
            stmts.append(stmt)
        default.statements = stmts


def _signed(v: int, bits: int) -> int:
    return v - (1 << bits) if v >> (bits - 1) & 1 else v


def _eval_cmp(op: str, a: int, b: int) -> bool:
    return {
        "CmpEQ": a == b,
        "CmpNE": a != b,
        "CmpLT": a < b,
        "CmpLE": a <= b,
        "CmpGT": a > b,
        "CmpGE": a >= b,
    }[op]


def _addr_and_offset(addr: Expression) -> tuple[Expression | None, int]:
    if isinstance(addr, Const):
        return None, addr.value_int
    if isinstance(addr, BinaryOp) and addr.op == "Add":
        lhs, rhs = addr.operands
        if isinstance(rhs, Const):
            return lhs, rhs.value_int
        if isinstance(lhs, Const):
            return rhs, lhs.value_int
    return addr, 0
