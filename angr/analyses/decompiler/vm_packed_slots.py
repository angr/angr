"""
Forward reads of packed VM operand-stack slots to the values written into them.

VMProtect's 32-bit handlers push two dwords and read them back as one qword (NOR, AND, ...), or push the stack pointer
and read a dword through it. Stack SSA unifies such overlapping accesses into one aggregate variable, written by Insert
chains and read by Extracts at other offsets:

    v1 = Insert(Insert(Insert(0, 0, flags), 4, a), 8, a)
    v2 = Insert(v1, 4, Extract(v1, 32bits@8))
    ... (Extract(~Extract(v2, 64bits@4), 32bits@4) & ~Extract(Extract(v2, 64bits@4), 32bits@0)) ...

SPropagator never propagates an Insert definition, so the operands of the VM's boolean operation never meet and the
dead flag words in the slot stay alive. This pass rewrites each such read to the bits of the definition it reads,
recursively through the definitions of the variables it reaches (``~a & ~a`` above). It stops at a definition whose
bits are, or contain, a load, a call, a dirty expression or a tmp: moving those to the read would change what they
read or how often they run. Rewriting a read of an SSA variable to the expression that defined it is otherwise
value-preserving wherever the read is.
"""

from __future__ import annotations

import logging
from collections import defaultdict

import archinfo
import networkx

from angr.ailment.block_walker import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Phi,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment

from .ailgraph_walker import AILGraphWalker
from .peephole_optimizations.known_bits import known_bits

l = logging.getLogger(name=__name__)

# reads wider than a register are struct copies; their pieces are not what this pass is about
_MAX_READ_BITS = 64


def _mask(bits: int) -> int:
    return (1 << bits) - 1


def _const_int(expr: Expression) -> int | None:
    if isinstance(expr, Const) and isinstance(expr.value, int):
        return expr.value_int
    return None


def _le_shift(offset: Expression, endness, outer_bits: int, inner_bits: int) -> int | None:
    """Bit position of a little-endian Insert/Extract at a constant byte offset."""
    if not (isinstance(offset, Const) and isinstance(offset.value, int)) or endness != archinfo.Endness.LE:
        return None
    shift = offset.value * 8
    if shift < 0 or shift + inner_bits > outer_bits:
        return None
    return shift


def _is_int_convert(expr: Expression) -> bool:
    return isinstance(expr, Convert) and expr.from_type == Convert.TYPE_INT and expr.to_type == Convert.TYPE_INT


class _Unmovable(AILBlockViewer):
    """Whether an expression reads memory, has side effects or depends on block-local tmps."""

    def __init__(self):
        super().__init__()
        self.found = False

    def _handle_Load(self, *args, **kwargs):
        self.found = True

    def _handle_Call(self, *args, **kwargs):
        self.found = True

    def _handle_DirtyExpression(self, *args, **kwargs):
        self.found = True

    def _handle_Tmp(self, *args, **kwargs):
        self.found = True


def _unmovable(expr: Expression) -> bool:
    viewer = _Unmovable()
    viewer.walk_expression(expr)
    return viewer.found


class _BitSlicer:
    """Expressions for bit ranges of a value, looking through stack-variable definitions."""

    def __init__(self, defs: dict[int, Expression], dies=None, slice_reads=None):
        self.defs = defs
        # (varid, shift, width) -> number of reads of exactly those bits
        self._slice_reads = slice_reads if slice_reads is not None else {}
        # varid -> whether every use of that version is a read this pass can take apart (or the base of a version
        # that also dies): only then may its reads be pointed at an older version of the same slot
        self._dies = dies if dies is not None else (lambda varid: True)
        # slices already built, keyed by (varid or expression, shift, width): a chain of self-NORs (~a & ~a, a being a
        # read of the previous slot) would otherwise be rebuilt, and grow, twice per level
        self._memo: dict[tuple, tuple[Expression, bool, bool]] = {}
        # how many slices so far read through a definition; a slice that did not keeps its original spelling
        self._forwards = 0
        # True while resolving the partial reads inside a whole value: a whole read of a slot there stays a read
        self._whole = False
        # read -> what _ReadRewriter rewrote it to (None: left alone)
        self.forwarded: dict[Expression, Expression | None] = {}

    @staticmethod
    def _leaf(expr: Expression, shift: int, width: int) -> Expression:
        if shift == 0 and width == expr.bits:
            return expr
        if (isinstance(expr, VirtualVariable) or expr.bits > 64) and shift % 8 == 0:
            return Extract(None, width, expr, Const(None, shift // 8, 64), archinfo.Endness.LE)
        if shift:
            expr = BinaryOp(None, "Shr", [expr, Const(None, shift, 8)], False, bits=expr.bits)
        return Convert(None, expr.bits, width, False, expr)

    def part(self, expr: Expression, shift: int, width: int) -> tuple[Expression, bool]:
        """
        Bits [shift, shift + width) of ``expr``, and whether it was decomposed structurally (False: only wrapped in an
        Extract or Convert).
        """
        # the slicing steps below are generators that yield (expr, shift, width) for each sub-slice they need; they run
        # on this explicit stack, since a chain of slot versions is as long as the VM code that writes it
        stack = [self._part(expr, shift, width)]
        result = None
        while True:
            try:
                request = stack[-1].send(result)
            except StopIteration as done:
                stack.pop()
                if not stack:
                    return done.value
                result = done.value
            else:
                stack.append(self._part(*request))
                result = None

    def _part(self, expr: Expression, shift: int, width: int):
        c = _const_int(expr)
        if c is not None:
            return Const(None, (c >> shift) & _mask(width), width), True
        if isinstance(expr, VirtualVariable):
            if self._whole and shift == 0 and width == expr.bits:
                return expr, True
            return (yield from self._part_vvar(expr, shift, width))
        return (
            yield from self._memoized(
                (expr, shift, width, self._whole), lambda: self._part_expr(expr, shift, width), expr, shift, width
            )
        )

    def _memoized(self, key, compute, expr: Expression, shift: int, width: int):
        cached = self._memo.get(key)
        if cached is None:
            before = self._forwards
            outer, self._whole = self._whole, shift == 0 and width == expr.bits
            try:
                out, exact = yield from compute()
            finally:
                self._whole = outer
            forwarded = self._forwards != before
            if shift == 0 and width == expr.bits:
                if not forwarded:
                    # the whole value and nothing below it read through a definition: keep it as it was
                    out, exact = expr, True
            cached = self._memo[key] = (out, exact, forwarded)
        elif cached[2]:
            self._forwards += 1
        return cached[0], cached[1]

    def _part_expr(self, expr: Expression, shift: int, width: int):
        if shift == 0 and width == expr.bits:
            if isinstance(expr, (UnaryOp, BinaryOp)):
                return (yield from self._resolve_whole(expr)), True
            if not isinstance(expr, (Extract, Convert)):
                return expr, True
            # an Extract or a truncation is itself a read of part of a value: slice what it reads
        if expr.bits <= 64:
            zeros, ones = known_bits(expr)
            hole = _mask(width) << shift
            if (zeros | ones) & hole == hole:
                return Const(None, (ones >> shift) & _mask(width), width), True

        if isinstance(expr, Insert):
            r = yield from self._part_insert(expr, shift, width)
            if r is not None:
                return r, True
        elif isinstance(expr, Extract):
            s = _le_shift(expr.offset, expr.endness, expr.base.bits, expr.bits)
            if s is not None:
                return (yield expr.base, s + shift, width)[0], True
        elif _is_int_convert(expr):
            if shift + width <= min(expr.from_bits, expr.to_bits):
                return (yield expr.operand, shift, width)[0], True
            if expr.to_bits > expr.from_bits and not expr.is_signed and shift >= expr.from_bits:
                return Const(None, 0, width), True
        elif isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg" and expr.operand.bits == expr.bits:
            inner, exact = yield expr.operand, shift, width
            if exact:
                return UnaryOp(None, "BitwiseNeg", inner, bits=width), True
        elif isinstance(expr, BinaryOp) and not expr.floating_point and len(expr.operands) == 2:
            r = yield from self._part_binop(expr, shift, width)
            if r is not None:
                return r, True
        if shift == 0 and width == expr.bits:
            return expr, True
        return self._leaf(expr, shift, width), False

    def _resolve_whole(self, expr: Expression):
        """``expr`` itself, with the partial slot reads below it resolved; the node keeps its idx and tags."""
        children = list(expr.operands) if isinstance(expr, BinaryOp) else [expr.operand]
        out = expr
        for child in children:
            new_child = (yield child, 0, child.bits)[0]
            if new_child is not child and not new_child.likes(child):
                _, out = out.replace(child, new_child)
        if out is expr:
            return expr
        return _fold_same_operands(out) or out

    def _part_vvar(self, vvar: VirtualVariable, shift: int, width: int):
        # only slices that read through the definition are shared: a slice of the read itself must keep that read's
        # atom, or later passes count two reads of the variable as one
        key = (vvar.varid, shift, width)
        cached = self._memo.get(key)
        if cached is not None and cached[2]:
            self._forwards += 1
            return cached[0], cached[1]
        if cached is not None:
            return self._leaf(vvar, shift, width), cached[1]
        before = self._forwards
        outer, self._whole = self._whole, False
        try:
            out, exact = yield from self._slice_vvar(vvar, shift, width)
        finally:
            self._whole = outer
        self._memo[key] = (out, exact, self._forwards != before)
        return out, exact

    def _slice_vvar(self, vvar: VirtualVariable, shift: int, width: int):
        src = self.defs.get(vvar.varid) if vvar.was_stack else None
        if src is not None and src.bits == vvar.bits:
            out, exact = yield src, shift, width
            if not exact and not _reads_a_variable(out):
                # the definition does not come apart (e.g. a select of two whole values, or arithmetic): copying it
                # into every read duplicates the computation, so read the slot. Bits of another variable are a read.
                return self._leaf(vvar, shift, width), True
            if _unmovable(out):
                # the bits are a load or a call result: read this version of the slot instead
                return self._leaf(vvar, shift, width), True
            if self._slice_reads.get((vvar.varid, shift, width), 0) > 1 and not _plain(out):
                # several reads take these bits and they are a computation: copying it into each read duplicates
                # it (Tigress reads a state word twice in one update), so read the slot
                return self._leaf(vvar, shift, width), True
            if not self._dies(vvar.varid) and _reads_older_version(out, vvar):
                # this version stays live for its other uses; reading an older version of the slot here as well
                # would keep both alive, and codegen then splits the slot into separate variables
                return self._leaf(vvar, shift, width), True
            self._forwards += 1
            return out, True
        return self._leaf(vvar, shift, width), shift == 0 and width == vvar.bits

    def _part_insert(self, expr: Insert, shift: int, width: int):
        s = _le_shift(expr.offset, expr.endness, expr.bits, expr.value.bits)
        if s is None:
            return None
        end = s + expr.value.bits
        if s <= shift and shift + width <= end:
            return (yield expr.value, shift - s, width)[0]
        if shift + width <= s or end <= shift:
            return (yield expr.base, shift, width)[0]
        # the read straddles the inserted value: concatenate the pieces on each side of its boundaries
        cuts = sorted({shift, shift + width, *(x for x in (s, end) if shift < x < shift + width)})
        out = None
        for lo, hi in zip(cuts, cuts[1:]):
            piece = (yield expr, lo, hi - lo)[0]
            out = piece if out is None else BinaryOp(None, "Concat", [piece, out], False, bits=piece.bits + out.bits)
        return out

    def _part_binop(self, expr: BinaryOp, shift: int, width: int):
        a, b = expr.operands
        amount = _const_int(b)
        op = expr.op
        if op == "Mul" and amount is not None and amount > 0 and amount & (amount - 1) == 0:
            op, amount = "Shl", amount.bit_length() - 1
        if op in {"And", "Or", "Xor"} and a.bits == b.bits == expr.bits:
            pa, ea = yield a, shift, width
            pb, eb = yield b, shift, width
            if ea or eb:
                out = BinaryOp(None, op, [pa, pb], False, bits=width)
                return _fold_same_operands(out) or out
        elif op == "Concat":
            low = b.bits
            if shift + width <= low:
                return (yield b, shift, width)[0]
            if shift >= low:
                return (yield a, shift - low, width)[0]
            lo_part = (yield b, shift, low - shift)[0]
            hi_part = (yield a, 0, shift + width - low)[0]
            return BinaryOp(None, "Concat", [hi_part, lo_part], False, bits=width)
        elif op == "Shl" and amount is not None and a.bits == expr.bits:
            if shift + width <= amount:
                return Const(None, 0, width)
            if shift >= amount:
                return (yield a, shift - amount, width)[0]
        elif op == "Shr" and amount is not None and a.bits == expr.bits and shift + amount + width <= expr.bits:
            return (yield a, shift + amount, width)[0]
        return None


def _plain(expr: Expression) -> bool:
    """Whether ``expr`` only moves bits of variables and constants around (Extract, Convert, Concat, constant shifts,
    complements): nothing a reader would have to recompute."""
    if isinstance(expr, (VirtualVariable, Const)):
        return True
    if isinstance(expr, Extract):
        return _plain(expr.base)
    if isinstance(expr, Convert) or (isinstance(expr, UnaryOp) and expr.op == "BitwiseNeg"):
        return _plain(expr.operand)
    if isinstance(expr, BinaryOp) and len(expr.operands) == 2:
        a, b = expr.operands
        if expr.op == "Concat":
            return _plain(a) and _plain(b)
        if expr.op in {"Shr", "Shl"} and _const_int(b) is not None:
            return _plain(a)
    return False


def _reads_a_variable(expr: Expression) -> bool:
    """Whether ``expr`` only selects bits of a variable (or a constant): Extracts, truncations and constant shifts."""
    while True:
        if isinstance(expr, Extract):
            expr = expr.base
        elif isinstance(expr, Convert):
            expr = expr.operand
        elif isinstance(expr, BinaryOp) and expr.op == "Shr" and _const_int(expr.operands[1]) is not None:
            expr = expr.operands[0]
        else:
            return isinstance(expr, (VirtualVariable, Const))


class _StackVVars(AILBlockViewer):
    """Stack variables in an expression: varid -> stack offset, and how often each occurs."""

    def __init__(self):
        super().__init__()
        self.offsets: dict[int, int] = {}
        self.count: defaultdict[int, int] = defaultdict(int)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.offsets[expr.varid] = expr.stack_offset
            self.count[expr.varid] += 1


def _stack_vvars(expr: Expression) -> _StackVVars:
    collector = _StackVVars()
    collector.walk_expression(expr)
    return collector


def _reads_older_version(expr: Expression, vvar: VirtualVariable) -> bool:
    """Whether ``expr`` reads another version of ``vvar``'s stack slot."""
    return any(
        offset == vvar.stack_offset and varid != vvar.varid for varid, offset in _stack_vvars(expr).offsets.items()
    )


class _SlotUses(AILBlockViewer):
    """
    For each stack variable: how often it is used, how many of those uses are inside a read this pass may forward
    (a byte-aligned partial read), and which variables it is the base of an Insert for (``dst = Insert(it, ...)``).
    """

    def __init__(self):
        super().__init__()
        self.uses: defaultdict[int, int] = defaultdict(int)
        self.forwardable: defaultdict[int, int] = defaultdict(int)
        self.insert_into: defaultdict[int, list[int]] = defaultdict(list)
        # (varid, shift, width) -> how many reads take exactly those bits of the variable
        self.slice_reads: defaultdict[tuple[int, int, int], int] = defaultdict(int)
        self._in_read = 0

    def _handle_Assignment(self, stmt_idx, stmt, block):
        src = stmt.src
        if (
            isinstance(stmt.dst, VirtualVariable)
            and stmt.dst.was_stack
            and isinstance(src, Insert)
            and isinstance(src.base, VirtualVariable)
            and src.base.was_stack
        ):
            self.insert_into[src.base.varid].append(stmt.dst.varid)
            self.forwardable[src.base.varid] += 1
        # the destination is a definition, not a use
        self._handle_expr(1, src, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if expr.was_stack:
            self.uses[expr.varid] += 1

    def _read(self, expr, handler, *args):
        read = _read_of_part(expr) if not self._in_read else None
        if read is not None and read[1] % 8 == 0 and read[2] % 8 == 0 and read[2] <= _MAX_READ_BITS:
            for varid, n in _stack_vvars(read[0]).count.items():
                self.forwardable[varid] += n
            if isinstance(read[0], VirtualVariable):
                self.slice_reads[(read[0].varid, read[1], read[2])] += 1
            self._in_read += 1
            try:
                return handler(*args)
            finally:
                self._in_read -= 1
        return handler(*args)

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        return self._read(expr, super()._handle_Extract, expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        return self._read(expr, super()._handle_Convert, expr_idx, expr, stmt_idx, stmt, block)


def _dying_versions(collector: _SlotUses):
    """
    A predicate on stack variables: whether every use of the variable is inside a read this pass may forward, or is
    the base of an Insert that defines another such variable. Those are the versions forwarding can leave unused.
    """
    memo: dict[int, bool] = {}

    def enter(varid: int) -> bool:
        memo[varid] = False  # a cycle (through a loop) keeps the versions in it live
        return collector.uses[varid] <= collector.forwardable[varid]

    def dies(varid: int) -> bool:
        if varid in memo:
            return memo[varid]
        if not enter(varid):
            return False
        # depth first on an explicit stack: the versions of a slot form a chain as long as the VM code that writes it
        stack = [(varid, iter(collector.insert_into[varid]))]
        while stack:
            current, next_versions = stack[-1]
            for next_varid in next_versions:
                if next_varid not in memo and enter(next_varid):
                    stack.append((next_varid, iter(collector.insert_into[next_varid])))
                    break
                if not memo[next_varid]:
                    # a live next version keeps every version on the stack live
                    return False
            else:
                memo[current] = True
                stack.pop()
        return True

    return dies


def _fold_same_operands(expr: Expression) -> Expression | None:
    """x & x and x | x are x, x ^ x is 0: a VM's NOT is a NOR of a value with itself."""
    if not isinstance(expr, BinaryOp) or expr.op not in {"And", "Or", "Xor"} or len(expr.operands) != 2:
        return None
    a, b = expr.operands
    if a.bits != b.bits or not a.likes(b):
        return None
    return Const(None, 0, expr.bits) if expr.op == "Xor" else a


def _read_of_part(expr: Expression) -> tuple[Expression, int, int] | None:
    """(value, shift, width) if ``expr`` reads bits of a wider value."""
    if isinstance(expr, Extract):
        s = _le_shift(expr.offset, expr.endness, expr.base.bits, expr.bits)
        if s is not None:
            return expr.base, s, expr.bits
    elif _is_int_convert(expr) and expr.to_bits < expr.from_bits:
        return expr.operand, 0, expr.to_bits
    return None


class _ReadRewriter(AILBlockRewriter):
    def __init__(self, slicer: _BitSlicer):
        super().__init__(update_block=False)
        self.slicer = slicer
        self.rewritten = 0

    def _forward(self, expr: Expression) -> Expression | None:
        # the rewriter re-walks each result until it settles, so the same read comes back once per copy of it
        cache = self.slicer.forwarded
        if expr in cache:
            out = cache[expr]
        else:
            out = cache[expr] = self._forward_uncached(expr)
        if out is not None:
            self.rewritten += 1
        return out

    def _forward_uncached(self, expr: Expression) -> Expression | None:
        read = _read_of_part(expr)
        if read is None:
            return None
        base, shift, width = read
        if width > _MAX_READ_BITS:
            return None
        if shift % 8 or width % 8:
            # a bit extraction, e.g. a flag of a flags word: the flags-word folds read those in their own shape
            return None
        if isinstance(base, VirtualVariable):
            if not base.was_stack or base.varid not in self.slicer.defs:
                return None
        elif not isinstance(base, (Insert, BinaryOp, UnaryOp, Extract)):
            return None
        out, exact = self.slicer.part(base, shift, width)
        if not exact or out.likes(expr):
            return None
        return out

    def _handle_Extract(self, expr_idx, expr, stmt_idx, stmt, block):
        out = self._forward(expr)
        if out is not None:
            return out
        return super()._handle_Extract(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Convert(self, expr_idx, expr, stmt_idx, stmt, block):
        out = self._forward(expr)
        if out is not None:
            return out
        return super()._handle_Convert(expr_idx, expr, stmt_idx, stmt, block)


def forward_packed_slot_reads(ail_graph: networkx.DiGraph) -> int:
    """Rewrite partial reads of stack variables in ``ail_graph`` in place. Returns the number of reads rewritten."""
    defs: dict[int, Expression] = {}
    for block in ail_graph:
        for stmt in block.statements:
            if (
                isinstance(stmt, Assignment)
                and isinstance(stmt.dst, VirtualVariable)
                and stmt.dst.was_stack
                and not isinstance(stmt.src, Phi)
            ):
                defs[stmt.dst.varid] = stmt.src
    if not defs:
        return 0
    collector = _SlotUses()
    for block in ail_graph:
        collector.walk(block)
    slicer = _BitSlicer(defs, _dying_versions(collector), collector.slice_reads)
    replacements = {}
    total = 0
    for block in list(ail_graph):
        rewriter = _ReadRewriter(slicer)
        new_block = rewriter.walk(block)
        if rewriter.rewritten and new_block is not block:
            replacements[block] = new_block
            total += rewriter.rewritten
    if replacements:
        AILGraphWalker(ail_graph, replacements.get, replace_nodes=True).walk()
    l.debug("forward_packed_slot_reads: %d reads rewritten", total)
    return total
