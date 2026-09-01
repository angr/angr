from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, NamedTuple

from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StackBaseOffset,
    VirtualVariable,
)
from angr.ailment import AILBlockRewriter
from angr.ailment.statement import Assignment, Return, Statement, Store

if TYPE_CHECKING:
    import networkx

l = logging.getLogger(name=__name__)

#: How many candidate addresses one expression may reduce to before it is treated as unknown.
#: Phi nodes merge frame pointers along different paths, so a handful is normal; a large set means
#: the value is not usefully constrained.
MAX_ADDRS = 8


class StackAddr(NamedTuple):
    """
    A store/load address expressed relative to the frame register it is rooted at.

    ``chain`` is the sequence of operations applied to that register, normalised so that two
    addresses computed the same way compare equal. An alignment mask is kept in the chain rather
    than abandoning the address, which is what makes a devirtualised VM body tractable: its slots
    are reached through ``((sp - c) & ~0xf) +/- d``.

    ``offset`` is the total constant displacement when the chain is purely additive, and None once
    a mask is involved.
    """

    base: str  # "sp" or "bp"
    chain: tuple[tuple[str, int], ...]
    offset: int | None

    def is_affine(self) -> bool:
        return self.offset is not None


class StackDeadStoreEliminator:
    """
    Remove stores to frame slots that nothing ever reads.

    angr resolves stack addresses through StackPointerTracker, which reports a numeric offset per
    instruction. That works for compiler-generated prologues and fails completely on a
    devirtualised VM body: the VM computes its own stack pointer, so the tracker's affine domain
    goes TOP at the first obfuscated update and every later address stays an opaque ``BinaryOp``
    over a register variable. Such addresses are never promoted to stack variables, so the
    ordinary dead-store elimination never sees them.

    This pass sidesteps the numeric route. In SSA every virtual variable has exactly one
    definition, so a frame-register variable can be resolved *symbolically* by following
    assignments back to the function's incoming sp/bp -- no per-instruction tracking needed.

    An expression resolves to a *set* of candidate addresses rather than a single one. A phi
    merging the frame pointer along two paths is extremely common, and demanding that its inputs
    agree would throw away perfectly good information: the access is to one of two known slots,
    which is all the analysis needs. A load marks every address it might touch as read; a store
    dies only if none of the addresses it might write can alias any of them.

    Safety. The analysis only ever removes a store it can prove nothing reads, and every
    uncertainty keeps the store:

    * an address that does not reduce to sp/bp is unresolvable. As the target of a *load* it could
      read anywhere on the frame, so it disables the pass entirely; as the target of a *store* it
      simply keeps that store.
    * two addresses off different frame roots are assumed to alias. So are two whose operation
      chains diverge on an alignment mask, since their displacement is then unknowable.
    * a slot whose address escapes -- passed to a call, or stored as data -- is assumed to be read
      and is kept.

    Calls are taken to read only escaped slots, not the whole frame. That is the ordinary C
    assumption (a callee reaches the caller's locals only through pointers it was given) and is
    the same assumption the calling-convention-driven dead-code elimination already makes. It is
    why this pass is opt-in rather than on by default.

    The incoming stack pointer is taken to be ``sp_alignment``-aligned (16 by default, the
    x86-64 ABI). That makes an alignment mask exact rather than opaque: if ``sp`` is a multiple of
    16 then ``(sp + off) & ~0xf`` is ``sp + (off - (off & 0xf))``, a plain offset. Without it every
    masked address is incomparable with every unmasked one and nothing can be proven dead on an
    aligned frame. Only masks clearing no more bits than the known alignment are resolved this way;
    anything wider, or rooted at a frame register whose alignment is not known, stays opaque.

    A load through a pointer that is *not* frame-derived -- one read out of memory, say -- is
    treated the same way, and for the same reason: such a pointer can only name a frame slot whose
    address escaped, and every escaped slot is already protected. A load whose address *is*
    frame-derived but does not reduce to a known set still disables the pass, because it could
    name any slot. Both rest on the escape analysis being complete, which is the assumption to
    challenge first if this pass ever removes something it should not.
    """

    def __init__(
        self, arch, ail_graph: networkx.DiGraph, sp_alignment: int = 16, sp_shift: int = 0, ail_manager=None
    ):
        self.arch = arch
        self._graph = ail_graph
        # What the incoming stack pointer is known to be aligned to. Any mask that clears no more
        # bits than this is exactly computable, which turns an aligned frame into ordinary
        # affine offsets. 1 disables the reasoning.
        self._sp_alignment = sp_alignment if sp_alignment and sp_alignment > 0 else 1
        # StackBaseOffset offsets are measured from the stack base; ours are measured from the
        # incoming sp, and the two differ by the shift the stack-pointer tracker was seeded with.
        self._sp_shift = sp_shift
        # Rewritten expressions need their own atom index; sharing one makes SSA bookkeeping
        # see a single expression defining at several locations.
        self._ail_manager = ail_manager
        self.rewritten_addrs = 0
        self._sp_offset = arch.sp_offset
        self._bp_offset = getattr(arch, "bp_offset", None)

        self._vvar_addr: dict[int, tuple[StackAddr, ...]] = {}
        self._vvar_def: dict[int, Expression] = {}
        self.removed = 0
        self.bailed_reason: str | None = None
        self.n_loads = 0
        self.n_unresolved_loads = 0
        self.n_opaque_loads = 0
        self.n_overwritten = 0

    #
    # address resolution
    #

    def _root_base(self, vvar: VirtualVariable) -> str | None:
        """Is this variable the function's incoming sp/bp?"""
        if not getattr(vvar, "was_reg", False):
            return None
        oident = vvar.oident
        if oident == self._sp_offset:
            return "sp"
        if self._bp_offset is not None and oident == self._bp_offset:
            return "bp"
        return None

    @staticmethod
    def _extend(addrs: tuple[StackAddr, ...], op: str, value: int) -> tuple[StackAddr, ...]:
        out = []
        for addr in addrs:
            chain = (*addr.chain, (op, value))
            if op == "add" and addr.offset is not None:
                out.append(StackAddr(addr.base, chain, addr.offset + value))
            else:
                # A mask makes the displacement unknowable; the chain still identifies the slot.
                out.append(StackAddr(addr.base, chain, None))
        return _dedup(out)

    def _apply_mask(self, addrs: tuple[StackAddr, ...], mask: int) -> tuple[StackAddr, ...]:
        """
        Apply ``& mask``, resolving it exactly where the known alignment allows.

        Only a mask that clears a run of low bits is an alignment mask, and it is only exact when
        the bits it clears are already known to be zero in the base -- i.e. when the granularity
        divides the alignment we were told to assume.
        """
        full = (1 << self.arch.bits) - 1
        low = (~mask) & full  # the bits this mask clears
        exact = low & (low + 1) == 0 and (low + 1) <= self._sp_alignment and self._sp_alignment % (low + 1) == 0

        out: list[StackAddr] = []
        for addr in addrs:
            if exact and addr.base == "sp" and addr.offset is not None:
                aligned = addr.offset - (addr.offset & low)
                out.append(StackAddr(addr.base, (*addr.chain, ("add", aligned - addr.offset)), aligned))
            else:
                # Unknown alignment for this base, a non-alignment mask, or an already-opaque
                # offset: keep the mask in the chain so identical computations still match.
                out.append(StackAddr(addr.base, (*addr.chain, ("and", mask)), None))
        return _dedup(out)

    def resolve(self, expr: Expression, depth: int = 0) -> tuple[StackAddr, ...] | None:
        """Reduce an address expression to the frame addresses it may denote, or None."""
        if depth > 16:
            return None

        if isinstance(expr, StackBaseOffset):
            off = expr.offset if isinstance(expr.offset, int) else None
            if off is None:
                return None
            return (StackAddr("sp", (("add", off),), off),)

        if isinstance(expr, VirtualVariable):
            known = self._vvar_addr.get(expr.varid)
            if known is not None:
                return known
            base = self._root_base(expr)
            if base is not None and expr.varid not in self._vvar_def:
                # No in-graph definition: this is the value the register held on entry.
                return (StackAddr(base, (), 0),)
            return None

        if isinstance(expr, BinaryOp):
            op0, op1 = expr.operands
            if expr.op in ("Add", "Sub"):
                # only a constant displacement keeps the address comparable
                if isinstance(op1, Const) and isinstance(op1.value, int):
                    inner = self.resolve(op0, depth + 1)
                    if inner is None:
                        return None
                    delta = op1.value if expr.op == "Add" else -op1.value
                    return self._extend(inner, "add", _signed(delta, self.arch.bits))
                if expr.op == "Add" and isinstance(op0, Const) and isinstance(op0.value, int):
                    inner = self.resolve(op1, depth + 1)
                    if inner is None:
                        return None
                    return self._extend(inner, "add", _signed(op0.value, self.arch.bits))
                # A non-constant displacement is still usable when it is bounded to a few values.
                for base_expr, index_expr in ((op0, op1), (op1, op0)):
                    if expr.op == "Sub" and base_expr is op1:
                        continue
                    inner = self.resolve(base_expr, depth + 1)
                    if inner is None:
                        continue
                    values = self._bounded_values(index_expr, depth + 1)
                    if values is None or not values or len(values) * len(inner) > MAX_ADDRS:
                        continue
                    sign = -1 if expr.op == "Sub" else 1
                    out: list[StackAddr] = []
                    for value in sorted(values):
                        out.extend(self._extend(inner, "add", sign * value))
                    return _dedup(out)
                return None
            if expr.op == "And" and isinstance(op1, Const) and isinstance(op1.value, int):
                inner = self.resolve(op0, depth + 1)
                if inner is None:
                    return None
                return self._apply_mask(inner, op1.value)
            return None

        # Convert changes the width, so the address is no longer the value we reasoned about.
        return None

    def _bounded_values(self, expr: Expression, depth: int = 0) -> frozenset[int] | None:
        """
        The values an expression can take, when that set is small enough to enumerate.

        A VM indexes its frame with terms like ``(64 & x) >> 3`` or ``(extract(bp) & 15) >> 3``.
        The masked operand is unknown, but the mask bounds it: ``x & m`` can only be a subset of
        m's bits, whatever x is. Shifting narrows it further. That turns an "unknown index" into
        two or three concrete offsets, which is the difference between an unanalysable address and
        an ordinary one.
        """
        if depth > 8:
            return None

        if isinstance(expr, Const) and isinstance(expr.value, int):
            return frozenset({_signed(expr.value, self.arch.bits)})

        if isinstance(expr, Convert):
            # widening or narrowing does not change a small non-negative value
            return self._bounded_values(expr.operand, depth + 1)

        if isinstance(expr, BinaryOp):
            op0, op1 = expr.operands
            if expr.op == "And":
                # And is commutative; the mask may sit on either side
                mask_expr = op1 if isinstance(op1, Const) else (op0 if isinstance(op0, Const) else None)
                if mask_expr is None or not isinstance(mask_expr.value, int):
                    return None
                mask = mask_expr.value & ((1 << self.arch.bits) - 1)
                if bin(mask).count("1") > 6:
                    return None
                bits = [1 << i for i in range(self.arch.bits) if mask & (1 << i)]
                values = {0}
                for bit in bits:
                    values |= {v | bit for v in values}
                return frozenset(values)
            if expr.op in ("Shr", "Sar", "Shl") and isinstance(op1, Const) and isinstance(op1.value, int):
                inner = self._bounded_values(op0, depth + 1)
                if inner is None:
                    return None
                shift = op1.value
                if shift < 0 or shift >= self.arch.bits:
                    return None
                if expr.op == "Shl":
                    return frozenset(v << shift for v in inner)
                # our bounded values come from masks, so they are non-negative and >> is exact
                if any(v < 0 for v in inner):
                    return None
                return frozenset(v >> shift for v in inner)
        return None

    def _is_frame_derived(self, expr: Expression, depth: int = 0) -> bool:
        """
        Does any part of this address come from the frame pointer?

        Distinguishes "an address on the frame that I could not pin down" -- which could name any
        slot -- from "a pointer that has nothing to do with the frame", which can only reach a
        slot whose address escaped.
        """
        if depth > 16 or expr is None:
            return False
        if self.resolve(expr) is not None:
            return True
        if isinstance(expr, VirtualVariable):
            return expr.varid in self._vvar_addr or self._root_base(expr) is not None
        return any(self._is_frame_derived(sub, depth + 1) for sub in _subexpressions(expr))

    #
    # propagation
    #

    def _collect_definitions(self) -> None:
        for block in self._graph:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._vvar_def[stmt.dst.varid] = stmt.src

    def _propagate(self) -> None:
        """
        Resolve every frame-derived virtual variable, to a fixed point.

        A phi can only be resolved once its inputs are, so this needs more than one round; SSA
        keeps it terminating, and rounds stop as soon as one adds nothing.
        """
        self._collect_definitions()
        for _ in range(32):
            changed = False
            for varid, src in self._vvar_def.items():
                if varid in self._vvar_addr:
                    continue
                resolved = self._resolve_phi(src) if isinstance(src, Phi) else self.resolve(src)
                if resolved is not None:
                    self._vvar_addr[varid] = resolved
                    changed = True
            if not changed:
                break

    def _resolve_phi(self, phi: Phi) -> tuple[StackAddr, ...] | None:
        """
        The union of the frame addresses the incoming values may hold.

        Every input must be frame-relative -- one unknown predecessor means the merged value could
        be anything -- but the inputs need not agree. Merging the frame pointer along two paths is
        the normal shape, and the union says exactly what it should: one of these slots.
        """
        merged: list[StackAddr] = []
        for _, vvar in phi.src_and_vvars:
            if vvar is None:
                return None
            resolved = self._vvar_addr.get(vvar.varid)
            if resolved is None:
                base = self._root_base(vvar)
                if base is not None and vvar.varid not in self._vvar_def:
                    resolved = (StackAddr(base, (), 0),)
            if resolved is None:
                return None
            merged.extend(resolved)
            if len(merged) > MAX_ADDRS * 4:
                return None
        out = _dedup(merged)
        return out if len(out) <= MAX_ADDRS else None

    #
    # aliasing
    #

    @staticmethod
    def _relative(a: StackAddr, b: StackAddr) -> tuple[int, int] | None:
        """
        Displacements of two addresses from their common computation, or None if incomparable.

        Everything up to the longest shared prefix of the two chains evaluates to the same value,
        whatever it is -- masks included. If each remaining suffix is purely additive, the two
        addresses differ by exactly the difference of those suffixes, so they can be compared
        numerically even though neither offset is known on its own. This is what makes an
        alignment-masked frame ``((sp - c) & ~0xf) +/- d`` analysable.
        """
        n = 0
        while n < len(a.chain) and n < len(b.chain) and a.chain[n] == b.chain[n]:
            n += 1
        off_a = off_b = 0
        for op, value in a.chain[n:]:
            if op != "add":
                return None
            off_a += value
        for op, value in b.chain[n:]:
            if op != "add":
                return None
            off_b += value
        return off_a, off_b

    def _may_alias(self, a: StackAddr, a_size: int, b: StackAddr, b_size: int) -> bool:
        if a.base != b.base:
            # sp and bp normally address the same frame, so a differing root proves nothing.
            return True
        rel = self._relative(a, b)
        if rel is None:
            # The chains diverge on a mask; the displacement between them is unknowable.
            return True
        off_a, off_b = rel
        return off_a < off_b + b_size and off_b < off_a + a_size

    def _any_alias(self, addrs: tuple[StackAddr, ...], size: int, others: list[tuple[StackAddr, int]]) -> bool:
        return any(self._may_alias(a, size, o, o_size) for a in addrs for o, o_size in others)

    #
    # escape analysis
    #

    def _escaping(self) -> list[tuple[StackAddr, int]]:
        """Frame addresses handed to a call or written into memory, which a callee could read."""
        escaped: list[tuple[StackAddr, int]] = []

        def scan(expr: Expression, depth: int = 0) -> None:
            if depth > 16 or expr is None:
                return
            resolved = self.resolve(expr)
            if resolved is not None:
                escaped.extend((a, self.arch.bytes) for a in resolved)
                return
            for sub in _subexpressions(expr):
                scan(sub, depth + 1)

        for block in self._graph:
            for stmt in block.statements:
                for call in _calls_in(stmt):
                    for arg in call.args or ():
                        if isinstance(arg, Expression):
                            scan(arg)
                if isinstance(stmt, Store):
                    # the *data* being stored, not the destination
                    scan(stmt.data)
                elif isinstance(stmt, Return):
                    for value in getattr(stmt, "ret_exprs", None) or ():
                        if isinstance(value, Expression):
                            scan(value)
        return escaped

    #
    # overwritten stores
    #

    def _slot_universe(self):
        """
        Every distinct slot a store writes, which is the only thing liveness is ever asked about.

        Keeping the domain finite lets an opaque read mean "every slot is live" while still
        allowing a later definite overwrite to kill one of them -- the precision that a single
        boolean top flag throws away.
        """
        slots: dict[tuple[str, tuple, int], tuple[StackAddr, int]] = {}
        for block in self._graph:
            for stmt in block.statements:
                if not isinstance(stmt, Store):
                    continue
                addrs = self.resolve(stmt.addr)
                if addrs is None or len(addrs) != 1:
                    continue
                addr = addrs[0]
                slots[(addr.base, addr.chain, stmt.size)] = (addr, stmt.size)
        return slots

    def _block_events(self, block, slots, escaped):
        """
        Per-statement (gen, kill) over the slot universe, in program order.

        gen needs only a *may* read -- every slot a load might touch becomes live. kill needs a
        *must* overwrite: one known destination, matching width.
        """
        all_keys = frozenset(slots)
        call_gen = frozenset(
            key for key, (addr, size) in slots.items()
            if any(self._may_alias(addr, size, e, e_size) for e, e_size in escaped)
        )

        events = []
        for idx, stmt in enumerate(block.statements):
            gen: set = set()
            for load in _loads_in(stmt):
                resolved = self.resolve(load.addr)
                if resolved is None:
                    if not _is_constant_address(load.addr):
                        gen |= all_keys  # opaque pointer: could read any slot
                    continue
                for read_addr in resolved:
                    gen |= {
                        key for key, (addr, size) in slots.items()
                        if self._may_alias(addr, size, read_addr, load.size)
                    }
            if next(_calls_in(stmt), None) is not None:
                gen |= call_gen

            kill = None
            if isinstance(stmt, Store):
                addrs = self.resolve(stmt.addr)
                if addrs is not None and len(addrs) == 1:
                    kill = (addrs[0].base, addrs[0].chain, stmt.size)

            events.append((idx, frozenset(gen), kill))
        return events

    @staticmethod
    def _transfer(events, live_out, collect_dead=False):
        """
        Walk a block backwards, returning the live set at its entry.

        Within a statement the reads happen before the write, so going backwards the write is
        applied first and the reads generated after it.
        """
        live = live_out
        dead: set[int] = set()
        for idx, gen, kill in reversed(events):
            if kill is not None:
                if kill not in live and collect_dead:
                    dead.add(idx)
                live = live - {kill}
            if gen:
                live = live | gen
        return live, dead

    def _dead_by_liveness(self, escaped: list[tuple[StackAddr, int]]) -> dict[tuple[int, int | None], set[int]]:
        """
        Stores whose value no path can ever read.

        A backward fixpoint over the block graph. Subsumes the in-block case -- a store overwritten
        later in its own block is one whose slot is not live at that point -- and the never-read
        case, since a slot nothing reads is never live anywhere. At a function exit only escaped
        slots stay live: the caller can reach those and nothing else of our frame.
        """
        slots = self._slot_universe()
        if not slots:
            return {}

        blocks = {(b.addr, b.idx): b for b in self._graph}
        events = {key: self._block_events(b, slots, escaped) for key, b in blocks.items()}
        exit_live = frozenset(
            key for key, (addr, size) in slots.items()
            if any(self._may_alias(addr, size, e, e_size) for e, e_size in escaped)
        )

        succs = {key: [(x.addr, x.idx) for x in self._graph.successors(b)] for key, b in blocks.items()}
        preds = {key: [(x.addr, x.idx) for x in self._graph.predecessors(b)] for key, b in blocks.items()}
        live_in: dict[tuple[int, int | None], frozenset] = {key: frozenset() for key in blocks}

        def live_out_of(key):
            if not succs[key]:
                return exit_live
            out: frozenset = frozenset()
            for succ in succs[key]:
                out |= live_in[succ]
            return out

        worklist = list(blocks)
        rounds = 0
        limit = 200 * max(len(blocks), 1)
        while worklist and rounds < limit:
            rounds += 1
            key = worklist.pop()
            new_in, _ = self._transfer(events[key], live_out_of(key))
            if new_in != live_in[key]:
                live_in[key] = new_in
                worklist.extend(preds[key])

        if rounds >= limit:
            l.debug("StackDeadStoreEliminator: liveness did not converge; removing nothing.")
            return {}

        dead: dict[tuple[int, int | None], set[int]] = defaultdict(set)
        for key in blocks:
            _, block_dead = self._transfer(events[key], live_out_of(key), collect_dead=True)
            if block_dead:
                dead[key] |= block_dead
        return dead

    def _stack_base_offset(self, addr_expr):
        """``StackBaseOffset`` for an address that reduces to one exact frame offset, else None."""
        if isinstance(addr_expr, StackBaseOffset):
            return None
        addrs = self.resolve(addr_expr)
        if addrs is None or len(addrs) != 1:
            return None
        addr = addrs[0]
        if addr.base != "sp" or addr.offset is None:
            return None
        idx = self._ail_manager.next_atom() if self._ail_manager is not None else None
        return StackBaseOffset(idx, addr_expr.bits, addr.offset + self._sp_shift)

    def _rewrite_addresses(self) -> int:
        if self._ail_manager is None:
            # Without an atom source new expressions would collide; skip rather than corrupt SSA.
            return 0

        """
        Turn resolved frame addresses into StackBaseOffset.

        This is the rewrite SPropagator would have done if StackPointerTracker could follow the
        stack pointer. Without it the frame is never expressed in terms of the stack base, so
        variable recovery creates no locals and the emitted C is stack-pointer arithmetic --
        ``rsp = rsp - 216`` and loads through it -- instead of variables. The dead-store analysis
        already knows each address exactly; this hands that knowledge to the rest of the pipeline.
        """
        eliminator = self

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)
                self.count = 0

            def _handle_Store(self, stmt_idx, stmt, block):
                rebuilt = super()._handle_Store(stmt_idx, stmt, block)
                current = rebuilt if rebuilt is not None else stmt
                sba = eliminator._stack_base_offset(current.addr)
                if sba is None:
                    return rebuilt
                self.count += 1
                return Store(
                    current.idx, sba, current.data, current.size, current.endness,
                    current.guard, **current.tags,
                )

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
                current = rebuilt if rebuilt is not None else expr
                sba = eliminator._stack_base_offset(current.addr)
                if sba is None:
                    return rebuilt
                self.count += 1
                return Load(
                    current.idx, sba, current.size, current.endness,
                    guard=current.guard, alt=current.alt, **current.tags,
                )

        rewriter = _Rewriter()
        for block in list(self._graph):
            new_block = rewriter.walk(block)
            if new_block is not None and new_block is not block:
                block.statements = list(new_block.statements)
        return rewriter.count

    #
    # entry point
    #

    def run(self) -> tuple[networkx.DiGraph, int]:
        self._propagate()

        reads: list[tuple[StackAddr, int]] = []
        examples: list[str] = []
        n_loads = n_unresolved = n_opaque = 0
        for block in self._graph:
            for stmt in block.statements:
                for load in _loads_in(stmt):
                    n_loads += 1
                    resolved = self.resolve(load.addr)
                    if resolved is not None:
                        reads.extend((a, load.size) for a in resolved)
                        continue
                    if _is_constant_address(load.addr):
                        # a global; cannot name a frame slot
                        continue
                    if not self._is_frame_derived(load.addr):
                        # An opaque pointer. It can only reach a slot whose address escaped, and
                        # every escaped slot is kept below, so this read needs no further handling.
                        n_opaque += 1
                        continue
                    n_unresolved += 1
                    if len(examples) < 3:
                        examples.append(str(load.addr)[:100])
        self.n_loads = n_loads
        self.n_unresolved_loads = n_unresolved
        self.n_opaque_loads = n_opaque

        if n_unresolved:
            # One load we cannot place could read any frame slot, so nothing is provably dead.
            self.bailed_reason = (
                f"{n_unresolved} of {n_loads} load addresses do not reduce to the frame; examples: {examples}"
            )
            return self._graph, 0

        escaped = self._escaping()

        dead: dict[tuple[int, int | None], set[int]] = defaultdict(set)
        candidates = 0
        for block in self._graph:
            for idx, stmt in enumerate(block.statements):
                if not isinstance(stmt, Store):
                    continue
                addrs = self.resolve(stmt.addr)
                if addrs is None:
                    continue
                candidates += 1
                # A store with several possible destinations has to be dead for all of them.
                if self._any_alias(addrs, stmt.size, reads):
                    continue
                if self._any_alias(addrs, stmt.size, escaped):
                    continue
                dead[(block.addr, block.idx)].add(idx)

        overwritten = self._dead_by_liveness(escaped)
        n_never_read = sum(len(v) for v in dead.values())
        for key, indices in overwritten.items():
            dead[key] |= indices
        self.n_overwritten = sum(len(v) for v in dead.values()) - n_never_read

        if not dead:
            self.rewritten_addrs = self._rewrite_addresses()
            l.debug(
                "StackDeadStoreEliminator: %d resolvable stores, none provably dead "
                "(%d reads, %d opaque pointer reads, %d escaped addresses).",
                candidates, len(reads), n_opaque, len(escaped),
            )
            return self._graph, 0

        for block in list(self._graph):
            key = (block.addr, block.idx)
            if key not in dead:
                continue
            drop = dead[key]
            block.statements = [s for i, s in enumerate(block.statements) if i not in drop]
            self.removed += len(drop)

        self.rewritten_addrs = self._rewrite_addresses()
        l.debug(
            "StackDeadStoreEliminator: removed %d of %d resolvable stack stores "
            "(%d never read, %d dead by liveness); rewrote %d addresses to StackBaseOffset.",
            self.removed, candidates, self.removed - self.n_overwritten, self.n_overwritten,
            self.rewritten_addrs,
        )
        return self._graph, self.removed


def _dedup(addrs) -> tuple[StackAddr, ...]:
    seen: dict[StackAddr, None] = {}
    for a in addrs:
        seen[a] = None
    return tuple(seen)


def _signed(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def _is_constant_address(expr: Expression) -> bool:
    return isinstance(expr, Const)


def _subexpressions(expr: Expression):
    for attr in ("operands", "args"):
        seq = getattr(expr, attr, None)
        if seq:
            yield from (s for s in seq if isinstance(s, Expression))
    for attr in ("operand", "addr", "expr"):
        sub = getattr(expr, attr, None)
        if isinstance(sub, Expression):
            yield sub


def _calls_in(stmt: Statement):
    """Every Call expression anywhere inside a statement (calls are expressions here)."""
    yield from _walk(stmt, Call)


def _loads_in(stmt: Statement):
    """Every Load anywhere inside a statement."""
    yield from _walk(stmt, Load)


def _walk(stmt: Statement, cls):
    stack: list = [stmt]
    seen = 0
    while stack and seen < 8192:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, cls):
            yield cur
        for attr in ("addr", "data", "src", "dst", "expr", "operand", "condition", "target", "ret_expr"):
            sub = getattr(cur, attr, None)
            if isinstance(sub, Expression):
                stack.append(sub)
        for attr in ("operands", "args"):
            seq = getattr(cur, attr, None)
            if seq:
                stack.extend(s for s in seq if isinstance(s, Expression))
