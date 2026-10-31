from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING, NamedTuple

from angr.ailment import AILBlockRewriter, AILBlockViewer
from angr.ailment.expression import (
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    StackBaseOffset,
    Tmp,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import (
    Assignment,
    ConditionalJump,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Statement,
    Store,
)
from angr.analyses.stack_pointer_tracker import abi_entry_sp_alignment

from .variadic_call_reads import VARIADIC_STACK_ARGS_TAG, VARIADIC_UNRESOLVED_TAG, is_unresolved_variadic_call

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

    What is known about the incoming stack pointer modulo a power of two (``entry_sp_alignment``,
    by default the ABI's: rsp + 8 is 16-aligned on AMD64, word alignment elsewhere) makes an
    alignment mask within that power of two exact: ``(sp + off) & ~m`` is a plain offset. A wider
    mask, or one on a frame register whose alignment is not known, stays opaque.

    A load through a pointer that is *not* frame-derived -- one read out of memory, say -- is
    treated the same way, and for the same reason: such a pointer can only name a frame slot whose
    address escaped, and every escaped slot is already protected. A load whose address *is*
    frame-derived but does not reduce to a known set still disables the pass, because it could
    name any slot. Both rest on the escape analysis being complete, which is the assumption to
    challenge first if this pass ever removes something it should not.
    """

    def __init__(
        self,
        arch,
        ail_graph: networkx.DiGraph,
        entry_sp_alignment: tuple[int, int] | None = None,
        sp_shift: int = 0,
        ail_manager=None,
        single_valued_bp: bool = True,
        call_sp_adjustments: dict[int, int | None] | None = None,
    ):
        self.arch = arch
        self._graph = ail_graph
        # Collapse a frame pointer that merges to several frame addresses down to one.
        #
        # A frame pointer adjusted on only some paths reaches the merge as a phi over two or more
        # offsets.  Nothing downstream can express that: StackBaseOffset denotes one slot, so the
        # accesses stay register-relative and are emitted as pointer arithmetic rather than
        # locals.  Assuming one canonical frame recovers them.
        #
        # This is a deobfuscation heuristic, not a sound approximation: the discarded values are
        # real on their paths, so a store may now be credited with overwriting a slot it only
        # conditionally overwrites, and could kill an earlier store that some path still reads.
        # Escaped slots stay live either way, which bounds the damage but does not remove it.
        self._single_valued_bp = single_valued_bp
        # What the incoming stack pointer is known to be aligned to. Any mask that clears no more
        # bits than this is exactly computable, which turns an aligned frame into ordinary
        # affine offsets. 1 disables the reasoning.
        # the incoming sp is known to be residue modulo modulus
        self._sp_modulus, self._sp_residue = entry_sp_alignment or abi_entry_sp_alignment(arch)
        # StackBaseOffset offsets are measured from the stack base; ours are measured from the
        # incoming sp, and the two differ by the shift the stack-pointer tracker was seeded with.
        self._sp_shift = sp_shift
        # Rewritten expressions need their own atom index; sharing one makes SSA bookkeeping
        # see a single expression defining at several locations.
        self._ail_manager = ail_manager
        self.rewritten_addrs = 0
        self._sp_offset = arch.sp_offset
        self._bp_offset = getattr(arch, "bp_offset", None)
        # StackPointerTracker's per-call-instruction sp change across the callee (ret pop + callee cleanup)
        self._call_sp_adjustments = call_sp_adjustments
        # sp variables defined by a call instruction, which hold sp after the callee returns -> that adjustment
        self._call_sp_defs: dict[int, int | None] = {}
        # (block key, stmt idx) -> the slots an unresolved variadic call there may read (see variadic_call_reads)
        self._variadic_reads: dict[tuple[int, int | None, int], list[tuple[StackAddr, int]]] = {}

        self._vvar_addr: dict[int, tuple[StackAddr, ...]] = {}
        # optimistic values of variables on def-use cycles, while _resolve_cycles runs
        self._cycle_values: dict[int, tuple[StackAddr, ...] | None] | None = None
        self._cycle_pending: set[int] = set()
        self._vvar_def: dict[int, Expression] = {}
        self._bp_vvars: set[int] = set()
        # variables whose definition resolves only by forwarding through frame slots
        self._fwd_vvar_addr: dict[int, tuple[StackAddr, ...]] = {}
        self.forwarded = 0
        self.collapsed_bp = 0
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
        Apply ``& mask``, resolving it exactly where what is known of the incoming sp allows.

        Only a mask that clears a run of low bits is an alignment mask, and it is only exact when its granularity
        divides the modulus the incoming sp is known for.
        """
        full = (1 << self.arch.bits) - 1
        low = (~mask) & full  # the bits this mask clears
        gran = low + 1
        exact = low & gran == 0 and self._sp_modulus % gran == 0

        out: list[StackAddr] = []
        for addr in addrs:
            if exact and addr.base == "sp" and addr.offset is not None:
                aligned = addr.offset - (self._sp_residue + addr.offset) % gran
                out.append(StackAddr(addr.base, (*addr.chain, ("add", aligned - addr.offset)), aligned))
            else:
                # Unknown alignment for this base, a non-alignment mask, or an already-opaque
                # offset: keep the mask in the chain so identical computations still match.
                out.append(StackAddr(addr.base, (*addr.chain, ("and", mask)), None))
        return _dedup(out)

    def resolve(self, expr: Expression, depth: int = 0, slots: dict | None = None) -> tuple[StackAddr, ...] | None:
        """
        Reduce an address expression to the frame addresses it may denote, or None.

        With ``slots`` (the frame slots known to hold frame addresses at this point), a load from
        such a slot resolves to the address it holds.
        """
        addrs = self.resolve_value(expr, depth, slots)
        if addrs is None or any(_is_negated(a) for a in addrs):
            return None
        return addrs

    def _negate(self, addrs: tuple[StackAddr, ...], bitwise: bool) -> tuple[StackAddr, ...] | None:
        """``~x`` is ``-x - 1``, so negating ``(+/-)base + off`` flips the sign of base."""
        out = []
        for addr in addrs:
            if addr.offset is None:
                return None
            base = addr.base[1:] if _is_negated(addr) else "-" + addr.base
            off = _signed(-addr.offset - (1 if bitwise else 0), self.arch.bits)
            out.append(StackAddr(base, (("add", off),), off))
        return _dedup(out)

    def resolve_value(
        self, expr: Expression, depth: int = 0, slots: dict | None = None
    ) -> tuple[StackAddr, ...] | None:
        """
        Like ``resolve``, but also admits negated frame values ``-base + off`` (base "-sp"/"-bp"),
        which are not addresses but turn back into one under another negation. VMProtect computes
        ``sp - c`` as ``~(~sp + c)``.
        """
        if depth > 16:
            return None

        if isinstance(expr, Tmp):
            entry = slots.get(("tmp", expr.tmp_idx)) if slots is not None else None
            return entry[1] if entry is not None else None

        if isinstance(expr, Load):
            if slots is None or expr.size != self.arch.bytes or expr.guard is not None:
                return None
            addrs = self.resolve(expr.addr, depth + 1, slots)
            if addrs is None:
                return None
            out: list[StackAddr] = []
            for addr in addrs:
                entry = slots.get(_slot_key(addr))
                if entry is None or entry[2] != expr.endness:
                    return None
                out.extend(entry[1])
            forwarded = _dedup(out)
            return forwarded if len(forwarded) <= MAX_ADDRS else None

        if isinstance(expr, StackBaseOffset):
            off = expr.offset if isinstance(expr.offset, int) else None
            if off is None:
                return None
            # StackBaseOffset is measured from the stack base; addresses here from the incoming sp
            off -= self._sp_shift
            return (StackAddr("sp", (("add", off),), off),)

        if isinstance(expr, VirtualVariable):
            known = self._vvar_addr.get(expr.varid)
            if known is not None:
                return known
            if self._cycle_values is not None and expr.varid in self._cycle_pending:
                if expr.varid not in self._cycle_values:
                    raise _NotReached
                return self._cycle_values[expr.varid]
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
                    inner = self.resolve_value(op0, depth + 1, slots)
                    if inner is None:
                        return None
                    delta = op1.value if expr.op == "Add" else -op1.value
                    return self._extend(inner, "add", _signed(delta, self.arch.bits))
                if isinstance(op0, Const) and isinstance(op0.value, int):
                    inner = self.resolve_value(op1, depth + 1, slots)
                    if inner is None:
                        return None
                    if expr.op == "Sub":
                        # C - x == -x + C
                        inner = self._negate(inner, False)
                        if inner is None:
                            return None
                    return self._extend(inner, "add", _signed(op0.value, self.arch.bits))
                # A non-constant displacement is still usable when it is bounded to a few values.
                for base_expr, index_expr in ((op0, op1), (op1, op0)):
                    if expr.op == "Sub" and base_expr is op1:
                        continue
                    inner = self.resolve_value(base_expr, depth + 1, slots)
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
                inner = self.resolve_value(op0, depth + 1, slots)
                if inner is None:
                    return None
                return self._apply_mask(inner, op1.value)
            if expr.op in ("And", "Or") and not isinstance(op0, Const) and not isinstance(op1, Const):
                # x & x == x | x == x; VMProtect's NOR/NAND handlers apply this to two copies of one value
                a = self.resolve_value(op0, depth + 1, slots)
                if a is None or len(a) != 1 or a[0].offset is None:
                    return None
                b = self.resolve_value(op1, depth + 1, slots)
                if b is None or len(b) != 1 or (b[0].base, b[0].offset) != (a[0].base, a[0].offset):
                    return None
                return a
            return None

        if isinstance(expr, UnaryOp) and expr.op in ("BitwiseNeg", "Neg") and expr.bits == self.arch.bits:
            inner = self.resolve_value(expr.operand, depth + 1, slots)
            if inner is None:
                return None
            return self._negate(inner, expr.op == "BitwiseNeg")

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
        if self.resolve_value(expr) is not None:
            return True
        if isinstance(expr, VirtualVariable):
            return expr.varid in self._vvar_addr or self._root_base(expr) is not None
        return any(self._is_frame_derived(sub, depth + 1) for sub in _subexpressions(expr))

    #
    # propagation
    #

    def _collect_definitions(self) -> None:
        self._call_sp_defs = {}
        for block in self._graph:
            for idx, stmt in enumerate(block.statements):
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    self._vvar_def[stmt.dst.varid] = stmt.src
                    base = self._root_base(stmt.dst)
                    if base == "bp":
                        self._bp_vvars.add(stmt.dst.varid)
                    elif base == "sp":
                        self._check_call_sp_def(block, idx)

    def _check_call_sp_def(self, block, idx: int) -> None:
        """
        Record the sp definition at ``idx`` if it is the last sp write of a call instruction.

        SSA gives a call no sp definition, so later instructions read the return-address push although the callee has
        popped it since. Like StackPointerTracker and SPropagator, take such a variable to hold sp after the call: its
        definition plus the callee's adjustment, or unresolved if that is unknown or the call itself reads the push.
        """
        stmt = block.statements[idx]
        ins = stmt.tags.get("ins_addr")
        if ins is None or stmt.tags.get("sp_after_call"):
            return
        later = [s for s in block.statements[idx + 1 :] if s.tags.get("ins_addr") == ins]
        if any(
            isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable) and self._root_base(s.dst) == "sp"
            for s in later
        ):
            return
        has_call = any(next(_calls_in(s), None) is not None for s in later)
        adjustments = self._call_sp_adjustments or {}
        if not has_call and ins not in adjustments:
            return
        # a call StackPointerTracker did not see, or one a pass removed: the callee's effect is unknown
        adjustment = adjustments.get(ins) if has_call else None
        varid = stmt.dst.varid
        if adjustment is not None and any(v.varid == varid for s in later for v in _walk(s, VirtualVariable)):
            adjustment = None
        self._call_sp_defs[varid] = adjustment

    def _def_value(self, varid: int, resolved: tuple[StackAddr, ...] | None) -> tuple[StackAddr, ...] | None:
        """The value a variable holds at its uses, given what its definition evaluates to."""
        if resolved is None or varid not in self._call_sp_defs:
            return resolved
        adjustment = self._call_sp_defs[varid]
        if adjustment is None:
            return None
        return self._extend(resolved, "add", adjustment)

    @staticmethod
    def _canonical_frame_addr(addrs: tuple[StackAddr, ...]) -> StackAddr:
        """
        The one of several merged frame addresses to treat as *the* frame pointer.

        Fewest derivation steps wins: that is the value the frame pointer was established with,
        before any path took an adjustment.  Ties go to the highest offset, then to the chain
        itself, so the choice never depends on dictionary iteration order.
        """
        return min(
            addrs,
            key=lambda a: (len(a.chain), 0 if a.offset is not None else 1, -(a.offset or 0), a.chain),
        )

    def _propagate(self) -> None:
        """
        Resolve every frame-derived virtual variable, to a fixed point.

        A phi can only be resolved once its inputs are, so this needs more than one round; SSA
        keeps it terminating, and rounds stop as soon as one adds nothing.
        """
        self._vvar_def = {}
        self._bp_vvars = set()
        self._vvar_addr = {}
        self._collect_definitions()
        for varid, resolved in self._fwd_vvar_addr.items():
            if self._single_valued_bp and len(resolved) > 1 and varid in self._bp_vvars and _all_addresses(resolved):
                resolved = (self._canonical_frame_addr(resolved),)
            self._vvar_addr[varid] = resolved
        for _ in range(32):
            changed = False
            for varid, src in self._vvar_def.items():
                if varid in self._vvar_addr:
                    continue
                resolved = self._resolve_phi(src) if isinstance(src, Phi) else self.resolve_value(src)
                resolved = self._def_value(varid, resolved)
                if resolved is not None:
                    if (
                        self._single_valued_bp
                        and len(resolved) > 1
                        and varid in self._bp_vvars
                        and _all_addresses(resolved)
                    ):
                        resolved = (self._canonical_frame_addr(resolved),)
                        self.collapsed_bp += 1
                    self._vvar_addr[varid] = resolved
                    changed = True
            if not changed:
                break
        self._resolve_cycles()

    def _resolve_cycles(self) -> None:
        """
        Resolve variables that depend on themselves through a phi, e.g. a frame pointer carried around a loop.

        The rounds above need every phi input resolved first, so a cycle never resolves. Here the unresolved
        definitions are solved optimistically instead: start with no value, evaluate definitions skipping phi inputs
        not reached yet, and join each result into the variable's set until nothing changes. This is the least
        solution of the SSA equations over (not reached < address sets < unknown); every transfer is monotone, so
        each value any execution gives a variable is in its set. A cycle that keeps adding addresses goes unknown.
        """
        pending = {varid for varid in self._vvar_def if varid not in self._vvar_addr}
        if not pending:
            return
        values: dict[int, tuple[StackAddr, ...] | None] = {}
        self._cycle_values, self._cycle_pending = values, pending
        order = sorted(pending)
        try:
            for _ in range(64):
                changed = False
                for varid in order:
                    old = values.get(varid, _NOT_REACHED)
                    if old is None:
                        continue
                    src = self._vvar_def[varid]
                    try:
                        if isinstance(src, Phi):
                            resolved = self._resolve_phi_optimistic(src)
                        else:
                            resolved = self._def_value(varid, self.resolve_value(src))
                    except _NotReached:
                        continue
                    new = resolved if old is _NOT_REACHED else _join(old, resolved)
                    if new != old:
                        values[varid] = new
                        changed = True
                if not changed:
                    break
            else:
                return
        finally:
            self._cycle_values, self._cycle_pending = None, set()
        for varid, resolved in values.items():
            if resolved is not None:
                self._vvar_addr[varid] = resolved

    def _resolve_phi_optimistic(self, phi: Phi) -> tuple[StackAddr, ...] | None:
        """Like _resolve_phi, but inputs not reached yet are skipped; raises _NotReached if none is."""
        merged: tuple[StackAddr, ...] | object | None = _NOT_REACHED
        for _, vvar in phi.src_and_vvars:
            if vvar is None:
                return None
            try:
                resolved = self.resolve_value(vvar)
            except _NotReached:
                continue
            if resolved is None:
                return None
            merged = resolved if merged is _NOT_REACHED else _join(merged, resolved)
            if merged is None:
                return None
        if merged is _NOT_REACHED:
            raise _NotReached
        return merged

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
    # forwarding frame addresses through frame slots
    #

    def _slot_transfer(self, stmt: Statement, slots: dict) -> dict:
        """
        Frame slots holding a known frame address after ``stmt``.

        Must-information: a slot is tracked only while every path stores a resolvable frame address
        of pointer width into it. Anything that might write it untracked drops it: an overlapping
        store, a store whose destination is unknown, a call, or a statement we do not model.
        Block-local temporaries holding frame addresses ride along under ``("tmp", idx)`` keys.
        """
        if isinstance(stmt, (Assignment, ConditionalJump, Jump, Label, Return, SideEffectStatement)):
            if isinstance(stmt, Assignment) and isinstance(stmt.dst, Tmp):
                value = self.resolve_value(stmt.src, slots=slots)
                slots = {k: v for k, v in slots.items() if k != ("tmp", stmt.dst.tmp_idx)}
                if value is not None:
                    slots[("tmp", stmt.dst.tmp_idx)] = (None, value, None)
            if next(_calls_in(stmt), None) is not None:
                return _tmps_only(slots)
            return slots
        if not isinstance(stmt, Store):
            return _tmps_only(slots)

        addrs = self.resolve(stmt.addr, slots=slots)
        value = None
        if addrs is not None and len(addrs) == 1 and stmt.guard is None and stmt.size == self.arch.bytes:
            value = self.resolve_value(stmt.data, slots=slots)
        if next(_calls_in(stmt), None) is not None:
            slots = _tmps_only(slots)
        if addrs is None:
            # a constant address is a global; anything else may hit any slot
            return slots if isinstance(stmt.addr, Const) else _tmps_only(slots)
        out = {
            key: entry
            for key, entry in slots.items()
            if key[0] == "tmp" or not any(self._may_alias(entry[0], self.arch.bytes, a, stmt.size) for a in addrs)
        }
        if value is not None:
            out[_slot_key(addrs[0])] = (addrs[0], value, stmt.endness)
        return out

    @staticmethod
    def _slot_join(states: list[dict]) -> dict:
        out = dict(states[0])
        for other in states[1:]:
            for key in list(out):
                theirs = other.get(key)
                mine = out[key]
                if theirs is None or theirs[2] != mine[2]:
                    del out[key]
                    continue
                merged = _dedup(mine[1] + theirs[1])
                if len(merged) > MAX_ADDRS:
                    del out[key]
                else:
                    out[key] = (mine[0], merged, mine[2])
        return out

    def _slot_dataflow(self) -> dict[tuple[int, int | None], list[dict]] | None:
        """Per block, the slot state before each statement; None if the analysis does not converge."""
        blocks = {(b.addr, b.idx): b for b in self._graph}
        preds = {key: [(x.addr, x.idx) for x in self._graph.predecessors(b)] for key, b in blocks.items()}
        succs = {key: [(x.addr, x.idx) for x in self._graph.successors(b)] for key, b in blocks.items()}
        out_states: dict[tuple[int, int | None], dict] = {}

        def in_state(key):
            if not preds[key]:
                return {}
            known = [out_states[p] for p in preds[key] if p in out_states]
            if not known:
                return None
            # temporaries do not outlive their block
            return {k: v for k, v in self._slot_join(known).items() if k[0] != "tmp"}

        worklist = [key for key in blocks if not preds[key]]
        rounds = 0
        limit = 200 * max(len(blocks), 1)
        while worklist and rounds < limit:
            rounds += 1
            key = worklist.pop()
            state = in_state(key)
            if state is None:
                continue
            for stmt in blocks[key].statements:
                state = self._slot_transfer(stmt, state)
            if out_states.get(key) != state:
                out_states[key] = state
                worklist.extend(s for s in succs[key] if s not in worklist)
        if rounds >= limit:
            return None

        pre_states: dict[tuple[int, int | None], list[dict]] = {}
        for key, block in blocks.items():
            state = in_state(key)
            if state is None:
                continue
            per_stmt = []
            for stmt in block.statements:
                per_stmt.append(state)
                state = self._slot_transfer(stmt, state)
            pre_states[key] = per_stmt
        return pre_states

    def _forward_frame_slots(self) -> int:
        """
        Resolve addresses that a VM keeps in its own frame slots.

        A devirtualised body holds its frame pointer in a VM register, i.e. a frame slot, and forms
        local addresses as ``Load(slot) + k``. SSA has not reached memory yet, so nothing else can
        see that ``Load(slot)`` is a frame address. Rewriting such an address to a StackBaseOffset
        is what lets stack-variable recovery see one local instead of an array spanning the frame
        from the VM's frame pointer.
        """
        if self._ail_manager is None:
            return 0
        total = 0
        for _ in range(4):
            self._propagate()
            pre_states = self._slot_dataflow()
            if pre_states is None:
                break
            known_vvars = len(self._fwd_vvar_addr)
            count = self._rewrite_addresses(pre_states)
            total += count
            if count == 0 and len(self._fwd_vvar_addr) == known_vvars:
                break
        self.forwarded = total
        return total

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

    def _escaping(self, pre_states: dict | None = None, calls_only: bool = False) -> list[tuple[StackAddr, int]]:
        """
        Frame addresses handed to a call or written into memory, which a callee could read.

        With ``pre_states`` (see _slot_dataflow), values forwarded through frame slots count too; with ``calls_only``,
        only the addresses handed to calls.
        """
        escaped: list[tuple[StackAddr, int]] = []
        slots = None

        def scan(expr: Expression, depth: int = 0) -> None:
            if depth > 16 or expr is None:
                return
            resolved = self.resolve_value(expr, slots=slots)
            if resolved is not None:
                for a in resolved:
                    if _is_negated(a) and a.offset is None:
                        # an opaque chain aliases every slot of its base
                        escaped.append((StackAddr(a.base[1:], (*a.chain, ("neg", 0)), None), self.arch.bytes))
                    elif _is_negated(a):
                        # -base + off negates to base - off and complements to base - off - 1
                        for off in (-a.offset, -a.offset - 1):
                            escaped.append((StackAddr(a.base[1:], (("add", off),), off), self.arch.bytes))
                    else:
                        escaped.append((a, self.arch.bytes))
                return
            for sub in _subexpressions(expr):
                scan(sub, depth + 1)

        for block in self._graph:
            per_stmt = pre_states.get((block.addr, block.idx)) if pre_states is not None else None
            for idx, stmt in enumerate(block.statements):
                slots = per_stmt[idx] if per_stmt is not None else None
                for call in _calls_in(stmt):
                    for arg in call.args or ():
                        if isinstance(arg, Expression):
                            scan(arg)
                if calls_only:
                    continue
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

    def _unresolved_variadic_reads(
        self, escaped: list[tuple[StackAddr, int]]
    ) -> dict[tuple[int, int | None, int], list[tuple[StackAddr, int]]]:
        """
        The outgoing stack-argument area of each variadic call whose variadic arguments are unknown: from its first
        variadic stack-argument slot up to the lowest frame-local slot above it (one live after the call). Every slot
        if the stack pointer at the call is unknown. Once a frame address escapes, every call reads every slot anyway.
        """
        if escaped:
            return {}
        calls = []
        for block in self._graph:
            for idx, stmt in enumerate(block.statements):
                if any(is_unresolved_variadic_call(call) for call in _calls_in(stmt)):
                    calls.append((block, idx, next(c for c in _calls_in(stmt) if is_unresolved_variadic_call(c))))
        if not calls:
            return {}

        slots = self._slot_universe()
        if not slots:
            return {}
        top = max(
            (a.offset + size for a, size in slots.values() if a.base == "sp" and a.offset is not None), default=None
        )
        blocks = {(b.addr, b.idx): b for b in self._graph}
        events = {key: self._block_events(b, slots, escaped) for key, b in blocks.items()}
        live_in = self._live_in(blocks, events, frozenset())

        areas = {}
        for block, idx, call in calls:
            key = (block.addr, block.idx)
            start = self._first_stack_arg(block, idx, call)
            if start is None:
                areas[(block.addr, block.idx, idx)] = list(slots.values())
                continue
            live_out: frozenset = frozenset()
            for succ in self._graph.successors(block):
                live_out |= live_in.get((succ.addr, succ.idx), frozenset())
            live_after, _ = self._transfer(events[key][idx + 1 :], live_out)
            local_offsets = {
                slots[k][0].offset
                for k in live_after
                if slots[k][0].base == "sp" and slots[k][0].offset is not None and slots[k][0].offset >= start
            }
            end = min(local_offsets, default=top)
            if end is not None and end > start:
                areas[(block.addr, block.idx, idx)] = [(StackAddr("sp", (("add", start),), start), end - start)]
        return areas

    def _live_in(self, blocks, events, exit_live) -> dict:
        """Backward liveness fixpoint over the slot universe: block key -> slots live at its entry."""
        succs = {key: [(x.addr, x.idx) for x in self._graph.successors(b)] for key, b in blocks.items()}
        preds = {key: [(x.addr, x.idx) for x in self._graph.predecessors(b)] for key, b in blocks.items()}
        live_in: dict = {key: frozenset() for key in blocks}
        worklist = list(blocks)
        rounds = 0
        limit = 200 * max(len(blocks), 1)
        while worklist and rounds < limit:
            rounds += 1
            key = worklist.pop()
            out = exit_live if not succs[key] else frozenset().union(*(live_in[s] for s in succs[key]))
            new_in, _ = self._transfer(events[key], out)
            if new_in != live_in[key]:
                live_in[key] = new_in
                worklist.extend(preds[key])
        return live_in

    def _first_stack_arg(self, block, idx: int, call: Call) -> int | None:
        """Where an unresolved variadic call's first stack-argument slot is, relative to the incoming sp."""
        start = call.tags.get(VARIADIC_STACK_ARGS_TAG)
        if start is not None:
            return start - self._sp_shift
        delta = call.tags.get(VARIADIC_UNRESOLVED_TAG)
        if not isinstance(delta, int) or isinstance(delta, bool):
            return None
        # the last sp definition before the call, in this block or up a chain of single predecessors
        seen = set()
        stmts = block.statements[:idx]
        while True:
            for stmt in reversed(stmts):
                if (
                    isinstance(stmt, Assignment)
                    and isinstance(stmt.dst, VirtualVariable)
                    and stmt.dst.was_reg
                    and stmt.dst.reg_offset == self._sp_offset
                ):
                    addrs = self._vvar_addr.get(stmt.dst.varid)
                    if addrs is None or len(addrs) != 1 or addrs[0].base != "sp" or addrs[0].offset is None:
                        return None
                    return addrs[0].offset + delta
            seen.add(block)
            preds = list(self._graph.predecessors(block))
            if len(preds) != 1 or preds[0] in seen or len(seen) > 16:
                return None
            block = preds[0]
            stmts = block.statements

    def _slot_universe(self):
        """
        Every distinct slot a store writes, which is the only thing liveness is ever asked about.

        Keeping the domain finite lets an opaque read mean "every slot is live" while still
        allowing a later definite overwrite to kill one of them -- the precision that a single
        boolean top flag throws away.
        """
        slots: dict[tuple, tuple[StackAddr, int]] = {}
        for block in self._graph:
            for stmt in block.statements:
                if not isinstance(stmt, Store):
                    continue
                addrs = self.resolve(stmt.addr)
                if addrs is None or len(addrs) != 1:
                    continue
                addr = addrs[0]
                slots.setdefault((*_slot_key(addr), stmt.size), (addr, stmt.size))
        return slots

    def _block_events(self, block, slots, escaped):
        """
        Per-statement (gen, kill) over the slot universe, in program order.

        gen needs only a *may* read -- every slot a load might touch becomes live. kill needs a
        *must* overwrite: one known destination, matching width.
        """
        all_keys = frozenset(slots)
        # a callee handed a frame address may reach any slot from it: the extent of the object it points into is
        # unknown, and a VM computes its slots from one such pointer
        call_gen = all_keys if escaped else frozenset()

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
                        key for key, (addr, size) in slots.items() if self._may_alias(addr, size, read_addr, load.size)
                    }
            if next(_calls_in(stmt), None) is not None:
                gen |= call_gen
                for read_addr, read_size in self._variadic_reads.get((block.addr, block.idx, idx), ()):
                    gen |= {
                        key for key, (addr, size) in slots.items() if self._may_alias(addr, size, read_addr, read_size)
                    }

            kill = None
            if isinstance(stmt, Store) and stmt.guard is None:
                addrs = self.resolve(stmt.addr)
                if addrs is not None and len(addrs) == 1:
                    kill = (*_slot_key(addrs[0]), stmt.size)

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
            key
            for key, (addr, size) in slots.items()
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

    def _stack_base_offset(self, addr_expr, slots: dict | None = None):
        """
        ``StackBaseOffset`` for an address that reduces to one exact frame offset, else None.

        With ``slots``, only addresses that need forwarding through frame slots are rewritten.
        """
        if isinstance(addr_expr, StackBaseOffset):
            return None
        if addr_expr.bits != self.arch.bits:
            # a narrowed frame register is not the frame address we reasoned about
            return None
        if slots is not None:
            if self.resolve(addr_expr) is not None:
                return None
            addrs = self.resolve(addr_expr, slots=slots)
        else:
            addrs = self.resolve(addr_expr)
        if addrs is None or len(addrs) != 1:
            return None
        addr = addrs[0]
        if addr.base != "sp" or addr.offset is None:
            return None
        idx = self._ail_manager.next_atom() if self._ail_manager is not None else None
        return StackBaseOffset(idx, addr_expr.bits, addr.offset + self._sp_shift)

    def _rewrite_addresses(self, pre_states: dict | None = None) -> int:
        """
        Turn resolved frame addresses into StackBaseOffset.

        This is the rewrite SPropagator would have done if StackPointerTracker could follow the
        stack pointer. Without it the frame is never expressed in terms of the stack base, so
        variable recovery creates no locals and the emitted C is stack-pointer arithmetic --
        ``rsp = rsp - 216`` and loads through it -- instead of variables. The dead-store analysis
        already knows each address exactly; this hands that knowledge to the rest of the pipeline.

        Load and store addresses are the obvious case, but the frame register itself matters just
        as much. While ``rsp = rsp - 224`` stays register arithmetic every value derived from it
        does too, so the assignment always has a live use and can never be removed -- which is why
        raw ``rsp`` survives into the decompiled C. Rewriting the *source* of an assignment whose
        destination is the frame register makes it an ordinary constant definition, which
        SPropagator folds into its uses and dead-code elimination then drops.
        """
        if self._ail_manager is None:
            # Without an atom source new expressions would collide; skip rather than corrupt SSA.
            return 0

        eliminator = self

        class _Rewriter(AILBlockRewriter):
            def __init__(self):
                super().__init__(update_block=False)
                self.count = 0

            @staticmethod
            def _slots(stmt_idx, block):
                if pre_states is None:
                    return None
                per_stmt = pre_states.get((block.addr, block.idx))
                # a block the analysis never reached has no state: nothing is forwarded there
                return per_stmt[stmt_idx] if per_stmt is not None else {}

            def _rewrite(self, expr, stmt_idx=None, block=None):
                sba = eliminator._stack_base_offset(expr, self._slots(stmt_idx, block))
                if sba is None:
                    return None
                self.count += 1
                return sba

            def _handle_Assignment(self, stmt_idx, stmt, block):
                # the destination must stay an atom, so it is never walked
                src = self._handle_expr(1, stmt.src, stmt_idx, stmt, block)
                if src is None:
                    src = stmt.src
                slots = self._slots(stmt_idx, block)
                if slots and isinstance(stmt.dst, VirtualVariable) and eliminator.resolve_value(src) is None:
                    resolved = eliminator._def_value(stmt.dst.varid, eliminator.resolve_value(src, slots=slots))
                    if resolved is not None:
                        eliminator._fwd_vvar_addr[stmt.dst.varid] = resolved
                tags = stmt.tags
                if isinstance(stmt.dst, VirtualVariable) and stmt.dst.varid in eliminator._call_sp_defs:
                    # becomes sp after the call, which is what its uses read. Only once forwarding is done: the
                    # adjustment is applied to whatever the definition holds.
                    if pre_states is None:
                        after = self._rewrite_call_sp_def(stmt.dst.varid, src)
                        if after is not None:
                            # SPropagator must not add the adjustment again
                            src, tags = after, {**stmt.tags, "sp_after_call": True}
                elif eliminator._root_base(stmt.dst) is not None:
                    src = self._rewrite(src, stmt_idx, block) or src
                if src != stmt.src:
                    return Assignment(stmt.idx, stmt.dst, src, **tags)
                return stmt

            def _rewrite_call_sp_def(self, varid, src):
                addrs = eliminator._vvar_addr.get(varid) or eliminator._fwd_vvar_addr.get(varid)
                if addrs is None or len(addrs) != 1 or addrs[0].base != "sp" or addrs[0].offset is None:
                    return None
                offset = addrs[0].offset + eliminator._sp_shift
                if isinstance(src, StackBaseOffset) and src.offset == offset:
                    return None
                self.count += 1
                idx = eliminator._ail_manager.next_atom()
                return StackBaseOffset(idx, eliminator.arch.bits, offset)

            def _handle_Store(self, stmt_idx, stmt, block):
                rebuilt = super()._handle_Store(stmt_idx, stmt, block)
                current = rebuilt if rebuilt is not None else stmt
                sba = self._rewrite(current.addr, stmt_idx, block)
                if sba is None:
                    return rebuilt
                return Store(
                    current.idx,
                    sba,
                    current.data,
                    current.size,
                    current.endness,
                    current.guard,
                    **current.tags,
                )

            def _handle_BinaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_BinaryOp(expr_idx, expr, stmt_idx, stmt, block)
                if pre_states is None:
                    return rebuilt
                # a frame address computed from a forwarded one, e.g. a VM's ``Load(slot) - 388``
                current = rebuilt if rebuilt is not None else expr
                return self._rewrite(current, stmt_idx, block) or rebuilt

            def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
                rebuilt = super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)
                current = rebuilt if rebuilt is not None else expr
                sba = eliminator._stack_base_offset(current.addr, self._slots(stmt_idx, block))
                if sba is None:
                    return rebuilt
                slot = StackAddr("sp", (("add", sba.offset - eliminator._sp_shift),), sba.offset - eliminator._sp_shift)
                if eliminator._any_alias((slot,), current.size, call_args):
                    # a direct read would be a stack variable read, and stack SSA only sees a callee write a variable
                    # through a pointer argument that is the variable's address itself, not one passed via memory
                    return rebuilt
                self.count += 1
                return Load(
                    current.idx,
                    sba,
                    current.size,
                    current.endness,
                    guard=current.guard,
                    alt=current.alt,
                    **current.tags,
                )

        call_args = self._escaping(pre_states, calls_only=True)
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
        self._forward_frame_slots()
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

        escaped = self._escaping()
        self._variadic_reads = self._unresolved_variadic_reads(escaped)
        for areas in self._variadic_reads.values():
            reads.extend(areas)

        dead: dict[tuple[int, int | None], set[int]] = defaultdict(set)
        candidates = 0
        if n_unresolved:
            # A load we cannot place could read any frame slot, so no store is never read. Liveness still holds:
            # it takes such a load to read every slot, and only removes stores overwritten before any read.
            self.bailed_reason = (
                f"{n_unresolved} of {n_loads} load addresses do not reduce to the frame; examples: {examples}"
            )
        # Once a frame address escapes, a pointer read out of memory or a callee may reach any slot through it.
        has_calls = any(next(_calls_in(stmt), None) is not None for block in self._graph for stmt in block.statements)
        pointer_reads = escaped and (n_opaque or has_calls)
        for block in self._graph if not n_unresolved and not pointer_reads else ():
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
                candidates,
                len(reads),
                n_opaque,
                len(escaped),
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
            self.removed,
            candidates,
            self.removed - self.n_overwritten,
            self.n_overwritten,
            self.rewritten_addrs,
        )
        return self._graph, self.removed


class _NotReached(Exception):
    """A variable on a cycle that _resolve_cycles has not given a value yet."""


_NOT_REACHED = object()


def _join(a: tuple[StackAddr, ...] | None, b: tuple[StackAddr, ...] | None) -> tuple[StackAddr, ...] | None:
    """Union of two address sets by slot; addresses with one offset are one value, however derived."""
    if a is None or b is None:
        return None
    seen: dict = {}
    for addr in (*a, *b):
        seen.setdefault(_slot_key(addr), addr)
    return tuple(seen.values()) if len(seen) <= MAX_ADDRS else None


def _dedup(addrs) -> tuple[StackAddr, ...]:
    seen: dict[StackAddr, None] = {}
    for a in addrs:
        seen[a] = None
    return tuple(seen)


def _is_negated(addr: StackAddr) -> bool:
    return addr.base.startswith("-")


def _all_addresses(addrs) -> bool:
    return not any(_is_negated(a) for a in addrs)


def _tmps_only(slots: dict) -> dict:
    return {k: v for k, v in slots.items() if k[0] == "tmp"}


def _slot_key(addr: StackAddr):
    """Affine addresses compare by offset alone; masked ones by how they were computed."""
    return (addr.base, addr.offset) if addr.offset is not None else (addr.base, addr.chain)


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
    for attr in ("operand", "addr", "expr", "base", "offset", "value", "cond", "iftrue", "iffalse"):
        sub = getattr(expr, attr, None)
        if isinstance(sub, Expression):
            yield sub


def _calls_in(stmt: Statement):
    """Every Call expression anywhere inside a statement (calls are expressions here)."""
    yield from _walk(stmt, Call)


def _loads_in(stmt: Statement):
    """Every Load anywhere inside a statement."""
    yield from _walk(stmt, Load)


class _Collector(AILBlockViewer):
    """Collects every Load, Call or VirtualVariable in a statement, through every expression kind."""

    def __init__(self, cls):
        super().__init__()
        self.cls = cls
        self.found: list = []

    def _handle_Load(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.cls is Load:
            self.found.append(expr)
        super()._handle_Load(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_Call(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.cls is Call:
            self.found.append(expr)
        super()._handle_Call(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_VirtualVariable(self, expr_idx, expr, stmt_idx, stmt, block):
        if self.cls is VirtualVariable:
            self.found.append(expr)
        super()._handle_VirtualVariable(expr_idx, expr, stmt_idx, stmt, block)


def _walk(stmt: Statement, cls):
    collector = _Collector(cls)
    collector.walk_statement(stmt)
    yield from collector.found
