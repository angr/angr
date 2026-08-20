# pylint:disable=too-many-boolean-expressions
"""Declarative pattern-AST for describing known AIL code idioms (KnownPatterns).

Pattern nodes are frozen dataclasses that structurally match AIL expressions and
statements. Every node accepts an optional ``name``: a named *capture*. When the
same capture name occurs more than once in a pattern, all occurrences must bind
``.likes()``-equal expressions (unification).

Matching is performed by calling :meth:`PatternNode.match` with a
:class:`MatchState` (the bindings environment) and a :class:`MatchCtx`
(matcher-wide flags and callbacks). Match methods are functional: they return a
new ``MatchState`` on success and ``None`` on failure, so alternatives
(commutative operand orders, :class:`PChoice`) can backtrack by simply reusing
the pre-branch state.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace

from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Load,
    Phi,
    StackBaseOffset,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import Assignment, ConditionalJump, SideEffectStatement, Statement, Store

# ops for which operand order is irrelevant; commutative matching tries both orders
COMMUTATIVE_OPS = frozenset({"Add", "Mul", "And", "Or", "Xor", "CmpEQ", "CmpNE"})


#: Indices for expressions synthesized without a finder. Starts high enough that
#: it cannot be confused with an index a real AIL graph handed out; nothing built
#: with one of these reaches a graph, because the finder always supplies its own
#: allocator, but they still have to be distinct from each other.
_STANDALONE_IDX = itertools.count(1 << 32)


def _standalone_idx() -> int:
    return next(_STANDALONE_IDX)


@dataclass
class MatchState:
    """The bindings environment threaded through a match attempt."""

    bindings: dict[str, Expression] = field(default_factory=dict)
    # statement indices (within the anchor block) consumed via def-chasing
    consumed_stmt_idxs: frozenset[int] = frozenset()
    # (varid, stmt_idx) pairs recorded when a vvar use was chased to its definition
    chased_defs: tuple[tuple[int, int], ...] = ()
    # (varid, pure expression) pairs recorded when a vvar use was chased to a
    # definition outside the anchor block (or behind a phi). Those statements
    # cannot be moved, so the outliner *recomputes* the expression inside the
    # region instead; see KnownPatternFinder._resolve_remote_def.
    remote_defs: tuple[tuple[int, Expression], ...] = ()
    # Convert wrappers that were skipped over during structural matching
    skipped_converts: tuple[Convert, ...] = ()
    # (varid, root varid, displacement) for virtual variables PField resolved to
    # `root + displacement`. The definition is left exactly where it is; the
    # outliner only needs to know the value so it can spell the same address
    # against the object pointer it materializes. See PField._peek_bind.
    base_aliases: tuple[tuple[int, int, int], ...] = ()

    def bind(self, name: str, expr: Expression) -> MatchState | None:
        """Bind ``name`` to ``expr``; on rebind, require ``.likes()`` equality."""
        existing = self.bindings.get(name)
        if existing is not None:
            return self if existing.likes(expr) else None
        new_bindings = dict(self.bindings)
        new_bindings[name] = expr
        return replace(self, bindings=new_bindings)


@dataclass(frozen=True)
class MatchCtx:
    """Matcher-wide flags and callbacks."""

    # match structural nodes through interposed Convert wrappers
    skip_conversions: bool = True
    # when a structural node meets a VirtualVariable, chase its unique non-phi
    # same-block definition; returns (stmt_idx, def_src_expr) or None
    chase_fn: Callable[[int], tuple[int, Expression] | None] | None = None
    # read-only definition lookup: what pure expression a vvar equals, without
    # consuming, moving or recomputing anything. PField uses it to canonicalize an
    # object address the compiler put in a register of its own.
    peek_fn: Callable[[int], Expression | None] | None = None
    # fallback for when ``chase_fn`` declines: resolve a vvar to a *pure*
    # expression that can be recomputed wherever the vvar is live -- a CSE'd
    # definition in a dominating block, possibly behind phis. Returns None when
    # the definition is not recomputable.
    remote_chase_fn: Callable[[int], Expression | None] | None = None
    # resolve a virtual variable to the *stack slot* it was copied from, through
    # any chain of plain copies. A local container's fields are slots, but the
    # compiler keeps one of them in a register across the accessor, so a stack
    # idiom reaches the matcher half in slots and half in registers.
    stack_slot_fn: Callable[[int], VirtualVariable | None] | None = None
    # every name a Call's callee is known by -- the raw symbol and, for a C++
    # binary, its demangled spelling. Supplied by the finder, which holds the
    # Project; a pattern that names a callee is only matchable with it.
    call_target_fn: Callable[[Call], frozenset[str]] | None = None
    # allocator for the AIL indices of expressions the matcher has to synthesize
    # (PField's ``root + K``, PStackField's StackBaseOffset). The finder supplies
    # Clinic's, so a synthesized object lands in the same index space as the
    # graph it will be spliced into; the default exists so a pattern can be
    # matched without a finder at all, as the DSL unit tests do. It must never
    # hand out None: the decompiler's VariableMap is keyed by index and every
    # object built with idx=None collides at index 0.
    next_idx: Callable[[], int] = _standalone_idx
    # the expression that *defined* a virtual variable, followed through plain
    # copies and through phis whose arms agree. Deliberately *not* ``peek_fn``:
    # that one's contract is "this expression can be recomputed at the use", so
    # it refuses loads and calls. This one only answers "what produced this
    # value", which a load or a call can perfectly well have done -- the answer
    # is used to *identify* an idiom, never to move or re-evaluate anything.
    def_fn: Callable[[int], Expression | None] | None = None


class PatternNode:
    """Base class of all pattern nodes."""

    __slots__ = ()


class PatternExpr(PatternNode):
    """Base class of expression patterns."""

    __slots__ = ()

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        raise NotImplementedError

    def _prepare(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> tuple[Expression, MatchState] | None:
        """Common preamble for structural nodes: skip Convert wrappers and chase
        vvar definitions when enabled."""
        while ctx.skip_conversions and isinstance(expr, Convert):
            state = replace(state, skipped_converts=(*state.skipped_converts, expr))
            expr = expr.operand
        if isinstance(expr, VirtualVariable) and (ctx.chase_fn is not None or ctx.remote_chase_fn is not None):
            chased = ctx.chase_fn(expr.varid) if ctx.chase_fn is not None else None
            if chased is not None:
                stmt_idx, def_expr = chased
                state = replace(
                    state,
                    consumed_stmt_idxs=state.consumed_stmt_idxs | {stmt_idx},
                    chased_defs=(*state.chased_defs, (expr.varid, stmt_idx)),
                )
                return self._prepare(def_expr, state, ctx)
            if ctx.remote_chase_fn is not None:
                remote = ctx.remote_chase_fn(expr.varid)
                if remote is not None and remote.bits == expr.bits:
                    if all(varid != expr.varid for varid, _ in state.remote_defs):
                        state = replace(state, remote_defs=(*state.remote_defs, (expr.varid, remote)))
                    return self._prepare(remote, state, ctx)
            return None
        return expr, state

    def _bind_if_named(self, name: str | None, expr: Expression, state: MatchState) -> MatchState | None:
        if name is None:
            return state
        return state.bind(name, expr)


@dataclass(frozen=True)
class PAny(PatternExpr):
    """Matches any expression."""

    name: str | None = None
    bits: int | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if self.bits is not None and getattr(expr, "bits", None) != self.bits:
            return None
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PVVar(PatternExpr):
    """Matches a VirtualVariable."""

    name: str | None = None
    bits: int | None = None
    categories: frozenset[VirtualVariableCategory] | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(expr, VirtualVariable):
            return None
        if self.bits is not None and expr.bits != self.bits:
            return None
        if self.categories is not None and expr.category not in self.categories:
            return None
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PConst(PatternExpr):
    """Matches a Const, by exact value or by predicate. Width is ignored unless
    ``bits`` is given (e.g. shift amounts are often 8-bit)."""

    value: int | None = None
    pred: Callable[[int], bool] | None = None
    bits: int | None = None
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(expr, Const) or not isinstance(expr.value, int):
            return None
        if self.value is not None and expr.value != self.value:
            return None
        if self.pred is not None and not self.pred(expr.value):
            return None
        if self.bits is not None and expr.bits != self.bits:
            return None
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PBinOp(PatternExpr):
    """Matches a BinaryOp. ``op`` may be a single op string or a set of
    acceptable ops. Commutative ops try both operand orders unless
    ``commutative`` is explicitly False."""

    op: str | frozenset[str]
    operands: tuple[PatternExpr, PatternExpr]
    commutative: bool | None = None
    name: str | None = None

    def __post_init__(self):
        if not isinstance(self.op, (str, frozenset)):
            object.__setattr__(self, "op", frozenset(self.op))
        if not isinstance(self.operands, tuple):
            object.__setattr__(self, "operands", tuple(self.operands))

    def _op_matches(self, op: str) -> bool:
        return op == self.op if isinstance(self.op, str) else op in self.op

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        prepared = self._prepare(expr, state, ctx)
        if prepared is None:
            return None
        expr, state = prepared
        if not isinstance(expr, BinaryOp) or not self._op_matches(expr.op):
            return None
        commutative = self.commutative if self.commutative is not None else expr.op in COMMUTATIVE_OPS
        orders = ((0, 1), (1, 0)) if commutative else ((0, 1),)
        for i, j in orders:
            st = self.operands[0].match(expr.operands[i], state, ctx)
            if st is None:
                continue
            st = self.operands[1].match(expr.operands[j], st, ctx)
            if st is None:
                continue
            st = self._bind_if_named(self.name, expr, st)
            if st is not None:
                return st
        return None


@dataclass(frozen=True)
class PUnaryOp(PatternExpr):
    """Matches a UnaryOp."""

    op: str | frozenset[str]
    operand: PatternExpr
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        prepared = self._prepare(expr, state, ctx)
        if prepared is None:
            return None
        expr, state = prepared
        if not isinstance(expr, UnaryOp):
            return None
        if not (expr.op == self.op if isinstance(self.op, str) else expr.op in self.op):
            return None
        st = self.operand.match(expr.operand, state, ctx)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PConv(PatternExpr):
    """Matches a Convert explicitly (never skipped)."""

    operand: PatternExpr
    from_bits: int | None = None
    to_bits: int | None = None
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(expr, Convert):
            return None
        if self.from_bits is not None and expr.from_bits != self.from_bits:
            return None
        if self.to_bits is not None and expr.to_bits != self.to_bits:
            return None
        st = self.operand.match(expr.operand, state, ctx)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PExtract(PatternExpr):
    """Matches an ``Extract`` -- a bit-slice of a wider value.

    This is how a scalar reaches integer code out of a vector register when the
    128-bit op did not get narrowed away: ``movq %xmm2,%rax`` on a value that
    came from ``maxsd``/``mulsd`` lifts to ``Extract(vvar_128, 64bits@0)``, not
    to a Convert. Without a node for it, every libm bit-twiddle whose operand is
    a *computed* double rather than an incoming argument is unmatchable.

    ``bits``/``offset`` default to unconstrained; ``offset`` is in bits.
    """

    operand: PatternExpr
    bits: int | None = None
    offset: int | None = None
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(expr, Extract):
            return None
        if self.bits is not None and expr.bits != self.bits:
            return None
        if self.offset is not None:
            off = expr.offset
            if not (isinstance(off, Const) and isinstance(off.value, int) and off.value == self.offset):
                return None
        st = self.operand.match(expr.base, state, ctx)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PLoad(PatternExpr):
    """Matches a memory Load. ``size`` is in bytes."""

    addr: PatternExpr
    size: int | None = None
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        prepared = self._prepare(expr, state, ctx)
        if prepared is None:
            return None
        expr, state = prepared
        if not isinstance(expr, Load):
            return None
        if self.size is not None and expr.size != self.size:
            return None
        st = self.addr.match(expr.addr, state, ctx)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PCall(PatternExpr):
    """Matches a ``Call`` whose callee is one of ``names``.

    The callee is what makes a pattern containing this node self-guarding: an
    idiom spelled around a named runtime function -- ``operator delete`` in the
    std::string destructor, ``__ctype_b_loc`` in ``isspace`` -- cannot be
    confused with arithmetic that happens to look alike, because no other code
    calls that function to do something else.

    ``names`` is matched against *every* spelling the callee is known by (the
    raw symbol and its demangled form), so a pattern may name either. Prefer the
    mangled spelling: it is exact, while a demangled one carries the argument
    list and varies with the demangler.

    ``args=None`` leaves the arguments unconstrained; a tuple constrains them
    positionally, with ``None`` in a slot meaning "any expression".
    """

    names: frozenset[str]
    args: tuple[PatternExpr | None, ...] | None = None
    name: str | None = None

    def __post_init__(self):
        if not isinstance(self.names, frozenset):
            object.__setattr__(self, "names", frozenset(self.names))
        if self.args is not None and not isinstance(self.args, tuple):
            object.__setattr__(self, "args", tuple(self.args))

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        # deliberately not _prepare: chasing a virtual variable to its definition
        # marks that definition consumed, which would let the outliner *move* the
        # call. See PCallResult for the read-only way to reach a call's result.
        while ctx.skip_conversions and isinstance(expr, Convert):
            expr = expr.operand
        if not isinstance(expr, Call) or ctx.call_target_fn is None:
            return None
        if not (self.names & ctx.call_target_fn(expr)):
            return None
        if self.args is not None:
            args = expr.args or ()
            if len(args) != len(self.args):
                return None
            for arg_pat, arg in zip(self.args, args):
                if arg_pat is None:
                    continue
                st = arg_pat.match(arg, state, ctx)
                if st is None:
                    return None
                state = st
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PCallResult(PatternExpr):
    """The value a call to one of ``names`` returned.

    A call's result is almost never used where it is produced: the compiler
    assigns it to a register and reads that register, often in another block --
    ``__ctype_b_loc()`` is called once per function and its table indexed at
    every predicate. So this node matches the *virtual variable*, and looks up
    its definition read-only. Nothing is consumed, moved or recomputed; the call
    stays exactly where the compiler put it.

    An inline ``Call`` expression is matched too, for the case where the value
    is used at its definition.
    """

    names: frozenset[str]
    name: str | None = None

    def __post_init__(self):
        if not isinstance(self.names, frozenset):
            object.__setattr__(self, "names", frozenset(self.names))

    def _target_matches(self, call: Call, ctx: MatchCtx) -> bool:
        return ctx.call_target_fn is not None and bool(self.names & ctx.call_target_fn(call))

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        while ctx.skip_conversions and isinstance(expr, Convert):
            expr = expr.operand
        if isinstance(expr, Call):
            return self._bind_if_named(self.name, expr, state) if self._target_matches(expr, ctx) else None
        if not isinstance(expr, VirtualVariable) or ctx.def_fn is None:
            return None
        call = ctx.def_fn(expr.varid)
        if not isinstance(call, Call) or not self._target_matches(call, ctx):
            return None
        # bind the variable, not the call: it is the value that exists at the
        # match site, and the only spelling the outliner could pass along
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PDefOf(PatternExpr):
    """``inner``, or a virtual variable whose reaching definition is ``inner``.

    The compiler is free to compute a value once and use it twice, and it does
    so exactly where an idiom uses one value twice. ``if (_M_p != &_M_local_buf)
    operator delete(_M_p, ...)`` reads _M_p in the compare and in the call, so
    gcc loads it into a register and the pattern sees ``Load(s)`` in neither
    place -- it sees the same virtual variable in both.

    Reading that variable's definition is read-only. Nothing is consumed, moved
    or recomputed, and the identification stays accurate even if memory changes
    afterwards: the variable holds what the load produced *at the definition*,
    which is what the idiom meant. That is why this is not ``peek_fn``, whose
    contract ("can be recomputed at the use") a load cannot satisfy.

    The unconsumed definition is left where it was, so a region that matches
    through this node keeps it as residue -- harmless, and dead-code elimination
    removes it once the idiom's other uses are gone.
    """

    inner: PatternExpr
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        # The read-only lookup goes *first*, deliberately. The ordinary
        # structural match would reach the same definition through ``chase_fn``,
        # but chasing consumes the defining statement -- it commits the outliner
        # to moving it -- and a value the compiler hoisted is hoisted precisely
        # because something else still reads it. The chased match is then thrown
        # away wholesale, and identifying the idiom fails for a reason that has
        # nothing to do with the idiom.
        stripped = expr
        while ctx.skip_conversions and isinstance(stripped, Convert):
            stripped = stripped.operand
        if isinstance(stripped, VirtualVariable) and ctx.def_fn is not None:
            definition = ctx.def_fn(stripped.varid)
            if definition is not None:
                st = self.inner.match(definition, state, ctx)
                if st is not None:
                    return self._bind_if_named(self.name, expr, st)
        st = self.inner.match(expr, state, ctx)
        if st is not None:
            return self._bind_if_named(self.name, expr, st)
        return None


@dataclass(frozen=True)
class PField(PatternExpr):
    """The *address* of the field at ``offset`` inside the object bound to ``base``.

    Spelling a container's fields as ``PLoad(PVVar("v"))`` / ``PLoad(PVVar("v") +
    8)`` requires the object to sit at the very address held in a virtual
    variable. That is the minority case: measured over the benchmark corpus, only
    10-25% of the DWARF sites for a ``std::vector`` accessor read the container
    through a bare pointer -- the rest reach it as a *field of something else*
    (``this->tokens.size()``), which lifts to ``Load(this + 56)`` /
    ``Load(this + 64)`` and cannot bind ``v`` at all.

    ``PField`` matches such an address and binds ``base`` to the object's own
    address: ``root`` when the object is at offset 0, else ``root + K``. Two
    fields of one object therefore unify on ``K``, which is what keeps the node
    honest -- it replaces the constraint "this displacement is exactly 8" with
    "these two displacements differ by exactly 8".

    **Only use it in patterns that reference at least two fields.** With a single
    field there is no second displacement to constrain, so ``PLoad(PField("s",
    8))`` degenerates into "any load through a pointer plus a non-negative
    constant" and matches essentially everything.

    ``root`` must be a virtual variable: the outliner materializes ``tmp = root +
    K`` ahead of the region so the synthesized call still takes a variable.
    """

    base: str
    offset: int
    name: str | None = None

    @staticmethod
    def _decompose(expr: Expression) -> tuple[Expression, int] | None:
        """``expr`` -> ``(root, displacement)``."""
        if isinstance(expr, BinaryOp) and expr.op == "Add":
            a, b = expr.operands
            for root, off in ((a, b), (b, a)):
                if isinstance(off, Const) and isinstance(off.value, int):
                    return root, off.value
            return None
        return expr, 0

    def _bind(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        decomposed = self._decompose(expr)
        if decomposed is None:
            return None
        root, disp = decomposed
        if not isinstance(root, VirtualVariable):
            return None
        obj_off = disp - self.offset
        # a negative object offset would mean the pointer we hold points *into*
        # the object past the field, which no accessor does -- and allowing it
        # would let a bare `Load(p)` satisfy a field at +8
        if obj_off < 0:
            return None
        base_expr: Expression = (
            root
            if obj_off == 0
            else BinaryOp(
                ctx.next_idx(),
                "Add",
                [root, Const(ctx.next_idx(), obj_off, root.bits)],
                False,
                bits=root.bits,
            )
        )
        st = state.bind(self.base, base_expr)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)

    def _peek_bind(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        """Canonicalize an address the compiler kept in a register of its own.

        ``lea 0x40(%rcx),%r15`` puts the object's address in a variable, so one
        field of a pair reaches the matcher as a bare vvar and the other as
        ``root + displacement``; the two do not unify, and the idiom is missed
        even though both name the same object. Reading the vvar's definition
        fixes that without touching it: nothing is moved, copied or recomputed --
        the alias is recorded so the outliner can spell the same address against
        the object pointer it materializes.
        """
        if not isinstance(expr, VirtualVariable) or ctx.peek_fn is None:
            return None
        # Only when this capture is already bound. Peeking exists to reconcile a
        # second field with the base the first one established -- with nothing
        # bound there is nothing to reconcile, and doing it anyway costs a
        # definition lookup and a synthesized address for every `Load(v)` in the
        # program times every template in the library, which is minutes per
        # function on a large binary.
        if self.base not in state.bindings:
            return None
        peeked = ctx.peek_fn(expr.varid)
        if peeked is None:
            return None
        decomposed = self._decompose(peeked)
        if decomposed is None:
            return None
        root, disp = decomposed
        if not isinstance(root, VirtualVariable) or disp - self.offset < 0:
            return None
        st = self._bind(peeked, state, ctx)
        if st is None:
            return None
        return replace(st, base_aliases=(*st.base_aliases, (expr.varid, root.varid, disp)))

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        while ctx.skip_conversions and isinstance(expr, Convert):
            expr = expr.operand
        # Take the address as written first. Chasing is the *fallback*, not the
        # default: a bare field address is a virtual variable, and _prepare would
        # helpfully replace it by its definition -- turning `Load(v)` into
        # `Load(<whatever defined v>)`, which decomposes to no base at all.
        st = self._bind(expr, state, ctx)
        if st is not None:
            return st
        st = self._peek_bind(expr, state, ctx)
        if st is not None:
            return st
        # ...and when the address is a computed value the matcher may move,
        # the chased form is the one that agrees with the other field's base.
        prepared = self._prepare(expr, state, ctx)
        if prepared is None:
            return None
        chased, state = prepared
        if chased is expr:
            return None
        return self._bind(chased, state, ctx)


@dataclass(frozen=True)
class PStackField(PatternExpr):
    """A field of a container that lives **on the stack**.

    A stack object never reaches the matcher as an object at all: variable
    recovery has already split it into one virtual variable per slot, so
    ``std::string s;`` is a handful of independent ``vvar{s-112}``,
    ``vvar{s-96}`` and there is no ``Load(s)`` to match and no ``s + 16`` to
    compare against. That is not a rare shape -- measured over the benchmark
    corpus (`kp-eval/stack_share.py`), stack objects are 40-54% of the DWARF
    sites for ``std::string::length`` and 15-35% for ``std::vector<T>::size``.

    This node matches the *slot* of the field at ``offset`` and binds ``base`` to
    the object's own stack offset, so two fields of one object unify on it
    exactly as :class:`PField`'s two displacements do. ``as_address`` matches the
    address form (``&slot``, which lifts to ``UnaryOp("Reference", vvar)``) rather
    than the value form -- ``std::string::capacity`` needs both, since it compares
    the data pointer against the address of the local buffer.

    The binding is a ``StackBaseOffset`` -- the object's own address. That is both
    the thing two fields must agree on and, directly, the argument the synthesized
    call takes, so nothing has to be materialized for it.

    Matching is only half the problem, and the other half is why a pattern using
    this node is never *outlined*: the region for a stack container reads N
    independent slots, so its live-ins are N values rather than one pointer and
    there is nothing for a synthesized callee to take. Such a match is instead
    rewritten in place -- the matched expression, or the whole region, is
    replaced by ``call(&s)``, whose argument the binding already is. See
    ``KnownPatternFinder._rewrite_in_place`` and ``_rewrite_graph_in_place``.
    """

    base: str
    offset: int
    as_address: bool = False
    size: int | None = None
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        while ctx.skip_conversions and isinstance(expr, Convert):
            expr = expr.operand
        if self.as_address:
            if not (isinstance(expr, UnaryOp) and expr.op == "Reference"):
                return None
            slot = expr.operand
        else:
            slot = expr
        if isinstance(slot, VirtualVariable) and slot.category != VirtualVariableCategory.STACK:
            # a register holding a copy of the slot: follow it back
            if ctx.stack_slot_fn is None:
                return None
            resolved = ctx.stack_slot_fn(slot.varid)
            if resolved is None:
                return None
            slot = resolved
        if not isinstance(slot, VirtualVariable) or slot.category != VirtualVariableCategory.STACK:
            return None
        if self.size is not None and slot.bits != self.size * 8:
            return None
        stack_off = slot.stack_offset
        if stack_off is None:
            return None
        st = state.bind(self.base, StackBaseOffset(ctx.next_idx(), slot.bits, stack_off - self.offset))
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PPhi(PatternExpr):
    """Matches a Phi expression, capturing it whole (its individual sources are
    not matched). Useful for loop-header blocks, whose statements are phi
    assignments."""

    name: str | None = None
    bits: int | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(expr, Phi):
            return None
        if self.bits is not None and expr.bits != self.bits:
            return None
        return self._bind_if_named(self.name, expr, state)


@dataclass(frozen=True)
class PITE(PatternExpr):
    """Matches an ITE (ternary) expression ``cond ? iftrue : iffalse``.

    Needed because ITERegionConverter (AFTER_GLOBAL_SIMPLIFICATION) collapses
    ``if (c) x = a; else x = b;`` diamonds into a single ITE assignment *before*
    the KnownPatternOutliner runs, so a two-armed value-select idiom reaches the
    outliner as an expression, not as a PGraphPat region. (A *triangle* -- one
    arm empty, as in the MSVC std::string::c_str SSO select -- is not converted,
    which is why that idiom is still a PGraphPat.)
    """

    cond: PatternExpr
    iftrue: PatternExpr
    iffalse: PatternExpr
    name: str | None = None

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        prepared = self._prepare(expr, state, ctx)
        if prepared is None:
            return None
        expr, state = prepared
        if not isinstance(expr, ITE):
            return None
        st = self.cond.match(expr.cond, state, ctx)
        if st is None:
            return None
        st = self.iftrue.match(expr.iftrue, st, ctx)
        if st is None:
            return None
        st = self.iffalse.match(expr.iffalse, st, ctx)
        if st is None:
            return None
        return self._bind_if_named(self.name, expr, st)


@dataclass(frozen=True)
class PChoice(PatternExpr):
    """Ordered alternation: matches the first alternative that succeeds."""

    alternatives: tuple[PatternExpr, ...]

    def __init__(self, *alternatives: PatternExpr):
        object.__setattr__(self, "alternatives", tuple(alternatives))

    def match(self, expr: Expression, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        for alt in self.alternatives:
            st = alt.match(expr, state, ctx)
            if st is not None:
                return st
        return None


class PatternStmt(PatternNode):
    """Base class of statement patterns."""

    __slots__ = ()

    def match(self, stmt: Statement, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        raise NotImplementedError


@dataclass(frozen=True)
class PAssign(PatternStmt):
    """Matches an Assignment statement."""

    dst: PatternExpr
    src: PatternExpr

    def match(self, stmt: Statement, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(stmt, Assignment):
            return None
        st = self.dst.match(stmt.dst, state, ctx)
        if st is None:
            return None
        return self.src.match(stmt.src, st, ctx)


@dataclass(frozen=True)
class PStore(PatternStmt):
    """Matches a Store statement. ``size`` is in bytes."""

    addr: PatternExpr
    value: PatternExpr
    size: int | None = None

    def match(self, stmt: Statement, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(stmt, Store):
            return None
        if self.size is not None and stmt.size != self.size:
            return None
        st = self.addr.match(stmt.addr, state, ctx)
        if st is None:
            return None
        return self.value.match(stmt.data, st, ctx)


@dataclass(frozen=True)
class PCallStmt(PatternStmt):
    """Matches a statement whose effect is a call.

    Ailment has no Call *statement*: a call whose result is discarded is a
    ``SideEffectStatement`` wrapping the Call expression, and one whose result is
    kept is an ordinary ``Assignment``. Both spellings are the same idiom, so
    both match; ``dst``, when given, additionally constrains the assigned
    destination (and thereby requires the assignment form).
    """

    call: PCall
    dst: PatternExpr | None = None

    def match(self, stmt: Statement, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if isinstance(stmt, SideEffectStatement):
            return None if self.dst is not None else self.call.match(stmt.expr, state, ctx)
        if not isinstance(stmt, Assignment):
            return None
        st = self.call.match(stmt.src, state, ctx)
        if st is None:
            return None
        return self.dst.match(stmt.dst, st, ctx) if self.dst is not None else st


@dataclass(frozen=True)
class PCondJump(PatternStmt):
    """Matches a ConditionalJump, matching its condition expression."""

    condition: PatternExpr

    def match(self, stmt: Statement, state: MatchState, ctx: MatchCtx) -> MatchState | None:
        if not isinstance(stmt, ConditionalJump):
            return None
        return self.condition.match(stmt.condition, state, ctx)


@dataclass(frozen=True)
class PStmtSeq(PatternStmt):
    """Matches a group of statements within one block. When ``ordered`` (the
    default), the statement patterns must match in order; with ``allow_gaps``,
    unrelated statements may sit between the matched ones. When ``ordered`` is
    False, the statement patterns match statements of the block in any order
    (each pattern to a distinct statement) — useful for idioms whose statement
    order the compiler chooses freely (e.g. list-link stores)."""

    stmts: tuple[PatternStmt, ...]
    allow_gaps: bool = True
    ordered: bool = True
    #: How many unmatched statements may sit between two matched ones. Without a
    #: bound the scan runs to the end of the block from every statement it could
    #: start at -- quadratic per block *per template* -- and finds nothing: an
    #: idiom's statements are adjacent apart from what the scheduler interleaved,
    #: which is a handful of instructions, not a basic block.
    max_gap: int = 8


@dataclass(frozen=True)
class PBlockPat(PatternNode):
    """A labeled block of statements in a multi-block pattern graph. An empty
    ``stmts`` sequence matches any block (structure alone identifies it)."""

    label: str
    stmts: PStmtSeq


@dataclass(frozen=True)
class PGraphPat(PatternNode):
    """A multi-block pattern: labeled blocks connected by edges.

    ``blocks`` maps a label to its :class:`PBlockPat`. ``edges`` are
    ``(src_label, dst_label)`` pairs; a destination label that does not appear
    in ``blocks`` denotes an **external successor** — a region exit that
    becomes the Outliner frontier. ``entry`` is the label of the single entry
    block. Captures unify across all blocks (one bindings environment).
    """

    blocks: dict[str, PBlockPat]
    edges: Sequence[tuple[str, str]]
    entry: str

    def __post_init__(self):
        if self.entry not in self.blocks:
            raise ValueError(f"PGraphPat entry {self.entry!r} is not among its blocks")
        labels = set(self.blocks)
        for src, _dst in self.edges:
            # the destination may be internal or an external-successor label
            if src not in labels:
                raise ValueError(f"PGraphPat edge source {src!r} is not an internal block")
        # every internal non-entry block must be reachable via internal edges
        reachable = {self.entry}
        changed = True
        internal_edges = [(s, d) for s, d in self.edges if d in labels]
        while changed:
            changed = False
            for src, dst in internal_edges:
                if src in reachable and dst not in reachable:
                    reachable.add(dst)
                    changed = True
        unreachable = labels - reachable
        if unreachable:
            raise ValueError(f"PGraphPat blocks {sorted(unreachable)} are not reachable from the entry")

    @property
    def external_labels(self) -> set[str]:
        return {dst for _, dst in self.edges if dst not in self.blocks}


def pattern_anchor_key(node: PatternNode) -> tuple[str, str | None] | None:
    """A cheap discriminator of the pattern root, used to prune candidate
    patterns at each expression position: ``(ail kind, op or None)``.

    Returns None when the root is not discriminating (PAny/PChoice/...), in
    which case the pattern must be attempted everywhere.
    """
    if isinstance(node, PLoad):
        # the width is part of the discriminator: PLoad.match rejects a
        # different-sized Load outright, so a sized pattern need never be tried
        # at one
        return ("Load", None if node.size is None else str(node.size))
    if isinstance(node, PBinOp):
        return ("BinaryOp", node.op if isinstance(node.op, str) else None)
    if isinstance(node, PUnaryOp):
        return ("UnaryOp", node.op if isinstance(node.op, str) else None)
    if isinstance(node, PConv):
        return ("Convert", None)
    if isinstance(node, PExtract):
        return ("Extract", None)
    if isinstance(node, PCall):
        return ("Call", None)
    if isinstance(node, PDefOf):
        return None
    if isinstance(node, PCallResult):
        # matches a virtual variable, or the call itself where the result is used
        # at its definition -- two kinds, so it discriminates neither
        return None
    if isinstance(node, PConst):
        return ("Const", None)
    if isinstance(node, PITE):
        return ("ITE", None)
    if isinstance(node, PVVar):
        return ("VirtualVariable", None)
    if isinstance(node, PField):
        # a field address is an Add when the object is not at offset 0 and a bare
        # vvar when it is, so it discriminates nothing on its own
        return None
    if isinstance(node, PStackField):
        return ("UnaryOp", "Reference") if node.as_address else ("VirtualVariable", None)
    if isinstance(node, PAssign):
        return ("Assignment", None)
    if isinstance(node, PStore):
        return ("Store", None)
    if isinstance(node, PCallStmt):
        return ("Call", None)
    if isinstance(node, PCondJump):
        return ("ConditionalJump", None)
    if isinstance(node, PChoice):
        # a PChoice is usually a polarity/spelling alternation of one shape; when
        # every alternative discriminates the same way, keep that discriminator
        # rather than falling back to "try this pattern everywhere"
        keys = {pattern_anchor_key(alt) for alt in node.alternatives}
        return next(iter(keys)) if len(keys) == 1 and None not in keys else None
    if isinstance(node, PStmtSeq):
        return pattern_anchor_key(node.stmts[0]) if node.stmts else None
    if isinstance(node, PGraphPat):
        return pattern_anchor_key(node.blocks[node.entry].stmts)
    return None


StmtKey = tuple[str, tuple[str, str | None] | None]


def stmt_pattern_anchor_key(node: PatternNode) -> StmtKey | None:
    """The discriminator of a *statement* pattern's first statement.

    Statement patterns are anchored at every statement of every block and then
    scan forward, so trying one that cannot possibly match is the expensive kind
    of waste. The key is the statement kind plus the anchor key of the expression
    that carries the pattern's shape -- an assignment's source, a store's value
    -- which is what separates ``t = *a`` (a swap) from the assignments that
    make up most of a block.
    """
    if isinstance(node, PStmtSeq):
        return stmt_pattern_anchor_key(node.stmts[0]) if node.stmts else None
    if isinstance(node, PAssign):
        return ("Assignment", pattern_anchor_key(node.src))
    if isinstance(node, PStore):
        return ("Store", pattern_anchor_key(node.value))
    if isinstance(node, PCondJump):
        return ("ConditionalJump", None)
    if isinstance(node, PCallStmt):
        return ("Call", None)
    return None


def stmt_anchor_key(stmt: Statement) -> StmtKey:
    """The anchor key of a concrete AIL statement, for pruning."""
    if isinstance(stmt, Assignment):
        return ("Assignment", expr_anchor_key(stmt.src))
    if isinstance(stmt, Store):
        return ("Store", expr_anchor_key(stmt.data))
    if isinstance(stmt, ConditionalJump):
        return ("ConditionalJump", None)
    if isinstance(stmt, SideEffectStatement):
        return ("Call", None)
    return ("", None)


def expr_anchor_key(expr: Expression) -> tuple[str, str | None]:
    """The anchor key of a concrete AIL expression, for pruning."""
    if isinstance(expr, Load):
        return ("Load", str(expr.size))
    if isinstance(expr, BinaryOp):
        return ("BinaryOp", expr.op)
    if isinstance(expr, UnaryOp):
        return ("UnaryOp", expr.op)
    if isinstance(expr, Convert):
        return ("Convert", None)
    if isinstance(expr, Extract):
        return ("Extract", None)
    if isinstance(expr, Call):
        return ("Call", None)
    if isinstance(expr, Const):
        return ("Const", None)
    if isinstance(expr, ITE):
        return ("ITE", None)
    if isinstance(expr, VirtualVariable):
        return ("VirtualVariable", None)
    return ("", None)
