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

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from angr.ailment.expression import (
    BinaryOp,
    Const,
    Convert,
    Expression,
    Load,
    Phi,
    UnaryOp,
    VirtualVariable,
)
from angr.ailment.statement import Assignment, ConditionalJump, Statement, Store

if TYPE_CHECKING:
    from angr.ailment.expression import VirtualVariableCategory


# ops for which operand order is irrelevant; commutative matching tries both orders
COMMUTATIVE_OPS = frozenset({"Add", "Mul", "And", "Or", "Xor", "CmpEQ", "CmpNE"})


@dataclass
class MatchState:
    """The bindings environment threaded through a match attempt."""

    bindings: dict[str, Expression] = field(default_factory=dict)
    # statement indices (within the anchor block) consumed via def-chasing
    consumed_stmt_idxs: frozenset[int] = frozenset()
    # (varid, stmt_idx) pairs recorded when a vvar use was chased to its definition
    chased_defs: tuple[tuple[int, int], ...] = ()
    # Convert wrappers that were skipped over during structural matching
    skipped_converts: tuple[Convert, ...] = ()

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
        if isinstance(expr, VirtualVariable) and ctx.chase_fn is not None:
            chased = ctx.chase_fn(expr.varid)
            if chased is None:
                return None
            stmt_idx, def_expr = chased
            state = replace(
                state,
                consumed_stmt_idxs=state.consumed_stmt_idxs | {stmt_idx},
                chased_defs=(*state.chased_defs, (expr.varid, stmt_idx)),
            )
            return self._prepare(def_expr, state, ctx)
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
        return ("Load", None)
    if isinstance(node, PBinOp):
        return ("BinaryOp", node.op if isinstance(node.op, str) else None)
    if isinstance(node, PUnaryOp):
        return ("UnaryOp", node.op if isinstance(node.op, str) else None)
    if isinstance(node, PConv):
        return ("Convert", None)
    if isinstance(node, PConst):
        return ("Const", None)
    if isinstance(node, PVVar):
        return ("VirtualVariable", None)
    if isinstance(node, PAssign):
        return ("Assignment", None)
    if isinstance(node, PStore):
        return ("Store", None)
    if isinstance(node, PCondJump):
        return ("ConditionalJump", None)
    if isinstance(node, PStmtSeq):
        return pattern_anchor_key(node.stmts[0]) if node.stmts else None
    if isinstance(node, PGraphPat):
        return pattern_anchor_key(node.blocks[node.entry].stmts)
    return None


def expr_anchor_key(expr: Expression) -> tuple[str, str | None]:
    """The anchor key of a concrete AIL expression, for pruning."""
    if isinstance(expr, Load):
        return ("Load", None)
    if isinstance(expr, BinaryOp):
        return ("BinaryOp", expr.op)
    if isinstance(expr, UnaryOp):
        return ("UnaryOp", expr.op)
    if isinstance(expr, Convert):
        return ("Convert", None)
    if isinstance(expr, Const):
        return ("Const", None)
    if isinstance(expr, VirtualVariable):
        return ("VirtualVariable", None)
    return ("", None)
