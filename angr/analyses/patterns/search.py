"""Find approximate occurrences of a pattern in a token stream.

:func:`~.align.discover` finds what a function repeats by aligning the stream
against itself. This module answers the other question: given a pattern the user
wrote or selected, where does it occur, and how well? The template is aligned
semi-globally, every leaf statement of the pattern must be placed or skipped,
against any window of the stream, with the same affine-gap model as discovery.
Per-leaf fuzziness comes from the DSL: a wildcard accepts anything, an
``optional`` statement can be skipped for free, and ``weight`` scales a leaf's
share of the score.

Shape alignment says where; it cannot see constants, variable identity or
captures, since shapes erase them. :func:`verify` then runs each aligned pair
through the node's own structural ``match`` under one shared binding
environment, so a constraint the shape could not see still has to hold.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.ailment.expression import Call, Const
from angr.analyses.decompiler.known_patterns import dsl
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState, iter_stmt_patterns
from angr.analyses.decompiler.known_patterns.pattern import KnownPattern
from angr.analyses.decompiler.known_patterns.symbols import symbol_addr

from .align import AlignParams, Interval
from .template import TEMPLATE_TOKENIZER, Fit, ShapeTree, match_shape, parse_shape, shape_of
from .tokenizer import TokenStream, tokenize

if TYPE_CHECKING:
    from collections.abc import Callable

    import networkx

    from angr.ailment import Block
    from angr.knowledge_base import KnowledgeBase

_l = logging.getLogger(__name__)

_NEG = float("-inf")


@dataclass(frozen=True)
class TemplateColumn:
    """One leaf of the template and what it landed on.

    ``token`` is the stream position, or None when the leaf was skipped.
    ``verified`` is None until :func:`verify` runs, then whether the node's own
    structural match accepted the statement.
    """

    leaf: int
    token: int | None
    fit: Fit
    verified: bool | None = None


@dataclass
class TemplateMatch:
    """One occurrence of a template in a stream."""

    interval: Interval
    score: float
    #: score over the best score the required leaves could reach, clamped to 1
    similarity: float
    #: fraction of required leaves that fit exactly
    identity: float
    columns: list[TemplateColumn]
    #: after :func:`verify`: every required leaf passed its structural match
    verified: bool | None = None
    #: after :func:`verify`: the capture bindings, by name
    captures: dict[str, object] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.interval)

    @property
    def placed_leaves(self) -> int:
        return sum(1 for c in self.columns if c.token is not None)


@dataclass(frozen=True)
class _Leaf:
    node: dsl.LeafStmt
    optional: bool
    weight: float
    shape: str | None  # exact shape, for seeding; None for a wildcard


def template_leaves(pattern: KnownPattern | dsl.PatternNode) -> list[dsl.LeafStmt]:
    """The template's leaf statements in stream order.

    A statement sequence is already in order. A graph pattern is flattened the
    way the tokenizer linearizes a function, reverse post-order from the entry,
    so that a template lifted from a selection lines up with the stream that
    produced it.
    """
    node = pattern.pattern if isinstance(pattern, KnownPattern) else pattern
    if isinstance(node, dsl.PGraphPat):
        order = _rpo(node)
        leaves: list[dsl.LeafStmt] = []
        for label in order:
            leaves.extend(iter_stmt_patterns(node.blocks[label]))
        return leaves
    if isinstance(node, dsl.PatternExpr):
        raise TypeError("an expression pattern has no statements to search for; wrap it in a statement")
    return list(iter_stmt_patterns(node))


def _rpo(graph: dsl.PGraphPat) -> list[str]:
    succs: dict[str, list[str]] = defaultdict(list)
    for src, dst in graph.edges:
        if dst in graph.blocks:
            succs[src].append(dst)
    post: list[str] = []
    seen = {graph.entry}
    stack: list[tuple[str, list[str]]] = [(graph.entry, sorted(succs[graph.entry]))]
    while stack:
        _label, rest = stack[-1]
        while rest:
            nxt = rest.pop(0)
            if nxt not in seen:
                seen.add(nxt)
                stack.append((nxt, sorted(succs[nxt])))
                break
        else:
            post.append(stack.pop()[0])
    return post[::-1]


def tokenize_for_templates(
    graph: networkx.DiGraph[Block], entry: Block, *, kb: KnowledgeBase | None = None, loader=None
) -> TokenStream:
    """A stream a template can be searched in: the tokenizer under the template settings."""
    return tokenize(graph, entry, kb=kb, loader=loader, **TEMPLATE_TOKENIZER)


class _Scorer:
    """Fit of every leaf against every distinct shape of the stream, computed on demand."""

    def __init__(self, leaves: list[_Leaf], stream: TokenStream, params: AlignParams):
        self._leaves = leaves
        self._trees: list[ShapeTree | None] = [None] * len(stream.shape_vocab)
        self._vocab = stream.shape_vocab
        self._fits: dict[tuple[int, int], Fit] = {}
        self._value = {Fit.EXACT: params.match, Fit.KLASS: params.klass_match, Fit.NONE: params.mismatch}

    def fit(self, leaf: int, shape_id: int) -> Fit:
        key = (leaf, shape_id)
        fit = self._fits.get(key)
        if fit is None:
            tree = self._trees[shape_id]
            if tree is None:
                tree = self._trees[shape_id] = parse_shape(self._vocab[shape_id])
            fit = self._fits[key] = match_shape(self._leaves[leaf].node, tree)
        return fit

    def score(self, leaf: int, shape_id: int) -> float:
        return self._value[self.fit(leaf, shape_id)] * self._leaves[leaf].weight


def _candidates(leaves: list[_Leaf], stream: TokenStream, params: AlignParams) -> list[int]:
    """Stream offsets at which the template may start, most promising first.

    Every concrete leaf votes for the diagonal of each stream token with its
    shape. A template with no concrete leaf at all cannot vote and is tried at
    every offset.
    """
    shape_index = {s: i for i, s in enumerate(stream.shape_vocab)}
    by_shape: dict[int, list[int]] = defaultdict(list)
    for pos, sid in enumerate(stream.shape_ids):
        by_shape[sid].append(pos)

    votes: dict[int, int] = defaultdict(int)
    concrete = 0
    for t, leaf in enumerate(leaves):
        if leaf.shape is None:
            continue
        concrete += 1
        sid = shape_index.get(leaf.shape)
        if sid is None:
            continue
        positions = by_shape[sid]
        if len(positions) > params.max_seed_multiplicity:
            continue
        for pos in positions:
            votes[pos - t] += 1
    if concrete == 0:
        return list(range(-len(leaves) + 1, len(stream)))
    ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
    return [d for d, _ in ranked[: params.max_candidates]]


def _is_glue(shape: str) -> bool:
    return shape in ("Jf", "Jb", "J?")


def _align(
    leaves: list[_Leaf],
    stream: TokenStream,
    scorer: _Scorer,
    lo: int,
    hi: int,
    params: AlignParams,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[float, list[TemplateColumn]] | None:
    """Semi-global affine-gap alignment of the whole template against stream ``[lo, hi)``.

    The template is consumed in full; the stream is free on both sides. Rows
    are template leaves, columns stream tokens. State M places a leaf on a
    token, X skips a leaf (free when the leaf is optional), Y skips a token.
    """
    n = len(leaves)
    width = hi - lo
    if n == 0 or width <= 0:
        return None
    ids = stream.shape_ids
    # an unconditional jump is control glue between blocks, not a statement an
    # occurrence has to account for: skipping one costs nothing
    glue = [_is_glue(stream.shapes[lo + j]) for j in range(width)]

    # dp[state][i][j], j in 0..width; column 0 is "before the window"
    m = [[_NEG] * (width + 1) for _ in range(n + 1)]
    x = [[_NEG] * (width + 1) for _ in range(n + 1)]
    y = [[_NEG] * (width + 1) for _ in range(n + 1)]
    back: dict[tuple[int, int, int], tuple[int, int, int]] = {}
    for j in range(width + 1):
        m[0][j] = 0.0  # a free start anywhere in the window

    for i in range(1, n + 1):
        if checkpoint is not None:
            checkpoint()
        leaf = leaves[i - 1]
        skip_open = 0.0 if leaf.optional else params.gap_open * leaf.weight
        skip_ext = 0.0 if leaf.optional else params.gap_extend * leaf.weight
        for j in range(width + 1):
            # skip leaf i (X): coming from any state at (i-1, j)
            best, src = m[i - 1][j] + skip_open, (0, i - 1, j)
            if x[i - 1][j] + skip_ext > best:
                best, src = x[i - 1][j] + skip_ext, (1, i - 1, j)
            if y[i - 1][j] + skip_open > best:
                best, src = y[i - 1][j] + skip_open, (2, i - 1, j)
            if best > _NEG:
                x[i][j] = best
                back[1, i, j] = src
            if j == 0:
                continue
            # place leaf i on token j (M)
            s = scorer.score(i - 1, ids[lo + j - 1])
            best, src = m[i - 1][j - 1], (0, i - 1, j - 1)
            if x[i - 1][j - 1] > best:
                best, src = x[i - 1][j - 1], (1, i - 1, j - 1)
            if y[i - 1][j - 1] > best:
                best, src = y[i - 1][j - 1], (2, i - 1, j - 1)
            if best > _NEG:
                m[i][j] = best + s
                back[0, i, j] = src
            # skip token j between placed leaves (Y): only inside the template
            tok_open, tok_ext = (0.0, 0.0) if glue[j - 1] else (params.gap_open, params.gap_extend)
            best, src = m[i][j - 1] + tok_open, (0, i, j - 1)
            if y[i][j - 1] + tok_ext > best:
                best, src = y[i][j - 1] + tok_ext, (2, i, j - 1)
            if best > _NEG:
                y[i][j] = best
                back[2, i, j] = src

    # the template is consumed; the stream after the last placed token is free
    end_j, end_state, best = 0, 0, _NEG
    for j in range(width + 1):
        for state, table in ((0, m), (1, x)):
            if table[n][j] > best:
                best, end_j, end_state = table[n][j], j, state
    if best == _NEG:
        return None

    columns: list[TemplateColumn] = []
    state, i, j = end_state, n, end_j
    while i > 0:
        if state == 0:
            columns.append(TemplateColumn(i - 1, lo + j - 1, scorer.fit(i - 1, ids[lo + j - 1])))
        elif state == 1:
            columns.append(TemplateColumn(i - 1, None, Fit.NONE))
        state, i, j = back[state, i, j]
    columns.reverse()
    return best, columns


def search(
    pattern: KnownPattern | dsl.PatternNode,
    stream: TokenStream,
    params: AlignParams | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> list[TemplateMatch]:
    """Every non-overlapping occurrence of ``pattern`` in ``stream`` scoring at least
    ``params.min_identity`` in similarity, best first. ``checkpoint`` is called from the
    alignment loops; see :class:`.priority.Checkpoint`.

    The stream must come from :func:`tokenize_for_templates` (or an equivalent
    :data:`~.template.TEMPLATE_TOKENIZER` configuration), or shapes will not
    line up with the template's rendering.
    """
    params = params or AlignParams()
    leaves = [
        _Leaf(node=node, optional=node.optional, weight=node.weight, shape=shape_of(node))
        for node in template_leaves(pattern)
    ]
    if not leaves:
        return []
    scorer = _Scorer(leaves, stream, params)
    n = len(leaves)
    required = [leaf for leaf in leaves if not leaf.optional]
    max_score = sum(params.match * leaf.weight for leaf in required) or sum(
        params.match * leaf.weight for leaf in leaves
    )

    found: list[TemplateMatch] = []
    seen_windows: set[tuple[int, int]] = set()
    # a window just wide enough for the gaps a copy can carry; wider, and two copies
    # near each other fall into one window, of which only the best comes back
    slack = max(n, 2)
    for start in _candidates(leaves, stream, params):
        if checkpoint is not None:
            checkpoint()
        lo = max(0, start - slack)
        hi = min(len(stream), start + n + slack)
        if (lo, hi) in seen_windows:
            continue
        seen_windows.add((lo, hi))
        aligned = _align(leaves, stream, scorer, lo, hi, params, checkpoint)
        if aligned is None:
            continue
        score, columns = aligned
        placed = [c.token for c in columns if c.token is not None]
        if not placed:
            continue
        exact_required = sum(
            1 for c in columns if c.token is not None and c.fit is Fit.EXACT and not leaves[c.leaf].optional
        )
        similarity = min(1.0, score / max_score) if max_score > 0 else 0.0
        if similarity < params.min_identity:
            continue
        found.append(
            TemplateMatch(
                interval=Interval(min(placed), max(placed) + 1),
                score=score,
                similarity=similarity,
                identity=exact_required / len(required) if required else 1.0,
                columns=columns,
            )
        )

    found.sort(key=lambda mt: (-mt.score, mt.interval.start))
    kept: list[TemplateMatch] = []
    for mt in found:
        if not any(mt.interval.overlaps(k.interval) for k in kept):
            kept.append(mt)
    return kept


def verify(
    match: TemplateMatch,
    pattern: KnownPattern | dsl.PatternNode,
    stream: TokenStream,
    ctx: MatchCtx | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> TemplateMatch:
    """Run every placed leaf's structural ``match`` on its statement, sharing one
    binding environment, and record the outcome on the match.

    Shapes erase constants, variable identity and sizes below the statement, so
    a leaf can fit a token's shape while its ``PConst(value=...)`` or a repeated
    capture name does not hold. A required leaf that fails leaves the match
    unverified; an optional one is merely noted on its column.
    """
    # a lifted pattern has had its conversions dropped, so its leaves must step over them
    ctx = ctx or MatchCtx(
        skip_conversions=True,
        skip_conversions_at_leaves=True,
        call_target_fn=_callee_names_fn(stream.kb),
        symbol_addr_fn=_symbol_addr_fn(stream.kb),
    )
    leaves = template_leaves(pattern)
    blocks = {(b.addr, b.idx): b for b in stream.blocks}
    state = MatchState()
    ok = True
    columns: list[TemplateColumn] = []
    for column in match.columns:
        if checkpoint is not None:
            checkpoint()
        if column.token is None:
            columns.append(column)
            continue
        loc = stream.locs[column.token]
        stmt = blocks[loc.block_loc].statements[loc.stmt_idx]
        new_state = leaves[column.leaf].match(stmt, state, ctx)
        passed = new_state is not None
        if passed:
            state = new_state
        elif not leaves[column.leaf].optional:
            ok = False
        columns.append(TemplateColumn(column.leaf, column.token, column.fit, verified=passed))
    match.columns = columns
    match.verified = ok
    match.captures = dict(state.bindings)
    return match


def _callee_names_fn(kb: KnowledgeBase | None) -> Callable[[Call], frozenset[str]]:
    """Every name a call's callee is known by, as the exact finder resolves them."""
    cache: dict[int, frozenset[str]] = {}

    def resolve(call: Call) -> frozenset[str]:
        target = call.target
        if isinstance(target, str):
            return frozenset((target,))
        if kb is None or not isinstance(target, Const) or not isinstance(target.value, int):
            return frozenset()
        addr = target.value
        names = cache.get(addr)
        if names is None:
            func = kb.functions.get_by_addr(addr) if kb.functions.contains_addr(addr) else None
            names = frozenset(n for n in ((func.name, func.demangled_name) if func is not None else ()) if n)
            cache[addr] = names
        return names

    return resolve


def _symbol_addr_fn(kb: KnowledgeBase | None) -> Callable[[str], int | None]:
    """Where a named symbol lives in this binary."""

    def resolve(name: str) -> int | None:
        return symbol_addr(kb._project.loader, name) if kb is not None else None

    return resolve


def find_template_occurrences(
    pattern: KnownPattern | dsl.PatternNode,
    graph: networkx.DiGraph[Block],
    entry: Block,
    *,
    kb: KnowledgeBase | None = None,
    params: AlignParams | None = None,
    ctx: MatchCtx | None = None,
    checkpoint: Callable[[], None] | None = None,
) -> tuple[TokenStream, list[TemplateMatch]]:
    """Tokenize ``graph``, search it for ``pattern``, and verify every hit."""
    stream = tokenize_for_templates(graph, entry, kb=kb)
    matches = search(pattern, stream, params, checkpoint)
    for match in matches:
        verify(match, pattern, stream, ctx, checkpoint)
    return stream, matches


__all__ = [
    "TemplateColumn",
    "TemplateMatch",
    "find_template_occurrences",
    "search",
    "template_leaves",
    "tokenize_for_templates",
    "verify",
]
