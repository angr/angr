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
import math
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
    # statements whose shape is too common to vote; a copy can only be counted on for the rest
    voting = 0
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
        voting += 1
        for pos in positions:
            votes[pos - t] += 1
    if concrete == 0:
        return list(range(-len(leaves) + 1, len(stream)))
    # a real occurrence lines up many statements on its diagonal; a diagonal only one or two
    # happen to agree on is not worth a window, and a large template has hundreds of those.
    # Measured against the statements that can vote: common shapes do not, so a template
    # made mostly of them gets few votes even on its own copy.
    threshold = min(params.min_votes, max(1, math.ceil(voting / 4)))
    ranked = sorted(((d, v) for d, v in votes.items() if v >= threshold), key=lambda kv: (-kv[1], kv[0]))
    return [d for d, _ in ranked[: params.max_candidates]]


def _is_glue(shape: str) -> bool:
    return shape in ("Jf", "Jb", "J?")


#: the band of an alignment never narrows below this many tokens either side of its diagonals
_MIN_BAND = 16


def _align(
    leaves: list[_Leaf],
    stream: TokenStream,
    scorer: _Scorer,
    lo: int,
    hi: int,
    params: AlignParams,
    checkpoint: Callable[[], None] | None = None,
    diagonals: list[int] | None = None,
    min_score: float | None = None,
) -> tuple[float, list[TemplateColumn]] | None:
    """Semi-global affine-gap alignment of the whole template against stream ``[lo, hi)``.

    The template is consumed in full; the stream is free on both sides. Rows
    are template leaves, columns stream tokens. State M places a leaf on a
    token, X skips a leaf (free when the leaf is optional), Y skips a token.

    With ``diagonals``, only cells within a band of a quarter of the template's length
    (at least :data:`_MIN_BAND`) around them are computed. With ``min_score``, a first
    pass computes scores alone and gives up on a window that cannot reach it; only a
    window that can is aligned again with traceback.
    """
    n = len(leaves)
    width = hi - lo
    if n == 0 or width <= 0:
        return None
    ids = stream.shape_ids
    # an unconditional jump is control glue between blocks, not a statement an
    # occurrence has to account for: skipping one costs nothing
    glue = [_is_glue(stream.shapes[lo + j]) for j in range(width)]
    if diagonals:
        band = max(_MIN_BAND, n // 4)
        dmin, dmax = min(diagonals) - lo, max(diagonals) - lo
        bounds = [(max(0, dmin + i - band), min(width, dmax + i + band)) for i in range(n + 1)]
    else:
        bounds = [(0, width)] * (n + 1)

    def run(keep: bool):
        """(best score, end column, end state, rows) where rows is kept only for traceback."""
        clo, chi = bounds[0]
        pm = [0.0] * (chi - clo + 1)  # a free start anywhere in the window
        px = [_NEG] * len(pm)
        py = [_NEG] * len(pm)
        plo = clo
        rows = [(clo, pm, px, py, None)] if keep else None
        for i in range(1, n + 1):
            if checkpoint is not None:
                checkpoint()
            leaf = leaves[i - 1]
            skip_open = 0.0 if leaf.optional else params.gap_open * leaf.weight
            skip_ext = 0.0 if leaf.optional else params.gap_extend * leaf.weight
            clo, chi = bounds[i]
            if chi < clo:
                return None
            size = chi - clo + 1
            cm = [_NEG] * size
            cx = [_NEG] * size
            cy = [_NEG] * size
            bm = [0] * size if keep else None
            bx = [0] * size if keep else None
            by = [0] * size if keep else None
            plen = len(pm)
            for k in range(size):
                j = clo + k
                # skip leaf i (X): coming from any state at (i-1, j)
                pk = j - plo
                if 0 <= pk < plen:
                    best, code = pm[pk] + skip_open, 0
                    if px[pk] + skip_ext > best:
                        best, code = px[pk] + skip_ext, 1
                    if py[pk] + skip_open > best:
                        best, code = py[pk] + skip_open, 2
                    if best > _NEG:
                        cx[k] = best
                        if keep:
                            bx[k] = code
                if j == 0:
                    continue
                # place leaf i on token j (M): from (i-1, j-1)
                pk -= 1
                if 0 <= pk < plen:
                    best, code = pm[pk], 0
                    if px[pk] > best:
                        best, code = px[pk], 1
                    if py[pk] > best:
                        best, code = py[pk], 2
                    if best > _NEG:
                        cm[k] = best + scorer.score(i - 1, ids[lo + j - 1])
                        if keep:
                            bm[k] = code
                # skip token j between placed leaves (Y): from (i, j-1), only inside the template
                if k > 0:
                    tok_open, tok_ext = (0.0, 0.0) if glue[j - 1] else (params.gap_open, params.gap_extend)
                    best, code = cm[k - 1] + tok_open, 0
                    if cy[k - 1] + tok_ext > best:
                        best, code = cy[k - 1] + tok_ext, 2
                    if best > _NEG:
                        cy[k] = best
                        if keep:
                            by[k] = code
            pm, px, py, plo = cm, cx, cy, clo
            if keep:
                rows.append((clo, cm, cx, cy, (bm, bx, by)))
        # the template is consumed; the stream after the last placed token is free
        end_j, end_state, best = 0, 0, _NEG
        for k in range(len(pm)):
            for state, table in ((0, pm), (1, px)):
                if table[k] > best:
                    best, end_j, end_state = table[k], plo + k, state
        return best, end_j, end_state, rows

    first = run(keep=False)
    if first is None or first[0] == _NEG:
        return None
    if min_score is not None and first[0] < min_score:
        return None
    best, end_j, end_state, rows = run(keep=True)

    columns: list[TemplateColumn] = []
    state, i, j = end_state, n, end_j
    while i > 0:
        clo, _cm, _cx, _cy, (bm, bx, by) = rows[i]
        k = j - clo
        if state == 0:
            columns.append(TemplateColumn(i - 1, lo + j - 1, scorer.fit(i - 1, ids[lo + j - 1])))
            state, i, j = bm[k], i - 1, j - 1
        elif state == 1:
            columns.append(TemplateColumn(i - 1, None, Fit.NONE))
            state, i = bx[k], i - 1
        else:
            state, j = by[k], j - 1
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
    # a window just wide enough for the gaps a copy can carry around its diagonal
    slack = max(n, 2)
    diagonals = sorted(_candidates(leaves, stream, params))
    # Neighbouring diagonals are the same copy seen from a little to the side, so they are
    # aligned as one window. A window's best alignment is found, and the parts of the window
    # either side of it are searched again if a candidate diagonal lands there, so two copies
    # near each other are both found. A window whose best is below the cutoff holds nothing:
    # every other alignment in it scores lower still.
    windows: list[tuple[int, int, list[int]]] = []
    for d in diagonals:
        if windows and d - windows[-1][2][-1] <= slack:
            windows[-1][2].append(d)
        else:
            windows.append((0, 0, [d]))
    work = [(max(0, ds[0] - slack), min(len(stream), ds[-1] + n + slack), ds) for _, _, ds in windows]
    while work:
        if checkpoint is not None:
            checkpoint()
        lo, hi, ds = work.pop()
        if hi - lo <= 0:
            continue
        aligned = _align(
            leaves, stream, scorer, lo, hi, params, checkpoint, diagonals=ds, min_score=params.min_identity * max_score
        )
        if aligned is None:
            continue
        score, columns = aligned
        placed = [c.token for c in columns if c.token is not None]
        if not placed:
            continue
        similarity = min(1.0, score / max_score) if max_score > 0 else 0.0
        if similarity < params.min_identity:
            continue
        exact_required = sum(
            1 for c in columns if c.token is not None and c.fit is Fit.EXACT and not leaves[c.leaf].optional
        )
        match = TemplateMatch(
            interval=Interval(min(placed), max(placed) + 1),
            score=score,
            similarity=similarity,
            identity=exact_required / len(required) if required else 1.0,
            columns=columns,
        )
        found.append(match)
        for side_lo, side_hi in ((lo, match.interval.start), (match.interval.end, hi)):
            side = [d for d in ds if side_lo <= d + n // 2 < side_hi]
            if side:
                work.append((side_lo, side_hi, side))

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
