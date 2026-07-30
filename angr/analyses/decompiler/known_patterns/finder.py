"""KnownPatternFinder: find occurrences of KnownPatterns in a Clinic AIL graph
and outline them into calls via the Outliner analysis."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Convert,
    Expression,
    Extract,
    Insert,
    Load,
    Reinterpret,
    UnaryOp,
    VirtualVariable,
    VirtualVariableCategory,
)
from angr.ailment.statement import (
    Assignment,
    ConditionalJump,
    DirtyStatement,
    Jump,
    Label,
    Return,
    SideEffectStatement,
    Statement,
    Store,
    WeakAssignment,
)
from angr.analyses.analysis import AnalysesHub, Analysis
from angr.analyses.outliner import Outliner
from angr.analyses.s_reaching_definitions import SReachingDefinitionsAnalysis
from angr.knowledge_plugins.functions import Function
from angr.utils.ssa import is_phi_assignment

from .dsl import MatchCtx, MatchState, PatternExpr, PatternStmt, PGraphPat, PStmtSeq, expr_anchor_key
from .pattern import KnownPattern

BlockLoc = tuple[int, "int | None"]

_l = logging.getLogger(__name__)

# (field name, element index or None) steps from a statement root down to an expression
ExprPath = tuple[tuple[str, int | None], ...]


class UnsupportedOutlineError(Exception):
    """Raised when a match cannot be safely outlined (e.g. side-effecting
    statements interleave with the matched span, or the recovered callee
    interface does not agree with the pattern's declared parameters)."""


@dataclass
class KnownPatternMatch:
    """One occurrence of a KnownPattern in an AIL graph.

    For expression-level matches, the boundary is ``consumed_stmt_idxs``
    (statements wholly owned by the match, e.g. chased definitions) plus
    ``expr_path`` (the location of the matched sub-expression inside the
    anchor statement). For statement-sequence matches, ``stmt_span`` holds the
    ordered matched statement indices (the anchor is the first) and
    ``matched_expr`` is None.
    """

    pattern: KnownPattern
    block_loc: tuple[int, int | None]
    anchor_stmt_idx: int
    expr_path: ExprPath
    consumed_stmt_idxs: frozenset[int]
    captures: dict[str, Expression]
    matched_expr: Expression | None
    # statement-sequence matches only
    stmt_span: tuple[int, ...] | None = None
    # multi-block (graph) matches only
    block_map: dict[str, tuple[int, int | None]] | None = None
    consumed_by_block: dict[tuple[int, int | None], frozenset[int]] | None = None
    frontier_locs: frozenset[tuple[int, int | None]] | None = None

    def __repr__(self):
        return (
            f"<KnownPatternMatch {self.pattern.name} @ {self.block_loc[0]:#x}"
            f"{'' if self.block_loc[1] is None else '.' + str(self.block_loc[1])}"
            f"[{self.anchor_stmt_idx}]>"
        )


@dataclass
class OutlineResult:
    """The outcome of outlining one KnownPatternMatch."""

    graph: networkx.DiGraph
    match: KnownPatternMatch
    call_stmt: Statement
    child_func: Function
    child_graph: networkx.DiGraph
    child_funcargs: list[VirtualVariable]


def _iter_expr_children(expr: Expression) -> Iterator[tuple[tuple[str, int | None], Expression]]:
    if isinstance(expr, BinaryOp):
        yield ("operands", 0), expr.operands[0]
        yield ("operands", 1), expr.operands[1]
    elif isinstance(expr, (UnaryOp, Convert, Reinterpret)):
        yield ("operand", None), expr.operand
    elif isinstance(expr, Extract):
        yield ("base", None), expr.base
    elif isinstance(expr, Insert):
        yield ("base", None), expr.base
        yield ("value", None), expr.value
    elif isinstance(expr, Load):
        yield ("addr", None), expr.addr
    elif isinstance(expr, ITE):
        yield ("cond", None), expr.cond
        yield ("iftrue", None), expr.iftrue
        yield ("iffalse", None), expr.iffalse
    elif isinstance(expr, Call):
        if isinstance(expr.target, Expression):
            yield ("target", None), expr.target
        if expr.args:
            for i, arg in enumerate(expr.args):
                yield ("args", i), arg


def _iter_stmt_subexprs(stmt: Statement) -> Iterator[tuple[ExprPath, Expression]]:
    """Enumerate all sub-expressions of a statement in pre-order, with their paths."""
    roots: list[tuple[tuple[str, int | None], Expression]] = []
    if isinstance(stmt, (Assignment, WeakAssignment)):
        roots = [(("dst", None), stmt.dst), (("src", None), stmt.src)]
    elif isinstance(stmt, Store):
        roots = [(("addr", None), stmt.addr), (("data", None), stmt.data)]
    elif isinstance(stmt, Return):
        roots = [(("ret_exprs", i), expr) for i, expr in enumerate(stmt.ret_exprs)]
    elif isinstance(stmt, ConditionalJump):
        roots = [(("condition", None), stmt.condition)]
    elif isinstance(stmt, SideEffectStatement):
        roots = [(("expr", None), stmt.expr)]

    stack: list[tuple[ExprPath, Expression]] = [((step,), expr) for step, expr in reversed(roots)]
    while stack:
        path, expr = stack.pop()
        yield path, expr
        for step, child in _iter_expr_children(expr):
            stack.append(((*path, step), child))


def _stmt_has_side_effects(stmt: Statement) -> bool:
    if isinstance(stmt, (Store, DirtyStatement, SideEffectStatement)):
        return True
    return any(isinstance(expr, Call) for _, expr in _iter_stmt_subexprs(stmt))


def _stmt_touches_memory(stmt: Statement) -> bool:
    if isinstance(stmt, (Store, DirtyStatement, SideEffectStatement)):
        return True
    return any(isinstance(expr, (Load, Call)) for _, expr in _iter_stmt_subexprs(stmt))


def _stmt_defs(stmt: Statement) -> frozenset[int]:
    if isinstance(stmt, (Assignment, WeakAssignment)) and isinstance(stmt.dst, VirtualVariable):
        return frozenset((stmt.dst.varid,))
    return frozenset()


def _stmt_uses(stmt: Statement) -> frozenset[int]:
    return frozenset(
        expr.varid for _, expr in _iter_stmt_subexprs(stmt) if isinstance(expr, VirtualVariable)
    ) - _stmt_defs(stmt)


class KnownPatternFinder(Analysis):
    """Finds occurrences of KnownPatterns in a Clinic AIL graph.

    The graph to match on is the final (SSA-form) Clinic graph, i.e.
    ``decompiler.ail_graph`` / ``clinic.cc_graph``. Matches are reported in
    ``self.matches``; :meth:`outline` turns a match into a synthesized call by
    invoking the Outliner analysis on a copy of the graph.
    """

    def __init__(
        self,
        func: Function,
        ail_graph: networkx.DiGraph,
        patterns: Iterable[object] | None = None,
        chase_defs: bool = True,
        skip_conversions: bool = True,
        vvar_id_start: int = 0xBEEF,
        block_addr_start: int = 0xAABB_0000,
        ail_manager=None,
    ):
        """``patterns`` may be pattern templates (KnownPatternTemplate) and/or
        already-concrete KnownPatterns; templates are instantiated for this
        binary's PatternContext. When None, the enabled-by-default templates are
        used."""
        from . import ALL_KNOWN_PATTERN_TEMPLATES, patterns_for  # pylint:disable=import-outside-toplevel
        from .context import PatternContext  # pylint:disable=import-outside-toplevel
        from .templates import KnownPatternTemplate  # pylint:disable=import-outside-toplevel

        self._func = func
        self._graph = ail_graph
        self._chase_defs = chase_defs
        self._skip_conversions = skip_conversions
        self._ail_manager = ail_manager
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start

        ctx = PatternContext.from_project(self.project)
        if patterns is None:
            self._patterns = patterns_for(ctx, ALL_KNOWN_PATTERN_TEMPLATES, enabled_only=True)
        else:
            selected = list(patterns)
            templates = [p for p in selected if isinstance(p, KnownPatternTemplate)]
            concrete = [p for p in selected if not isinstance(p, KnownPatternTemplate)]
            self._patterns = patterns_for(ctx, templates)
            arch_name = ctx.arch_name
            platform = self.project.simos.name if self.project.simos is not None else None
            self._patterns += [
                p
                for p in concrete
                if p.applicable(arch_name, platform) and (p.binary_guard is None or p.binary_guard(self.project))
            ]

        self.matches: list[KnownPatternMatch] = []
        self._srda_model = None
        self._analyze()

    #
    # matching
    #

    def _analyze(self) -> None:
        if not self._patterns:
            return
        if self._chase_defs:
            self._srda_model = (
                self.project.analyses[SReachingDefinitionsAnalysis]
                .prep(kb=self.kb)(self._func, func_graph=self._graph)
                .model
            )

        raw_matches: list[KnownPatternMatch] = []
        for block in self._graph.nodes:
            raw_matches.extend(self._match_block(block))

        # deduplicate/greedily select non-overlapping matches. Largest match wins:
        # for nested expressions that means the one closest to the statement root
        # (shortest expr_path); for statement-set matches, which all sit at the
        # root, it means the one covering the most statements — so a superset like
        # list_del_init beats the RemoveEntryList unlink it contains regardless of
        # registration order. Registration order only breaks remaining ties.
        pattern_order = {id(p): i for i, p in enumerate(self._patterns)}
        raw_matches.sort(
            key=lambda m: (
                m.block_loc[0],
                -1 if m.block_loc[1] is None else m.block_loc[1],
                m.anchor_stmt_idx,
                len(m.expr_path),
                -len(self._stmt_footprint(m)),
                pattern_order[id(m.pattern)],
            )
        )
        selected: list[KnownPatternMatch] = []
        for m in raw_matches:
            if not any(self._conflicts(m, s) for s in selected):
                selected.append(m)
        self.matches = selected

    @staticmethod
    def _stmt_footprint(m: KnownPatternMatch) -> frozenset[int]:
        return m.consumed_stmt_idxs | {m.anchor_stmt_idx} | (frozenset(m.stmt_span) if m.stmt_span else frozenset())

    @staticmethod
    def _blocks_of(m: KnownPatternMatch) -> set[tuple[int, int | None]]:
        if m.block_map is not None:
            return set(m.block_map.values())
        return {m.block_loc}

    @classmethod
    def _conflicts(cls, m1: KnownPatternMatch, m2: KnownPatternMatch) -> bool:
        # a multi-block match owns whole blocks; conservatively conflict with
        # any other match sharing one of its blocks
        if m1.block_map is not None or m2.block_map is not None:
            return bool(cls._blocks_of(m1) & cls._blocks_of(m2))

        if m1.block_loc != m2.block_loc:
            return False
        footprints_overlap = bool(cls._stmt_footprint(m1) & cls._stmt_footprint(m2))
        if m1.stmt_span is not None or m2.stmt_span is not None:
            # statement-level matches own their whole statements
            return footprints_overlap
        if m1.consumed_stmt_idxs & m2.consumed_stmt_idxs:
            return True
        if m1.anchor_stmt_idx in m2.consumed_stmt_idxs or m2.anchor_stmt_idx in m1.consumed_stmt_idxs:
            return True
        if m1.anchor_stmt_idx != m2.anchor_stmt_idx:
            return False
        # same anchor statement: conflict iff one matched expression contains the other
        shorter, longer = sorted((m1.expr_path, m2.expr_path), key=len)
        return longer[: len(shorter)] == shorter

    def _match_block(self, block: Block) -> Iterator[KnownPatternMatch]:
        # graph patterns are anchored at their entry block
        for pattern in self._patterns:
            if isinstance(pattern.pattern, PGraphPat):
                m = self._try_match_graph(pattern, block)
                if m is not None:
                    yield m
        # unordered statement-set patterns are matched once per block
        for pattern in self._patterns:
            if isinstance(pattern.pattern, PStmtSeq) and not pattern.pattern.ordered:
                m = self._try_match_stmt_bag(pattern, block)
                if m is not None:
                    yield m
        for stmt_idx, stmt in enumerate(block.statements):
            if is_phi_assignment(stmt):
                continue
            # statement-level patterns (single statements and ordered sequences)
            if not isinstance(stmt, Label):
                for pattern in self._patterns:
                    if isinstance(pattern.pattern, PStmtSeq) and not pattern.pattern.ordered:
                        continue
                    if isinstance(pattern.pattern, PatternStmt):
                        m = self._try_match_stmt_seq(pattern, block, stmt_idx)
                        if m is not None:
                            yield m
            # expression-level patterns
            for path, expr in _iter_stmt_subexprs(stmt):
                key = expr_anchor_key(expr)
                for pattern in self._patterns:
                    if not isinstance(pattern.pattern, PatternExpr):
                        continue
                    if not self._anchor_compatible(pattern.pattern, key):
                        continue
                    m = self._try_match(pattern, block, stmt_idx, expr, path, stmt)
                    if m is not None:
                        yield m

    @staticmethod
    def _scan_stmt_seq(
        block: Block,
        stmt_pats: tuple[PatternStmt, ...],
        allow_gaps: bool,
        start_idx: int,
        anchored: bool,
        state: MatchState,
        ctx: MatchCtx,
    ) -> tuple[MatchState, list[int]] | None:
        """Match ``stmt_pats`` in order against ``block`` starting at
        ``start_idx``. Label statements and phi assignments are skippable; with
        ``allow_gaps`` unrelated statements may sit between matched ones. When
        ``anchored``, the first pattern must match exactly at ``start_idx``.
        Returns ``(state, matched_idxs)`` or None. An empty ``stmt_pats``
        trivially matches with no consumed statements."""
        stmts = block.statements
        matched: list[int] = []
        scan = start_idx
        for pat_i, stmt_pat in enumerate(stmt_pats):
            found = False
            while scan < len(stmts):
                stmt = stmts[scan]
                skippable_gap = isinstance(stmt, Label) or is_phi_assignment(stmt)
                if not skippable_gap:
                    new_state = stmt_pat.match(stmt, state, ctx)
                    if new_state is not None:
                        state = new_state
                        matched.append(scan)
                        scan += 1
                        found = True
                        break
                if pat_i == 0 and anchored:
                    return None
                if not (skippable_gap or allow_gaps):
                    return None
                scan += 1
            if not found:
                return None
        return state, matched

    @staticmethod
    def _stmt_pats_of(pat: PatternStmt) -> tuple[tuple[PatternStmt, ...], bool]:
        if isinstance(pat, PStmtSeq):
            return pat.stmts, pat.allow_gaps
        return (pat,), False

    def _try_match_stmt_seq(self, pattern: KnownPattern, block: Block, start_idx: int) -> KnownPatternMatch | None:
        """Match a statement-level pattern (a single statement pattern or a
        PStmtSeq) anchored at ``start_idx``."""
        stmt_pats, allow_gaps = self._stmt_pats_of(pattern.pattern)  # type: ignore[arg-type]
        if not stmt_pats:
            return None
        ctx = MatchCtx(
            skip_conversions=self._skip_conversions,
            chase_fn=self._make_chase_fn(block, start_idx) if self._chase_defs else None,
        )
        result = self._scan_stmt_seq(block, stmt_pats, allow_gaps, start_idx, True, MatchState(), ctx)
        if result is None:
            return None
        state, matched = result
        if pattern.where is not None and not pattern.where(state.bindings):
            return None

        matched_stmt_idxs = state.consumed_stmt_idxs | frozenset(matched)
        for varid, _def_stmt_idx in state.chased_defs:
            if not self._all_uses_within(varid, block, matched_stmt_idxs):
                return None

        return KnownPatternMatch(
            pattern=pattern,
            block_loc=(block.addr, block.idx),
            anchor_stmt_idx=matched[0],
            expr_path=(),
            consumed_stmt_idxs=state.consumed_stmt_idxs,
            captures=dict(state.bindings),
            matched_expr=None,
            stmt_span=tuple(matched),
        )

    def _try_match_stmt_bag(self, pattern: KnownPattern, block: Block) -> KnownPatternMatch | None:
        """Match an unordered PStmtSeq: assign each statement pattern to a
        distinct non-Label/non-phi statement of the block, in any order, under
        one unifying MatchState. Statement patterns are tried in declaration
        order so that def-before-use captures bind correctly."""
        seq = pattern.pattern
        assert isinstance(seq, PStmtSeq)
        stmt_pats = seq.stmts
        if not stmt_pats:
            return None
        candidates = [
            i for i, s in enumerate(block.statements) if not isinstance(s, Label) and not is_phi_assignment(s)
        ]
        ctx = MatchCtx(skip_conversions=self._skip_conversions, chase_fn=None)

        def assign(pat_i: int, used: frozenset[int], state: MatchState) -> tuple[MatchState, list[int]] | None:
            if pat_i == len(stmt_pats):
                return state, sorted(used)
            for idx in candidates:
                if idx in used:
                    continue
                new_state = stmt_pats[pat_i].match(block.statements[idx], state, ctx)
                if new_state is None:
                    continue
                out = assign(pat_i + 1, used | {idx}, new_state)
                if out is not None:
                    return out
            return None

        result = assign(0, frozenset(), MatchState())
        if result is None:
            return None
        state, matched = result
        if pattern.where is not None and not pattern.where(state.bindings):
            return None

        return KnownPatternMatch(
            pattern=pattern,
            block_loc=(block.addr, block.idx),
            anchor_stmt_idx=matched[0],
            expr_path=(),
            consumed_stmt_idxs=frozenset(),
            captures=dict(state.bindings),
            matched_expr=None,
            stmt_span=tuple(matched),
        )

    def _match_block_seq(
        self, block: Block, block_pat, state: MatchState, ctx: MatchCtx
    ) -> tuple[MatchState, frozenset[int]] | None:
        """Match a PBlockPat's statement sequence anywhere within ``block``
        (not anchored). Returns ``(state, consumed_idxs)`` or None."""
        stmt_pats, allow_gaps = self._stmt_pats_of(block_pat.stmts)
        result = self._scan_stmt_seq(block, stmt_pats, allow_gaps, 0, False, state, ctx)
        if result is None:
            return None
        new_state, matched = result
        return new_state, frozenset(matched)

    def _try_match_graph(self, pattern: KnownPattern, entry_block: Block) -> KnownPatternMatch | None:
        gpat = pattern.pattern
        assert isinstance(gpat, PGraphPat)
        ctx = MatchCtx(skip_conversions=self._skip_conversions, chase_fn=None)

        # order internal blocks by BFS from the entry over internal edges, so
        # each block (after entry) is reached from an already-mapped block
        internal = set(gpat.blocks)
        adj: dict[str, list[str]] = {lbl: [] for lbl in internal}
        for src, dst in gpat.edges:
            if dst in internal:
                adj[src].append(dst)
        order = [gpat.entry]
        seen = {gpat.entry}
        i = 0
        while i < len(order):
            for nb in adj[order[i]]:
                if nb not in seen:
                    seen.add(nb)
                    order.append(nb)
            i += 1

        pat_edges = [(s, d) for s, d in gpat.edges]

        # recursive injective assignment of pattern labels to graph blocks
        def assign(
            idx: int, mapping: dict[str, Block], state: MatchState, consumed: dict[str, frozenset[int]]
        ) -> KnownPatternMatch | None:
            if idx == len(order):
                return self._finalize_graph_match(pattern, gpat, pat_edges, mapping, state, consumed)
            label = order[idx]
            if label == gpat.entry:
                candidates = [entry_block]
            else:
                pred_label = next(s for s, d in pat_edges if d == label and s in mapping)
                candidates = [s for s in self._graph.successors(mapping[pred_label]) if s not in mapping.values()]
            for cand in candidates:
                res = self._match_block_seq(cand, gpat.blocks[label], state, ctx)
                if res is None:
                    continue
                new_state, cons = res
                out = assign(
                    idx + 1,
                    {**mapping, label: cand},
                    new_state,
                    {**consumed, label: cons},
                )
                if out is not None:
                    return out
            return None

        return assign(0, {}, MatchState(), {})

    def _finalize_graph_match(
        self,
        pattern: KnownPattern,
        gpat: PGraphPat,
        pat_edges: list[tuple[str, str]],
        mapping: dict[str, Block],
        state: MatchState,
        consumed: dict[str, frozenset[int]],
    ) -> KnownPatternMatch | None:
        internal = set(gpat.blocks)
        loc = {lbl: (b.addr, b.idx) for lbl, b in mapping.items()}
        mapped_locs = set(loc.values())

        # every internal pattern edge must exist in the graph
        for src, dst in pat_edges:
            if dst in internal and mapping[dst] not in self._graph.successors(mapping[src]):
                return None

        # collect frontier locs (successors of mapped blocks that are not mapped)
        # and enforce the escape rule: every out-edge of a mapped block goes to
        # a mapped block along a pattern edge, or to a frontier loc
        internal_edge_pairs = {(loc[s], loc[d]) for s, d in pat_edges if d in internal}
        frontier: set[tuple[int, int | None]] = set()
        for lbl, b in mapping.items():
            for succ in self._graph.successors(b):
                sloc = (succ.addr, succ.idx)
                if sloc in mapped_locs:
                    if (loc[lbl], sloc) not in internal_edge_pairs:
                        return None  # an edge between matched blocks the pattern does not describe
                else:
                    frontier.add(sloc)
        if not gpat.external_labels and frontier:
            return None
        if gpat.external_labels and not frontier:
            return None

        if pattern.where is not None and not pattern.where(state.bindings):
            return None

        consumed_by_block = {loc[lbl]: consumed[lbl] for lbl in mapping}
        entry_loc = loc[gpat.entry]
        return KnownPatternMatch(
            pattern=pattern,
            block_loc=entry_loc,
            anchor_stmt_idx=min(consumed[gpat.entry], default=0),
            expr_path=(),
            consumed_stmt_idxs=consumed[gpat.entry],
            captures=dict(state.bindings),
            matched_expr=None,
            block_map=loc,
            consumed_by_block=consumed_by_block,
            frontier_locs=frozenset(frontier),
        )

    @staticmethod
    def _anchor_compatible(root: PatternExpr, key: tuple[str, str | None]) -> bool:
        from .dsl import pattern_anchor_key  # pylint:disable=import-outside-toplevel

        pkey = pattern_anchor_key(root)
        if pkey is None:
            return True
        if pkey[0] != key[0]:
            return False
        return pkey[1] is None or pkey[1] == key[1]

    def _try_match(
        self,
        pattern: KnownPattern,
        block: Block,
        stmt_idx: int,
        target: Expression | Statement,
        path: ExprPath,
        anchor_stmt: Statement,
    ) -> KnownPatternMatch | None:
        ctx = MatchCtx(
            skip_conversions=self._skip_conversions,
            chase_fn=self._make_chase_fn(block, stmt_idx) if self._chase_defs else None,
        )
        state = pattern.pattern.match(target, MatchState(), ctx)
        if state is None:
            return None
        if pattern.where is not None and not pattern.where(state.bindings):
            return None

        matched_stmt_idxs = state.consumed_stmt_idxs | {stmt_idx}
        # the all-uses-inside rule: every chased definition's vvar must be used
        # exclusively within the matched statements, otherwise moving the
        # definition into the outlined callee would break the other uses
        for varid, _def_stmt_idx in state.chased_defs:
            if not self._all_uses_within(varid, block, matched_stmt_idxs):
                return None

        return KnownPatternMatch(
            pattern=pattern,
            block_loc=(block.addr, block.idx),
            anchor_stmt_idx=stmt_idx,
            expr_path=path,
            consumed_stmt_idxs=state.consumed_stmt_idxs,
            captures=dict(state.bindings),
            matched_expr=target if isinstance(target, Expression) else None,  # type: ignore[arg-type]
        )

    def _make_chase_fn(self, block: Block, anchor_stmt_idx: int):
        def chase(varid: int) -> tuple[int, Expression] | None:
            if self._srda_model is None:
                return None
            defloc = self._srda_model.all_vvar_definitions.get(varid)
            if defloc is None or defloc.is_extern:
                return None
            if (defloc.addr, defloc.block_idx) != (block.addr, block.idx):
                return None
            if defloc.stmt_idx >= anchor_stmt_idx:
                return None
            def_stmt = block.statements[defloc.stmt_idx]
            if not isinstance(def_stmt, Assignment) or is_phi_assignment(def_stmt):
                return None
            return defloc.stmt_idx, def_stmt.src

        return chase

    def _all_uses_within(self, varid: int, block: Block, stmt_idxs: set[int] | frozenset[int]) -> bool:
        assert self._srda_model is not None
        for _, loc in self._srda_model.all_vvar_uses.get(varid, []):
            if loc.is_extern:
                return False
            if (loc.addr, loc.block_idx) != (block.addr, block.idx) or loc.stmt_idx not in stmt_idxs:
                return False
        return True

    #
    # outlining
    #

    def outline(self, match: KnownPatternMatch, ail_graph: networkx.DiGraph | None = None) -> OutlineResult:
        """Outline one match: split the anchor block so the matched span forms
        its own block, invoke the Outliner analysis on it, and rewrite the
        synthesized callsite into the pattern's call. Operates on (and returns)
        a copy; neither ``self._graph`` nor ``ail_graph`` is mutated."""
        from angr.analyses.decompiler.clinic import Clinic  # pylint:disable=import-outside-toplevel

        from .block_split import split_ail_block  # pylint:disable=import-outside-toplevel

        g = Clinic._copy_graph(ail_graph if ail_graph is not None else self._graph)
        nodes_dict = {(node.addr, node.idx): node for node in g}
        try:
            block = nodes_dict[match.block_loc]
        except KeyError as e:
            raise UnsupportedOutlineError(f"block {match.block_loc} is not in the given graph") from e

        if match.block_map is not None:
            return self._outline_graph(match, g)
        if match.stmt_span is not None:
            return self._outline_stmt_span(match, g, block)

        stmts = list(block.statements)
        anchor_idx = match.anchor_stmt_idx
        if anchor_idx >= len(stmts):
            raise UnsupportedOutlineError("stale match: the anchor statement is gone from the block")
        anchor = stmts[anchor_idx]
        if match.expr_path:
            anchored_expr = next((expr for path, expr in _iter_stmt_subexprs(anchor) if path == match.expr_path), None)
            if anchored_expr is None or not anchored_expr.likes(match.matched_expr):
                raise UnsupportedOutlineError(
                    "stale match: the anchor statement no longer contains the matched expression"
                )
        consumed = sorted(match.consumed_stmt_idxs)
        if any(i >= anchor_idx for i in consumed):
            raise UnsupportedOutlineError("consumed statements must precede the anchor statement")

        # moving consumed statements down to the matched span must not cross
        # side-effecting statements
        if consumed:
            for i in range(consumed[0], anchor_idx):
                if i not in match.consumed_stmt_idxs and _stmt_has_side_effects(stmts[i]):
                    raise UnsupportedOutlineError(
                        "side-effecting statements interleave with the matched statement span"
                    )

        ins_addr = anchor.tags.get("ins_addr")

        # determine the result vvar; lift the matched sub-expression into its
        # own assignment unless the anchor already is one
        anchor_absorbed = (
            isinstance(anchor, Assignment)
            and match.expr_path == (("src", None),)
            and isinstance(anchor.dst, VirtualVariable)
        )
        if anchor_absorbed:
            result_vvar = anchor.dst
            mid_stmts = [stmts[i] for i in consumed] + [anchor]
            post_head: list[Statement] = []
        else:
            vvar_id = self._next_vvar_id()
            result_vvar = VirtualVariable(
                None,
                vvar_id,
                match.matched_expr.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                ins_addr=ins_addr,
            )
            lifted = Assignment(None, result_vvar, match.matched_expr.copy(), ins_addr=ins_addr)
            replaced, new_anchor = anchor.replace(match.matched_expr, result_vvar.copy())
            if not replaced:
                raise UnsupportedOutlineError("failed to replace the matched expression in the anchor statement")
            mid_stmts = [stmts[i] for i in consumed] + [lifted]
            post_head = [new_anchor]

        pre_stmts = [s for i, s in enumerate(stmts[:anchor_idx]) if i not in match.consumed_stmt_idxs]
        post_stmts = post_head + stmts[anchor_idx + 1 :]

        _, b_mid, b_post = split_ail_block(g, block, pre_stmts, mid_stmts, post_stmts, self._next_block_addr)

        if b_post is not None:
            frontier_loc = (b_post.addr, b_post.idx)
        else:
            succs = [s for s in g.successors(b_mid) if s is not b_mid]
            if len(succs) != 1:
                raise UnsupportedOutlineError(
                    "the matched span ends its block and the block does not have exactly one successor"
                )
            frontier_loc = (succs[0].addr, succs[0].idx)

        return self._run_outliner_and_rewrite(g, match, (b_mid.addr, b_mid.idx), frontier_loc, ins_addr)

    def _outline_stmt_span(self, match: KnownPatternMatch, g: networkx.DiGraph, block: Block) -> OutlineResult:
        """Outline a statement-sequence match: the matched statements (plus any
        chased definitions) move wholesale into the callee; no expression
        lifting is involved."""
        from .block_split import split_ail_block  # pylint:disable=import-outside-toplevel

        assert match.stmt_span is not None
        # re-validate the match on the (copied) block; this both catches stale
        # matches and rebinds the captures to the copy's expressions
        seq = match.pattern.pattern
        if isinstance(seq, PStmtSeq) and not seq.ordered:
            revalidated = self._try_match_stmt_bag(match.pattern, block)
        else:
            revalidated = self._try_match_stmt_seq(match.pattern, block, match.stmt_span[0])
        if revalidated is None or set(revalidated.stmt_span or ()) != set(match.stmt_span):
            raise UnsupportedOutlineError("stale match: the statement span no longer matches the pattern")
        match = revalidated

        stmts = list(block.statements)
        span = list(match.stmt_span)
        consumed = sorted(match.consumed_stmt_idxs)
        if any(i >= span[0] for i in consumed):
            raise UnsupportedOutlineError("chased definitions must precede the matched span")
        if consumed:
            for i in range(consumed[0], span[0]):
                if i not in match.consumed_stmt_idxs and _stmt_has_side_effects(stmts[i]):
                    raise UnsupportedOutlineError("side-effecting statements interleave with the chased definitions")

        # gap statements inside the span are hoisted before the outlined
        # region; that is only sound if they neither touch memory around the
        # region's stores/calls nor use values the region defines
        matched_set = set(span) | set(consumed)
        matched_defs = frozenset().union(*(_stmt_defs(stmts[i]) for i in matched_set))
        region_has_side_effects = any(_stmt_has_side_effects(stmts[i]) for i in matched_set)
        gap_idxs = [i for i in range(span[0], span[-1]) if i not in matched_set]
        for i in gap_idxs:
            if region_has_side_effects and _stmt_touches_memory(stmts[i]):
                raise UnsupportedOutlineError("memory-touching statements interleave with the matched span")
            if _stmt_uses(stmts[i]) & matched_defs:
                raise UnsupportedOutlineError("interleaved statements use values defined by the matched span")

        pre_stmts = [s for i, s in enumerate(stmts[: span[0]]) if i not in match.consumed_stmt_idxs] + [
            stmts[i] for i in gap_idxs
        ]
        mid_stmts = [stmts[i] for i in consumed] + [stmts[i] for i in span]
        post_stmts = stmts[span[-1] + 1 :]

        ins_addr = stmts[span[0]].tags.get("ins_addr")
        _, b_mid, b_post = split_ail_block(g, block, pre_stmts, mid_stmts, post_stmts, self._next_block_addr)

        if b_post is not None:
            frontier_loc = (b_post.addr, b_post.idx)
        else:
            succs = [s for s in g.successors(b_mid) if s is not b_mid]
            if len(succs) != 1:
                raise UnsupportedOutlineError(
                    "the matched span ends its block and the block does not have exactly one successor"
                )
            frontier_loc = (succs[0].addr, succs[0].idx)

        return self._run_outliner_and_rewrite(g, match, (b_mid.addr, b_mid.idx), frontier_loc, ins_addr)

    def _outline_graph(self, match: KnownPatternMatch, g: networkx.DiGraph) -> OutlineResult:
        """Outline a multi-block (graph) match: the matched region (entry block
        plus fully-consumed interior blocks) is handed to the Outliner as a
        single-entry region with the matched external successor as frontier."""
        from .block_split import split_ail_block  # pylint:disable=import-outside-toplevel

        assert match.block_map is not None and match.frontier_locs is not None
        assert match.consumed_by_block is not None

        if len(match.frontier_locs) != 1:
            raise UnsupportedOutlineError(
                f"pattern {match.pattern.name}: region has {len(match.frontier_locs)} exits; v1 outlining "
                f"supports exactly one"
            )
        (frontier_loc,) = match.frontier_locs

        nodes_dict = {(node.addr, node.idx): node for node in g}
        entry_loc = match.block_map[match.pattern.pattern.entry]
        interior_locs = [loc for lbl, loc in match.block_map.items() if loc != entry_loc]

        # every interior (non-entry) block must be fully consumed apart from
        # Label statements and a trailing unconditional Jump — otherwise the
        # region has residue we cannot cut. A Jump is control-flow scaffolding
        # the Outliner rebuilds from the region edges, not data-flow residue, so
        # it never needs a pattern node to consume it (an interior block ending
        # in an explicit `goto merge`, common in un-structured AIL, is fine).
        for loc in interior_locs:
            block = nodes_dict.get(loc)
            if block is None:
                raise UnsupportedOutlineError("stale match: a matched block is gone from the graph")
            consumed = match.consumed_by_block[loc]
            for i, stmt in enumerate(block.statements):
                if i not in consumed and not isinstance(stmt, (Label, Jump)):
                    raise UnsupportedOutlineError(
                        f"pattern {match.pattern.name}: interior block {loc} has unmatched statements"
                    )

        entry_block = nodes_dict.get(entry_loc)
        if entry_block is None:
            raise UnsupportedOutlineError("stale match: the entry block is gone from the graph")
        entry_consumed = match.consumed_by_block[entry_loc]
        entry_residue = [
            i for i, s in enumerate(entry_block.statements) if i not in entry_consumed and not isinstance(s, Label)
        ]

        src_loc = entry_loc
        if entry_residue:
            # the entry has leading residue; it must all precede the consumed
            # part, and the entry must not be re-entered from inside the region
            # (a back-edge into a split entry would corrupt the region)
            if any(i > min(entry_consumed, default=len(entry_block.statements)) for i in entry_residue):
                raise UnsupportedOutlineError(
                    f"pattern {match.pattern.name}: the entry block interleaves matched and unmatched statements"
                )
            if any(
                pred in nodes_dict.values() and (pred.addr, pred.idx) in set(match.block_map.values())
                for pred in g.predecessors(entry_block)
            ):
                raise UnsupportedOutlineError(
                    f"pattern {match.pattern.name}: the entry block is re-entered from within the region"
                )
            pre_stmts = [entry_block.statements[i] for i in entry_residue]
            mid_stmts = [s for i, s in enumerate(entry_block.statements) if i not in entry_residue]
            _, b_mid, _ = split_ail_block(g, entry_block, pre_stmts, mid_stmts, [], self._next_block_addr)
            src_loc = (b_mid.addr, b_mid.idx)

        ins_addr = entry_block.statements[min(entry_consumed)].tags.get("ins_addr") if entry_consumed else None
        return self._run_outliner_and_rewrite(g, match, src_loc, frontier_loc, ins_addr)

    def _run_outliner_and_rewrite(
        self,
        g: networkx.DiGraph,
        match: KnownPatternMatch,
        src_loc: tuple[int, int | None],
        frontier_loc: tuple[int, int | None],
        ins_addr: int | None,
    ) -> OutlineResult:
        outliner = self.project.analyses[Outliner].prep(kb=self.kb)(
            self._func,
            g,
            src_loc=src_loc,
            frontier={frontier_loc},
            vvar_id_start=self.vvar_id_start,
            block_addr_start=self.block_addr_start,
        )
        self.vvar_id_start = outliner.vvar_id_start
        self.block_addr_start = outliner.block_addr_start

        void_call = match.pattern.returnty is None and match.pattern.returnty_factory is None
        if void_call and outliner.frontier_vars:
            raise UnsupportedOutlineError(
                f"pattern {match.pattern.name} is declared void but the outlined region has live-out values"
            )
        if not void_call and match.stmt_span is not None and not outliner.frontier_vars:
            raise UnsupportedOutlineError(
                f"pattern {match.pattern.name} declares a return type but the outlined region has no live-out value"
            )

        call_stmt = self._rewrite_callsite(g, match, src_loc, outliner.child_funcargs, ins_addr, void_call)

        return OutlineResult(
            graph=g,
            match=match,
            call_stmt=call_stmt,
            child_func=outliner.child_func,
            child_graph=outliner.child_graph,
            child_funcargs=outliner.child_funcargs,
        )

    def outline_at(
        self,
        location: tuple[int, int | None] | tuple[int, int | None, int],
        pattern: KnownPattern,
        ail_graph: networkx.DiGraph,
    ) -> OutlineResult:
        """Find ``pattern`` at ``location`` (``(block_addr, block_idx)`` or
        ``(block_addr, block_idx, stmt_idx)``) in ``ail_graph`` and outline it."""
        finder = self.project.analyses[KnownPatternFinder].prep(kb=self.kb)(
            self._func,
            ail_graph,
            patterns=[pattern],
            chase_defs=self._chase_defs,
            skip_conversions=self._skip_conversions,
            vvar_id_start=self.vvar_id_start,
            block_addr_start=self.block_addr_start,
        )
        block_loc = location[:2]
        for m in finder.matches:
            if m.block_loc != block_loc:
                continue
            if len(location) > 2 and m.anchor_stmt_idx != location[2]:
                continue
            return self.outline(m, ail_graph=ail_graph)
        raise UnsupportedOutlineError(f"pattern {pattern.name} does not match at location {location}")

    def _rewrite_callsite(
        self,
        g: networkx.DiGraph,
        match: KnownPatternMatch,
        call_block_loc: tuple[int, int | None],
        child_funcargs: list[VirtualVariable],
        ins_addr: int | None,
        void_call: bool = False,
    ) -> Statement:
        nodes_dict = {(node.addr, node.idx): node for node in g}
        call_block = nodes_dict.get(call_block_loc)
        if call_block is None:
            raise UnsupportedOutlineError("cannot find the synthesized call block after outlining")
        call_stmt_idx = next(
            (i for i, s in enumerate(call_block.statements) if isinstance(s, Assignment) and isinstance(s.src, Call)),
            None,
        )
        if call_stmt_idx is None:
            raise UnsupportedOutlineError("cannot find the synthesized call statement after outlining")
        old_stmt = call_block.statements[call_stmt_idx]
        old_call = old_stmt.src

        pattern = match.pattern
        param_vvars: list[VirtualVariable] = []
        for param in pattern.params:
            captured = match.captures.get(param.capture)
            if not isinstance(captured, VirtualVariable):
                raise UnsupportedOutlineError(
                    f"pattern {pattern.name}: capture {param.capture!r} is not a virtual variable"
                )
            param_vvars.append(captured)
        if {v.varid for v in param_vvars} != {v.varid for v in child_funcargs}:
            raise UnsupportedOutlineError(
                f"pattern {pattern.name}: the recovered callee interface "
                f"{sorted(v.varid for v in child_funcargs)} does not agree with the declared parameters "
                f"{sorted(v.varid for v in param_vvars)}"
            )

        args: list[Expression] = [v.copy() for v in param_vvars]
        for name in pattern.extra_args:
            captured = match.captures.get(name)
            if captured is None:
                raise UnsupportedOutlineError(f"pattern {pattern.name}: extra arg capture {name!r} is unbound")
            args.append(captured.copy())

        new_call = Call(
            self._ail_manager.next_atom() if self._ail_manager is not None else None,
            pattern.call_name,
            args=args,
            bits=old_call.bits,
            ins_addr=ins_addr if ins_addr is not None else old_call.tags.get("ins_addr"),
            known_pattern=pattern.name,
            is_prototype_guessed=False,
        )
        new_stmt: Statement
        if void_call:
            # the Outliner's synthesized destination is a dead return-register
            # vvar; drop it so the call renders as a bare statement
            new_stmt = SideEffectStatement(None, new_call, ret_expr=None, fp_ret_expr=None, **old_stmt.tags)
        else:
            new_stmt = Assignment(None, old_stmt.dst, new_call, **old_stmt.tags)
        call_block.statements[call_stmt_idx] = new_stmt
        return new_stmt

    def _next_vvar_id(self) -> int:
        vvar_id = self.vvar_id_start
        self.vvar_id_start += 1
        return vvar_id

    def _next_block_addr(self) -> int:
        block_addr = self.block_addr_start
        self.block_addr_start += 1
        return block_addr


AnalysesHub.register_default("KnownPatternFinder", KnownPatternFinder)
