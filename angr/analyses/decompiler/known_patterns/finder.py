"""KnownPatternFinder: find occurrences of KnownPatterns in a Clinic AIL graph
and outline them into calls via the Outliner analysis."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from dataclasses import replace as dataclass_replace

import networkx

from angr.ailment.block import Block
from angr.ailment.expression import (
    ITE,
    BinaryOp,
    Call,
    Const,
    Convert,
    Expression,
    Extract,
    Insert,
    Load,
    Reinterpret,
    StackBaseOffset,
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

from .dsl import (
    MatchCtx,
    MatchState,
    PatternExpr,
    PatternStmt,
    PGraphPat,
    PStmtSeq,
    expr_anchor_key,
    pattern_anchor_key,
)
from .pattern import KnownPattern

BlockLoc = tuple[int, "int | None"]

# expression kinds whose value depends only on their operands
_PURE_EXPR_TYPES_FWD = (BinaryOp, UnaryOp, Convert, Reinterpret, Extract, Insert, ITE)

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

    ``duplicated_stmt_idxs`` holds chased definitions that are *copied* into the
    outlined region instead of moved: the originals stay where they are (other
    code still uses them) and the copies make the pattern's captured values the
    region's live-ins. It is always disjoint from ``consumed_stmt_idxs``.

    ``recomputed_defs`` does the same for definitions that live in *another*
    block (a CSE'd value, possibly reaching the anchor through a phi): the
    expression is pure, so the region recomputes it from the captured operands.
    """

    pattern: KnownPattern
    block_loc: tuple[int, int | None]
    anchor_stmt_idx: int
    expr_path: ExprPath
    consumed_stmt_idxs: frozenset[int]
    captures: dict[str, Expression]
    matched_expr: Expression | None
    # chased definitions copied into the region, originals left in place
    duplicated_stmt_idxs: frozenset[int] = frozenset()
    # (varid, pure expression) definitions from other blocks, recomputed in the region
    recomputed_defs: tuple[tuple[int, Expression], ...] = ()
    # (varid, root varid, displacement) for variables that hold `root + displacement`
    # -- an object address the compiler computed once into a register of its own.
    # Nothing is moved for these; the outliner only rewrites references to them.
    base_aliases: tuple[tuple[int, int, int], ...] = ()
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


def _iter_subexprs(obj: Statement | Expression) -> Iterator[Expression]:
    """Every sub-expression of a statement, or of an expression (itself included)."""
    if isinstance(obj, Statement):
        for _, expr in _iter_stmt_subexprs(obj):
            yield expr
        return
    stack: list[Expression] = [obj]
    while stack:
        expr = stack.pop()
        yield expr
        for _, child in _iter_expr_children(expr):
            stack.append(child)


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

    # how many definitions (phi levels included) a remote chase follows
    MAX_REMOTE_CHASE_DEPTH = 6

    def __init__(
        self,
        func: Function,
        ail_graph: networkx.DiGraph,
        patterns: Iterable[object] | None = None,
        chase_defs: bool = True,
        chase_remote_defs: bool = True,
        skip_conversions: bool = True,
        vvar_id_start: int = 0xBEEF,
        block_addr_start: int = 0xAABB_0000,
        ail_manager=None,
        force_patterns: str | Iterable[str] | None = None,
    ):
        """``patterns`` may be pattern templates (KnownPatternTemplate) and/or
        already-concrete KnownPatterns; templates are instantiated for this
        binary's PatternContext. When None, the registry is used, filtered down
        to the templates that are enabled for this target: default-on ones, ones
        named by ``force_patterns``, and ones whose gate opens (see
        :mod:`.gating`).

        ``force_patterns`` is the user's force-enable selection — ``"all"`` or
        an iterable of template names / call names — and is only consulted when
        ``patterns`` is None (an explicit pattern list is already a selection).
        """
        from . import (  # pylint:disable=import-outside-toplevel
            partition_templates,
            patterns_for,
            resolve_pattern_selection,
        )
        from .context import PatternContext  # pylint:disable=import-outside-toplevel
        from .gating import GateContext  # pylint:disable=import-outside-toplevel
        from .templates import KnownPatternTemplate  # pylint:disable=import-outside-toplevel

        self._func = func
        self._graph = ail_graph
        self._chase_defs = chase_defs
        self._chase_remote_defs = chase_defs and chase_remote_defs
        self._skip_conversions = skip_conversions
        # varid -> the pure expression it can be recomputed from, or None
        self._remote_def_cache: dict[int, Expression | None] = {}
        # call target address -> every name that callee is known by
        self._call_names_cache: dict[int, frozenset[str]] = {}
        # varid -> the Call that defines it, or None
        self._call_def_cache: dict[int, Call | None] = {}
        self._blocks_by_loc: dict[tuple[int, int | None], Block] | None = None
        self._ail_manager = ail_manager
        self.vvar_id_start = vvar_id_start
        self.block_addr_start = block_addr_start

        ctx = PatternContext.from_project(self.project)
        self._ctx = ctx
        self._gate_ctx = GateContext(ctx=ctx, project=self.project)
        # templates whose gate needs the function's own matches to decide; resolved in a second stage by _analyze
        self._deferred_templates: list[KnownPatternTemplate] = []
        if patterns is None:
            forced = resolve_pattern_selection(force_patterns)
            enabled, self._deferred_templates = partition_templates(self._gate_ctx, forced)
            self._patterns = patterns_for(ctx, enabled)
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

        self._index_patterns()
        self.matches: list[KnownPatternMatch] = []
        self._srda_model = None
        self._analyze()

    def _index_patterns(self) -> None:
        """Bucket the candidate patterns by anchor key.

        The library is generated per element size -- one std::vector<T>::size
        template for every sizeof(T) -- so it runs to four figures, and a linear
        scan that recomputes pattern_anchor_key at every expression of every
        block is quadratic in exactly the wrong variable.

        Must be re-run whenever ``_patterns`` changes: the corroboration stage
        enlarges it mid-analysis, and an index built only in __init__ silently
        ignores every pattern a gate opens.
        """
        self._expr_patterns_by_key: dict[tuple[str, str | None], list[KnownPattern]] = defaultdict(list)
        self._expr_patterns_any: list[KnownPattern] = []
        self._stmt_patterns: list[KnownPattern] = []
        for p in self._patterns:
            if isinstance(p.pattern, PatternStmt):
                self._stmt_patterns.append(p)
                continue
            if not isinstance(p.pattern, PatternExpr):
                continue
            pkey = pattern_anchor_key(p.pattern)
            if pkey is None:
                self._expr_patterns_any.append(p)
            else:
                self._expr_patterns_by_key[pkey].append(p)

    def _expr_candidates(self, key: tuple[str, str | None]) -> list[KnownPattern]:
        """Patterns worth trying at an expression with this anchor key: those
        that discriminate on it, those that discriminate on its kind but not its
        op, and those that discriminate on nothing."""
        return (
            self._expr_patterns_any
            + self._expr_patterns_by_key.get(key, [])
            + (self._expr_patterns_by_key.get((key[0], None), []) if key[1] is not None else [])
        )

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

        self.matches = self._match_all()

        if self._deferred_templates:
            self._resolve_corroborated_patterns()

    def _resolve_corroborated_patterns(self) -> None:
        """Second matching stage for the gates that need per-function evidence.

        The evidence is what the *ungated* first stage established, so a gated
        pattern can never be its own witness. When a gate opens, the whole
        function is re-matched with the enlarged pattern set, so the newly
        enabled patterns take part in the greedy largest-match-wins selection on
        equal footing rather than being bolted on afterwards.

        The enlarged result is only kept if the gates are *still* open on it.
        A generic pattern often strictly contains its own witness — ``empty`` is
        ``CmpEQ(Load(s + size_off), 0)`` and the inner load is exactly the
        ``length`` match that justified enabling it — and when it swallows the
        last occurrence of that witness, the corroboration was circular: the
        function no longer shows the unambiguous idiom the naming rests on. In
        that case the first stage's matches stand.
        """
        from . import patterns_for  # pylint:disable=import-outside-toplevel

        stage1 = self.matches
        # known-pattern calls already in the graph count as evidence too: an earlier outlining round may have
        # replaced the corroborating idiom with its call, and the call name is exactly the witness name
        graph_calls = self._known_pattern_calls()
        evidence = self._evidence_of(stage1) | graph_calls
        if not evidence:
            return
        gate_ctx = self._gate_ctx.with_evidence(evidence)
        opened = [t for t in self._deferred_templates if t.gate is not None and t.gate(gate_ctx)]
        if not opened:
            return
        extra = patterns_for(self._ctx, opened)
        if not extra:
            return

        extra_ids = {id(p) for p in extra}
        self._patterns = self._patterns + extra
        self._index_patterns()
        stage2 = self._match_all()
        surviving = self._evidence_of(m for m in stage2 if id(m.pattern) not in extra_ids) | graph_calls
        gate_ctx = self._gate_ctx.with_evidence(surviving)
        if all(t.gate(gate_ctx) for t in opened if t.gate is not None):
            self.matches = stage2
        else:
            self._patterns = [p for p in self._patterns if id(p) not in extra_ids]
            self._index_patterns()

    @staticmethod
    def _evidence_of(matches: Iterable[KnownPatternMatch]) -> set[str]:
        """Both spellings (short name and call name) of every matched pattern."""
        evidence: set[str] = set()
        for m in matches:
            evidence.add(m.pattern.name)
            evidence.add(m.pattern.call_name)
        return evidence

    def _known_pattern_calls(self) -> set[str]:
        """Call names of the known-pattern calls already present in the graph."""
        from . import TEMPLATE_BY_CALL_NAME  # pylint:disable=import-outside-toplevel

        out: set[str] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                for _, expr in _iter_stmt_subexprs(stmt):
                    if isinstance(expr, Call) and isinstance(expr.target, str) and expr.target in TEMPLATE_BY_CALL_NAME:
                        out.add(expr.target)
        return out

    def _match_all(self) -> list[KnownPatternMatch]:
        raw_matches: list[KnownPatternMatch] = []
        for block in self._graph.nodes:
            raw_matches.extend(self._match_block(block))

        # deduplicate/greedily select non-overlapping matches. Largest match wins:
        # the one covering the most statements first — so a superset like
        # list_del_init beats the RemoveEntryList unlink it contains, and an idiom
        # that reaches back over its operands' definitions beats a sub-pattern
        # anchored in one of them (std::string::length matches the bare _M_finish
        # load of every std::vector<T>::size) — then, among matches of the same
        # size, the one closest to the statement root (shortest expr_path).
        # Registration order only breaks remaining ties. Matches are positioned at
        # the first statement they cover rather than at their anchor, so that a
        # match reaching back over earlier statements is offered first.
        pattern_order = {id(p): i for i, p in enumerate(self._patterns)}
        raw_matches.sort(
            key=lambda m: (
                m.block_loc[0],
                -1 if m.block_loc[1] is None else m.block_loc[1],
                min(self._stmt_footprint(m)),
                -len(self._stmt_footprint(m)),
                len(m.expr_path),
                pattern_order[id(m.pattern)],
            )
        )
        selected: list[KnownPatternMatch] = []
        for m in raw_matches:
            if not any(self._conflicts(m, s) for s in selected):
                selected.append(m)
        return self._collapse_folded_idioms(selected)

    def _collapse_folded_idioms(self, matches: list[KnownPatternMatch]) -> list[KnownPatternMatch]:
        """Keep one match per ``collapse_capture`` value, the one with the
        largest ``collapse_max_capture``.

        A compiler folds a pointer adjustment into every displacement that reads
        through it, so one source-level idiom reaches the matcher as a family of
        matches on the same base value with different constants -- and each of
        them names a different, mostly wrong, adjusted pointer. They describe one
        idiom, and the largest constant is the one that reaches the true base:
        every field of the record sits at ``base + member``, i.e. at
        ``p - (off - member)``, so no member can produce an offset larger than
        the idiom's own.

        Bases that a previous outlining round already named are excluded too --
        otherwise the rounds simply peel the family off one offset at a time."""
        claimed = self._collapsed_bases()
        best: dict[tuple[str, int], tuple[int, KnownPatternMatch]] = {}
        out: list[KnownPatternMatch] = []
        for m in matches:
            pattern = m.pattern
            if pattern.collapse_capture is None or pattern.collapse_max_capture is None:
                out.append(m)
                continue
            base = m.captures.get(pattern.collapse_capture)
            const = m.captures.get(pattern.collapse_max_capture)
            if not isinstance(base, VirtualVariable) or not isinstance(const, Const):
                out.append(m)
                continue
            key = (pattern.name, base.varid)
            if key in claimed:
                continue
            kept = best.get(key)
            if kept is None or const.value > kept[0]:
                best[key] = (const.value, m)
        out.extend(m for _, m in best.values())
        return out

    def _collapsed_bases(self) -> set[tuple[str, int]]:
        """``(pattern name, varid)`` of the bases already named by a synthesized
        call in the graph, for the patterns that collapse per base."""
        by_call = {p.call_name: p for p in self._patterns if p.collapse_capture is not None}
        if not by_call:
            return set()
        claimed: set[tuple[str, int]] = set()
        for block in self._graph.nodes:
            for stmt in block.statements:
                for _, expr in _iter_stmt_subexprs(stmt):
                    if not isinstance(expr, Call) or not isinstance(expr.target, str) or not expr.args:
                        continue
                    pattern = by_call.get(expr.target)
                    if pattern is None:
                        continue
                    idx = next(
                        (i for i, prm in enumerate(pattern.params) if prm.capture == pattern.collapse_capture), None
                    )
                    if idx is None or idx >= len(expr.args):
                        continue
                    arg = expr.args[idx]
                    if isinstance(arg, VirtualVariable):
                        claimed.add((pattern.name, arg.varid))
        return claimed

    @staticmethod
    def _stmt_footprint(m: KnownPatternMatch) -> frozenset[int]:
        """The statements a match covers. Duplicated definitions count: the match
        reads through them even though it leaves them in place, so a competing
        match anchored inside one of them describes the same code."""
        return (
            m.consumed_stmt_idxs
            | m.duplicated_stmt_idxs
            | {m.anchor_stmt_idx}
            | (frozenset(m.stmt_span) if m.stmt_span else frozenset())
        )

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
        # a duplicated definition stays where it is, so two matches may both read
        # through it; but a match anchored *inside* one describes a part of the
        # other, and the larger one has already been offered first
        if m1.anchor_stmt_idx in m2.duplicated_stmt_idxs or m2.anchor_stmt_idx in m1.duplicated_stmt_idxs:
            return True
        if m1.consumed_stmt_idxs & m2.duplicated_stmt_idxs or m2.consumed_stmt_idxs & m1.duplicated_stmt_idxs:
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
                for pattern in self._stmt_patterns:
                    if isinstance(pattern.pattern, PStmtSeq) and not pattern.pattern.ordered:
                        continue
                    m = self._try_match_stmt_seq(pattern, block, stmt_idx)
                    if m is not None:
                        yield m
            # expression-level patterns
            for path, expr in _iter_stmt_subexprs(stmt):
                for pattern in self._expr_candidates(expr_anchor_key(expr)):
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
        max_gap: int = 8,
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
            limit = len(stmts) if not matched else min(len(stmts), matched[-1] + 1 + max_gap)
            while scan < limit:
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
    def _stmt_pats_of(pat: PatternStmt) -> tuple[tuple[PatternStmt, ...], bool, int]:
        if isinstance(pat, PStmtSeq):
            return pat.stmts, pat.allow_gaps, pat.max_gap
        return (pat,), False, 0

    def _try_match_stmt_seq(self, pattern: KnownPattern, block: Block, start_idx: int) -> KnownPatternMatch | None:
        """Match a statement-level pattern (a single statement pattern or a
        PStmtSeq) anchored at ``start_idx``."""
        stmt_pats, allow_gaps, max_gap = self._stmt_pats_of(pattern.pattern)  # type: ignore[arg-type]
        if not stmt_pats:
            return None
        ctx = MatchCtx(
            skip_conversions=self._skip_conversions,
            chase_fn=self._make_chase_fn(block, start_idx) if self._chase_defs else None,
            call_target_fn=self._resolve_call_target,
            call_def_fn=self._resolve_call_def,
        )
        result = self._scan_stmt_seq(block, stmt_pats, allow_gaps, start_idx, True, MatchState(), ctx, max_gap)
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
            base_aliases=state.base_aliases,
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
        # An unordered bag match does not chase: the statements it consumes are
        # already the whole idiom. Peeking is read-only and stays available.
        ctx = MatchCtx(
            skip_conversions=self._skip_conversions,
            chase_fn=None,
            peek_fn=self._resolve_remote_def,
            stack_slot_fn=self._resolve_stack_slot,
            call_target_fn=self._resolve_call_target,
            call_def_fn=self._resolve_call_def,
        )

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
        stmt_pats, allow_gaps, max_gap = self._stmt_pats_of(block_pat.stmts)
        result = self._scan_stmt_seq(block, stmt_pats, allow_gaps, 0, False, state, ctx, max_gap)
        if result is None:
            return None
        new_state, matched = result
        return new_state, frozenset(matched)

    def _try_match_graph(self, pattern: KnownPattern, entry_block: Block) -> KnownPatternMatch | None:
        gpat = pattern.pattern
        assert isinstance(gpat, PGraphPat)
        # No chasing: a graph match consumes whole blocks, so there is nothing to
        # move a definition into. Peeking is still fine -- it reads a definition
        # without disturbing it, which is what lets a region whose object address
        # was computed into its own register (MSVC c_str, clang's capacity
        # triangle) match at all.
        ctx = MatchCtx(
            skip_conversions=self._skip_conversions,
            chase_fn=None,
            peek_fn=self._resolve_remote_def,
            stack_slot_fn=self._resolve_stack_slot,
            call_target_fn=self._resolve_call_target,
            call_def_fn=self._resolve_call_def,
        )

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
            base_aliases=state.base_aliases,
        )

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
            peek_fn=self._resolve_remote_def,
            stack_slot_fn=self._resolve_stack_slot,
            remote_chase_fn=self._make_remote_chase_fn(),
            call_target_fn=self._resolve_call_target,
            call_def_fn=self._resolve_call_def,
        )
        state = pattern.pattern.match(target, MatchState(), ctx)
        if state is None:
            return None
        if pattern.where is not None and not pattern.where(state.bindings):
            return None

        matched_stmt_idxs = state.consumed_stmt_idxs | {stmt_idx}
        # A chased definition can only be *moved* into the outlined callee when
        # nothing else uses it. In optimized code the intermediate values of an
        # idiom are routinely reused from other blocks -- that is exactly why the
        # compiler kept them in registers -- so rejecting the match outright makes
        # a pattern unreachable on the very code it targets.
        #
        # When a chased definition is shared, keep every chased statement where it
        # is instead and let the synthesized call recompute the value from the
        # captured pointer. Keeping *all* of them, rather than only the shared
        # ones, is what makes this safe to do piecemeal: a kept statement may
        # depend on another chased definition, and consuming that one would leave
        # a dangling reference behind.
        #
        # Recomputation is only sound if the callee re-reads the same memory, so
        # the span from the earliest chased definition to the anchor must not
        # write to memory or call anything.
        shared = [d for varid, d in state.chased_defs if not self._all_uses_within(varid, block, matched_stmt_idxs)]
        consumed = state.consumed_stmt_idxs
        duplicated: frozenset[int] = frozenset()
        if shared:
            span_start = min([*shared, *consumed]) if consumed else min(shared)
            for i in range(span_start, stmt_idx):
                if _stmt_has_side_effects(block.statements[i]):
                    return None
            captured = [state.bindings.get(param.capture) for param in pattern.params]
            # A capture that is not already a variable is fine as long as the
            # outliner can evaluate it into one in front of the region
            # (_materialize_exprs); anything else -- a call, a side effect -- is not.
            if not all(
                isinstance(cap, VirtualVariable) or (cap is not None and self._is_liftable(cap)) for cap in captured
            ):
                return None
            # Keeping the chased definitions shrinks the outlined region to the
            # anchor alone, so every value the synthesized call passes must still
            # be an input of that statement. When a capture is only reachable
            # *through* a kept definition -- a chained member load, say -- the
            # region's live-in is the intermediate value instead of the captured
            # pointer, and the callee interface cannot agree with the declared
            # parameters. Copy the chased definitions into the region for those:
            # the statements are pure (the span check above rejects anything
            # else), so the copies recompute the intermediate value from the
            # captured pointer while the originals stay behind for their other
            # users, and the region's live-in becomes the pointer again.
            anchor_uses = _stmt_uses(block.statements[stmt_idx])
            if not all(isinstance(cap, VirtualVariable) and cap.varid in anchor_uses for cap in captured):
                duplicated = consumed
            consumed = frozenset()

        # a recomputed definition only makes sense if the values the call will pass
        # are virtual variables the region can take as live-ins
        if state.remote_defs and not all(
            isinstance(state.bindings.get(param.capture), VirtualVariable) for param in pattern.params
        ):
            return None

        return KnownPatternMatch(
            pattern=pattern,
            block_loc=(block.addr, block.idx),
            anchor_stmt_idx=stmt_idx,
            expr_path=path,
            consumed_stmt_idxs=consumed,
            captures=dict(state.bindings),
            matched_expr=target if isinstance(target, Expression) else None,  # type: ignore[arg-type]
            duplicated_stmt_idxs=duplicated,
            recomputed_defs=state.remote_defs,
            base_aliases=state.base_aliases,
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

    def _make_remote_chase_fn(self):
        if not self._chase_remote_defs:
            return None
        return self._resolve_remote_def

    def _block_at(self, loc: tuple[int, int | None]) -> Block | None:
        if self._blocks_by_loc is None:
            self._blocks_by_loc = {(b.addr, b.idx): b for b in self._graph.nodes}
        return self._blocks_by_loc.get(loc)

    def _resolve_stack_slot(self, varid: int, _depth: int = 0) -> VirtualVariable | None:
        """The stack slot a variable was copied from, through a chain of copies.

        A local container's fields are stack slots, but the compiler routinely
        keeps one of them in a register across the accessor, so the idiom arrives
        half in slots and half in registers and the two halves do not look like
        one object. Following the copy chain puts them back together. Only plain
        copies are followed -- an arithmetic definition is a different value.
        """
        if _depth > self.MAX_REMOTE_CHASE_DEPTH or self._srda_model is None:
            return None
        defloc = self._srda_model.all_vvar_definitions.get(varid)
        if defloc is None or defloc.is_extern:
            return None
        block = self._block_at((defloc.addr, defloc.block_idx))
        if block is None or defloc.stmt_idx >= len(block.statements):
            return None
        stmt = block.statements[defloc.stmt_idx]
        if not isinstance(stmt, Assignment):
            return None
        if is_phi_assignment(stmt):
            # every incoming value must be the same slot -- which is exactly what
            # a field kept in a register across a branch looks like
            resolved: VirtualVariable | None = None
            for _, src_vvar in stmt.src.src_and_vvars:
                if src_vvar is None:
                    return None
                slot = (
                    src_vvar
                    if src_vvar.category == VirtualVariableCategory.STACK
                    else self._resolve_stack_slot(src_vvar.varid, _depth + 1)
                )
                if slot is None:
                    return None
                if resolved is None:
                    resolved = slot
                elif resolved.stack_offset != slot.stack_offset:
                    return None
            return resolved
        if not isinstance(stmt.src, VirtualVariable):
            return None
        src = stmt.src
        if src.category == VirtualVariableCategory.STACK:
            return src
        return self._resolve_stack_slot(src.varid, _depth + 1)

    def _resolve_call_target(self, call: Call) -> frozenset[str]:
        """Every name the callee of ``call`` is known by.

        Both spellings are returned because both are useful: the mangled symbol
        is exact, and the demangled one is what a reader recognizes. A pattern
        naming either matches. An indirect call resolves to nothing.
        """
        target = call.target
        if isinstance(target, str):
            return frozenset((target,))
        if not isinstance(target, Const) or not isinstance(target.value, int):
            return frozenset()
        addr = target.value
        cached = self._call_names_cache.get(addr)
        if cached is not None:
            return cached
        names: set[str] = set()
        func = self.kb.functions.get_by_addr(addr) if self.kb.functions.contains_addr(addr) else None
        if func is not None:
            if func.name:
                names.add(func.name)
            demangled = func.demangled_name
            if demangled:
                names.add(demangled)
        out = frozenset(names)
        self._call_names_cache[addr] = out
        return out

    def _resolve_call_def(self, varid: int, _depth: int = 0, _seen: frozenset[int] | None = None) -> Call | None:
        """The Call that defines ``varid``, through copies and agreeing phis.

        Read-only, and deliberately separate from :meth:`_resolve_remote_def`:
        that one answers "what can I recompute here", and refuses calls for
        exactly the right reason -- re-evaluating a call is not the same as
        reading its result. This one answers "what produced this value", which a
        call can perfectly well have done. Nothing is consumed or moved.
        """
        if _depth == 0:
            cached = self._call_def_cache.get(varid, False)
            if cached is not False:
                return cached
            out = self._resolve_call_def(varid, 1, frozenset((varid,)))
            self._call_def_cache[varid] = out
            return out
        if _depth > self.MAX_REMOTE_CHASE_DEPTH or self._srda_model is None:
            return None
        defloc = self._srda_model.all_vvar_definitions.get(varid)
        if defloc is None or defloc.is_extern:
            return None
        block = self._block_at((defloc.addr, defloc.block_idx))
        if block is None or defloc.stmt_idx >= len(block.statements):
            return None
        def_stmt = block.statements[defloc.stmt_idx]
        if not isinstance(def_stmt, Assignment):
            return None
        seen = _seen if _seen is not None else frozenset()
        if is_phi_assignment(def_stmt):
            resolved: Call | None = None
            for _, src_vvar in def_stmt.src.src_and_vvars:
                if src_vvar is None or src_vvar.varid in seen:
                    return None
                src_call = self._resolve_call_def(src_vvar.varid, _depth + 1, seen | {src_vvar.varid})
                if src_call is None:
                    return None
                if resolved is None:
                    resolved = src_call
                elif not resolved.likes(src_call):
                    return None
            return resolved
        src = def_stmt.src
        if isinstance(src, Convert):
            src = src.operand
        if isinstance(src, Call):
            return src
        if isinstance(src, VirtualVariable):
            if src.varid in seen:
                return None
            return self._resolve_call_def(src.varid, _depth + 1, seen | {src.varid})
        return None

    def _resolve_remote_def(self, varid: int, _depth: int = 0, _seen: frozenset[int] | None = None):
        """The pure expression a vvar defined *elsewhere* can be recomputed from.

        The same-block chase (:meth:`_make_chase_fn`) can only see a definition
        it is allowed to move or copy within the anchor block. Optimized code
        routinely computes an idiom's intermediate value once and feeds it to
        several blocks -- the CSE'd ``mode & S_IFMT`` of an ``S_IS*`` if-chain is
        the canonical case -- and then no block contains the whole idiom.

        Such a definition cannot be moved (its other users need it) and cannot be
        copied statement-wise (it is not in this block), but it *can* be
        recomputed at the use, provided the computation is pure: SSA guarantees a
        definition dominates its uses, hence so do the definitions of its
        operands, so re-evaluating the right-hand side at the use yields the same
        value. "Pure" here means register arithmetic only -- no load, no call, no
        dirty helper -- so that no intervening store can change the result.

        A phi is resolved by resolving every incoming value and requiring them to
        agree structurally: that is exactly the shape a CSE'd value takes when the
        compiler duplicated the computation into two arms of a diamond.
        """
        if _depth == 0:
            cached = self._remote_def_cache.get(varid, False)
            if cached is not False:
                return cached
            out = self._resolve_remote_def(varid, 1, frozenset((varid,)))
            self._remote_def_cache[varid] = out
            return out
        if _depth > self.MAX_REMOTE_CHASE_DEPTH or self._srda_model is None:
            return None

        defloc = self._srda_model.all_vvar_definitions.get(varid)
        if defloc is None or defloc.is_extern:
            return None
        block = self._block_at((defloc.addr, defloc.block_idx))
        if block is None or defloc.stmt_idx >= len(block.statements):
            return None
        def_stmt = block.statements[defloc.stmt_idx]
        if not isinstance(def_stmt, Assignment):
            return None

        if is_phi_assignment(def_stmt):
            resolved: Expression | None = None
            seen = _seen if _seen is not None else frozenset()
            for _, src_vvar in def_stmt.src.src_and_vvars:
                if src_vvar is None or src_vvar.varid in seen:
                    return None
                src_expr = self._resolve_remote_def(src_vvar.varid, _depth + 1, seen | {src_vvar.varid})
                if src_expr is None or src_expr.bits != def_stmt.dst.bits:
                    return None
                if resolved is None:
                    resolved = src_expr
                elif not resolved.likes(src_expr):
                    return None
            return resolved

        src = def_stmt.src
        if isinstance(src, VirtualVariable):
            # a copy: follow it, so a value renamed on the way to the use is still
            # recognized. Bare vvars are never returned, which keeps the chase in
            # dsl._prepare from re-entering on the same shape.
            if src.varid in (_seen or frozenset()):
                return None
            return self._resolve_remote_def(src.varid, _depth + 1, (_seen or frozenset()) | {src.varid})
        if not self._is_recomputable(src):
            return None
        return src

    _PURE_EXPR_TYPES = _PURE_EXPR_TYPES_FWD

    @classmethod
    def _is_recomputable(cls, expr: Expression) -> bool:
        """True when ``expr`` reads no memory and calls nothing, so evaluating it
        at any point its operands are live gives the same value."""
        for sub in _iter_subexprs(expr):
            if isinstance(sub, (VirtualVariable, Const, StackBaseOffset)):
                continue
            if not isinstance(sub, cls._PURE_EXPR_TYPES):
                return False
        return True

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

        # A stack container is *named in place*, not outlined. Its region's inputs
        # are N independent stack slots rather than one pointer, so there is
        # nothing for a synthesized callee to take -- and nothing needs to be:
        # the object's address is a StackBaseOffset the pattern already bound, so
        # replacing the matched expression by `call(&obj)` is the whole
        # transformation. See PStackField.
        if any(isinstance(match.captures.get(p.capture), StackBaseOffset) for p in match.pattern.params):
            return self._rewrite_in_place(match, g, block)
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
        duplicated = sorted(match.duplicated_stmt_idxs)
        if any(i >= anchor_idx for i in duplicated):
            raise UnsupportedOutlineError("duplicated definitions must precede the anchor statement")

        # moving consumed statements down to the matched span must not cross
        # side-effecting statements
        if consumed:
            for i in range(consumed[0], anchor_idx):
                if i not in match.consumed_stmt_idxs and _stmt_has_side_effects(stmts[i]):
                    raise UnsupportedOutlineError(
                        "side-effecting statements interleave with the matched statement span"
                    )
        # a duplicated definition is re-executed at the anchor's position, so it
        # must be pure and nothing in between may write memory or call
        if duplicated:
            for i in range(duplicated[0], anchor_idx):
                if _stmt_has_side_effects(stmts[i]):
                    raise UnsupportedOutlineError(
                        "side-effecting statements interleave with the duplicated definitions"
                    )

        ins_addr = anchor.tags.get("ins_addr")

        # copies of the chased definitions, on fresh vvar ids so the SSA form
        # holds; ``subst`` maps each original vvar id onto its copy's
        # destination, and is applied to the copies themselves (a later
        # definition may use an earlier one) and to everything else that moves
        # into the region and reads them
        recomputed_stmts, subst = self._recompute_defs(match.recomputed_defs, ins_addr)
        dup_stmts, dup_subst = self._duplicate_defs(stmts, duplicated, subst)
        dup_stmts = recomputed_stmts + dup_stmts
        subst = subst + dup_subst
        moved_stmts = [stmts[i] for i in consumed]
        for old_varid, new_vvar in subst:
            moved_stmts = [self._substitute_vvar(s, old_varid, new_vvar) for s in moved_stmts]

        # a container reached as a field of another object: compute its address
        # into a variable ahead of the region, and rebase the region onto it
        base_stmts, rebases, base_caps = self._materialize_bases(match, ins_addr)
        lift_stmts, lifts, lift_caps = self._materialize_exprs(match, ins_addr)
        base_stmts = base_stmts + lift_stmts
        if base_caps or lift_caps:
            match = dataclass_replace(match, captures={**match.captures, **base_caps, **lift_caps})
            moved_stmts = self._apply_exprs(self._apply_bases(moved_stmts, rebases, match.base_aliases), lifts)
            dup_stmts = self._apply_exprs(self._apply_bases(dup_stmts, rebases, match.base_aliases), lifts)

        # determine the result vvar; lift the matched sub-expression into its
        # own assignment unless the anchor already is one
        anchor_absorbed = (
            isinstance(anchor, Assignment)
            and match.expr_path == (("src", None),)
            and isinstance(anchor.dst, VirtualVariable)
        )
        if anchor_absorbed:
            result_vvar = anchor.dst
            region_anchor = anchor
            for old_varid, new_vvar in subst:
                region_anchor = self._substitute_vvar(region_anchor, old_varid, new_vvar)
            (region_anchor,) = self._apply_exprs(self._apply_bases([region_anchor], rebases, match.base_aliases), lifts)
            mid_stmts = dup_stmts + moved_stmts + [region_anchor]
            post_head: list[Statement] = []
        else:
            vvar_id = self._next_vvar_id()
            result_vvar = VirtualVariable(
                self._next_idx(),
                vvar_id,
                match.matched_expr.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                ins_addr=ins_addr,
            )
            region_expr = match.matched_expr.copy()
            for old_varid, new_vvar in subst:
                region_expr = self._substitute_vvar(region_expr, old_varid, new_vvar)
            (region_expr,) = self._apply_exprs(self._apply_bases([region_expr], rebases, match.base_aliases), lifts)
            lifted = Assignment(self._next_idx(), result_vvar, region_expr, ins_addr=ins_addr)
            replaced, new_anchor = anchor.replace(match.matched_expr, result_vvar.copy())
            if not replaced:
                raise UnsupportedOutlineError("failed to replace the matched expression in the anchor statement")
            mid_stmts = dup_stmts + moved_stmts + [lifted]
            post_head = [new_anchor]

        pre_stmts = [s for i, s in enumerate(stmts[:anchor_idx]) if i not in match.consumed_stmt_idxs] + base_stmts
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

    def _recompute_defs(
        self, recomputed: tuple[tuple[int, Expression], ...], ins_addr: int | None
    ) -> tuple[list[Statement], list[tuple[int, VirtualVariable]]]:
        """Build the assignments that re-derive definitions living outside the
        anchor block, for placement at the head of the outlined region.

        The expressions are pure (:meth:`_is_recomputable`), so re-evaluating
        them here is value-preserving; the originals are left untouched for their
        other users. They are emitted innermost-first: the chase records a
        definition before descending into it, so a later entry may appear inside
        an earlier one's expression but never the other way round."""
        stmts: list[Statement] = []
        subst: list[tuple[int, VirtualVariable]] = []
        for varid, src_expr in reversed(recomputed):
            if not self._is_recomputable(src_expr):
                raise UnsupportedOutlineError("stale match: the recomputed definition is no longer pure")
            src = src_expr.copy()
            for old_varid, new_vvar in subst:
                src = self._substitute_vvar(src, old_varid, new_vvar)
            vvar_id = self._next_vvar_id()
            new_dst = VirtualVariable(
                self._next_idx(),
                vvar_id,
                src.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                ins_addr=ins_addr,
            )
            stmts.append(Assignment(self._next_idx(), new_dst, src, ins_addr=ins_addr))
            subst.append((varid, new_dst))
        return stmts, subst

    def _duplicate_defs(
        self,
        stmts: list[Statement],
        duplicated: list[int],
        prior_subst: list[tuple[int, VirtualVariable]] | None = None,
    ) -> tuple[list[Statement], list[tuple[int, VirtualVariable]]]:
        """Copy the chased definitions at ``duplicated`` (ascending) for
        placement at the head of the outlined region. Each copy defines a fresh
        vvar -- reusing the original ids would give the same value two
        definitions and break SSA -- and uses the copies of the definitions
        before it. Returns the copies and the (original varid, copy's
        destination) substitutions to apply to the region's anchor."""
        dup_stmts: list[Statement] = []
        subst: list[tuple[int, VirtualVariable]] = list(prior_subst or [])
        n_prior = len(subst)
        for i in duplicated:
            stmt = stmts[i]
            if not isinstance(stmt, Assignment) or not isinstance(stmt.dst, VirtualVariable):
                raise UnsupportedOutlineError("only virtual-variable assignments can be duplicated into the region")
            src = stmt.src.copy()
            for old_varid, new_vvar in subst:
                src = self._substitute_vvar(src, old_varid, new_vvar)
            vvar_id = self._next_vvar_id()
            new_dst = VirtualVariable(
                self._next_idx(),
                vvar_id,
                stmt.dst.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                **stmt.dst.tags,
            )
            dup_stmts.append(Assignment(self._next_idx(), new_dst, src, **stmt.tags))
            subst.append((stmt.dst.varid, new_dst))
        return dup_stmts, subst[n_prior:]

    # --- memory disjointness ------------------------------------------------
    #
    # Gap statements are hoisted above the region, so a gap that touches memory
    # used to be rejected outright. That veto is what made std::swap unmatchable
    # on real code: an instruction scheduler always interleaves the next field's
    # load between this field's store and its writeback, and those two accesses
    # are trivially disjoint --
    #
    #     t   = *a          <- matched
    #     *a  = *b          <- matched
    #     t2  = *(b + 8)    <- the gap: a different field
    #     *b  = t           <- matched
    #
    # so require *disjointness*, not absence. Only the analyzable shape counts:
    # an address that is a variable plus a constant, against another address on
    # the same variable. Anything else is still refused.

    @staticmethod
    def _mem_interval(addr: Expression, size: int) -> tuple[int, int, int] | None:
        """``(base varid, lo, hi)`` for a ``vvar`` / ``vvar + const`` address."""
        if isinstance(addr, VirtualVariable):
            return (addr.varid, 0, size)
        if isinstance(addr, BinaryOp) and addr.op in ("Add", "Sub") and len(addr.operands) == 2:
            base, off = addr.operands
            if isinstance(base, VirtualVariable) and isinstance(off, Const) and isinstance(off.value, int):
                delta = off.value if addr.op == "Add" else -off.value
                return (base.varid, delta, delta + size)
        return None

    @classmethod
    def _mem_accesses(cls, stmt: Statement) -> tuple[list, list] | None:
        """``(reads, writes)`` as intervals, or None when any access is not of
        the analyzable shape (in which case nothing may be reordered around it)."""
        reads: list[tuple[int, int, int]] = []
        writes: list[tuple[int, int, int]] = []
        if isinstance(stmt, Store):
            iv = cls._mem_interval(stmt.addr, stmt.size)
            if iv is None:
                return None
            writes.append(iv)
        elif _stmt_has_side_effects(stmt):
            return None  # a call, a dirty statement: unanalyzable by construction
        for sub in _iter_subexprs(stmt):
            if isinstance(sub, Load):
                iv = cls._mem_interval(sub.addr, sub.size)
                if iv is None:
                    return None
                reads.append(iv)
        return reads, writes

    @staticmethod
    def _overlaps(x: tuple[int, int, int], y: tuple[int, int, int]) -> bool:
        """Whether two accesses can alias.

        Same base variable: exact, from the byte intervals.

        Different base variables: SSA says nothing about what two pointers hold,
        so the intervals are compared *as if the bases were equal*. Two accesses
        at disjoint offsets are then treated as disjoint. This is the ordinary
        field-disjointness assumption -- `x->a` and `y->b` do not overlap, since
        either x and y are different objects or they are the same object and the
        two fields still are. It is wrong only for pointers that alias at a
        *shift* (``x == (char *)y + 4``), which no idiom this library describes
        can be built out of; if that ever happens, a hoisted read would see a
        value written by the region instead of the one that was there before it.
        """
        return x[1] < y[2] and y[1] < x[2]

    @classmethod
    def _commutes_with_region(cls, gap: Statement, region_mem: list) -> bool:
        """Whether ``gap`` may be hoisted across every statement of the region.

        Two memory operations commute unless they can alias and at least one of
        them writes."""
        gap_mem = cls._mem_accesses(gap)
        if gap_mem is None:
            return False
        gap_reads, gap_writes = gap_mem
        for other in region_mem:
            if other is None:
                return False
            reads, writes = other
            for w in gap_writes:
                if any(cls._overlaps(w, iv) for iv in reads + writes):
                    return False
            for r in gap_reads:
                if any(cls._overlaps(r, iv) for iv in writes):
                    return False
        return True

    def _materialize_bases(
        self, match: KnownPatternMatch, ins_addr: int | None
    ) -> tuple[list[Statement], list[tuple[int, int, VirtualVariable]], dict[str, VirtualVariable]]:
        """Give every parameter capture bound to ``root + K`` a variable of its own.

        A :class:`~.dsl.PField` binds a container that is a *field of something
        else* to the address expression ``root + K``, which cannot be a call
        argument: the Outliner derives the callee's parameters from the region's
        live-ins, and those are always virtual variables. So the object pointer
        is computed once *ahead* of the region -- ``tmp = root + K`` -- and the
        region's field addresses are re-expressed against ``tmp``, which makes
        ``tmp`` the single live-in and gives the synthesized call a variable to
        pass. It also puts the object's type where it belongs: ``tmp`` is the
        ``std::vector<T> *``, not the enclosing object's pointer.

        Returns the assignments to place before the region, the rewrite triples
        ``(root varid, K, tmp)``, and the captures to override.
        """
        pre: list[Statement] = []
        rewrites: list[tuple[int, int, VirtualVariable]] = []
        new_caps: dict[str, VirtualVariable] = {}
        for param in match.pattern.params:
            captured = match.captures.get(param.capture)
            if captured is None or isinstance(captured, VirtualVariable):
                continue
            if not (
                isinstance(captured, BinaryOp)
                and captured.op == "Add"
                and len(captured.operands) == 2
                and isinstance(captured.operands[0], VirtualVariable)
                and isinstance(captured.operands[1], Const)
                and isinstance(captured.operands[1].value, int)
            ):
                # not an offset base; _rewrite_callsite will reject it
                continue
            root, off = captured.operands
            vvar_id = self._next_vvar_id()
            tmp = VirtualVariable(
                self._next_idx(),
                vvar_id,
                root.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                ins_addr=ins_addr,
            )
            src = BinaryOp(
                self._next_idx(),
                "Add",
                [root.copy(), Const(self._next_idx(), off.value, off.bits)],
                False,
                ins_addr=ins_addr,
            )
            pre.append(Assignment(self._next_idx(), tmp, src, ins_addr=ins_addr))
            rewrites.append((root.varid, off.value, tmp))
            new_caps[param.capture] = tmp
        return pre, rewrites, new_caps

    # expression kinds a parameter may be lifted out of the region as
    _LIFTABLE_EXPR_TYPES = (*_PURE_EXPR_TYPES_FWD, Load)
    #: Node budget for a lifted parameter expression -- see _is_liftable.
    MAX_LIFTED_EXPR_NODES = 8

    @classmethod
    def _is_liftable(cls, expr: Expression) -> bool:
        """True when ``expr`` may be evaluated into a temporary immediately before
        the region: no calls, no side effects. A ``Load`` qualifies -- lifting it
        does not *move* it, since the temporary lands directly in front of the
        statement the matched expression came out of, with nothing in between.

        Bounded in size, and that bound is doing real work. Rewriting the region
        to use the temporary has to *find* the occurrences, which means comparing
        the captured expression against every sub-expression of the statement with
        ``.likes()`` -- the product of two sizes, on statements that in a large
        optimized function are enormous. The captures this exists for are a field
        read or a variable behind a Convert; a whole computed sub-tree is neither
        cheap to find nor readable as an argument.
        """
        n = 0
        for sub in _iter_subexprs(expr):
            n += 1
            if n > cls.MAX_LIFTED_EXPR_NODES:
                return False
            if isinstance(sub, (VirtualVariable, Const, StackBaseOffset)):
                continue
            if not isinstance(sub, cls._LIFTABLE_EXPR_TYPES):
                return False
        return True

    def _materialize_exprs(
        self, match: KnownPatternMatch, ins_addr: int | None
    ) -> tuple[list[Statement], list[tuple[Expression, VirtualVariable]], dict[str, VirtualVariable]]:
        """Lift parameter captures that are expressions, not variables.

        The Outliner derives the callee's parameters from the region's live-ins,
        so a capture that is not already a virtual variable cannot become a call
        argument -- and the patterns compensated by *only matching* variables.
        That is why ``S_ISDIR(inode->i_mode)`` was invisible while
        ``S_ISDIR(st.st_mode)`` was not: the same macro, but one argument is a
        Load and the other is a stack vvar.

        Evaluating the capture into a temporary in front of the region fixes it
        without moving anything: the temporary is emitted at the end of the
        pre-region statements, which is exactly where the matched expression was
        going to be evaluated anyway.

        Expression-level matches only. A statement-sequence or graph match hoists
        gap statements around the region, so "nothing in between" no longer holds.
        """
        pre: list[Statement] = []
        subs: list[tuple[Expression, VirtualVariable]] = []
        new_caps: dict[str, VirtualVariable] = {}
        for param in match.pattern.params:
            captured = match.captures.get(param.capture)
            if captured is None or isinstance(captured, VirtualVariable):
                continue
            if isinstance(captured, BinaryOp) and captured.op == "Add" and isinstance(captured.operands[1], Const):
                continue  # an object base; _materialize_bases owns it
            if not self._is_liftable(captured):
                continue
            vvar_id = self._next_vvar_id()
            tmp = VirtualVariable(
                self._next_idx(),
                vvar_id,
                captured.bits,
                VirtualVariableCategory.TMP,
                oident=vvar_id,  # TMP-category vvars must carry a tmp idx
                ins_addr=ins_addr,
            )
            pre.append(Assignment(self._next_idx(), tmp, captured.copy(), ins_addr=ins_addr))
            subs.append((captured, tmp))
            new_caps[param.capture] = tmp
        return pre, subs, new_caps

    def _substitute_expr(self, obj, old_expr: Expression, tmp: VirtualVariable):
        """Replace every ``.likes()``-equal occurrence of ``old_expr`` in ``obj``."""

        def occurrences(o):
            return [e for e in _iter_subexprs(o) if e is not o and old_expr.likes(e)]

        remaining = len(occurrences(obj))
        while remaining:
            occ = occurrences(obj)[0]
            repl = VirtualVariable(self._next_idx(), tmp.varid, tmp.bits, tmp.category, oident=tmp.oident, **tmp.tags)
            replaced, obj = obj.replace(occ, repl)
            left = len(occurrences(obj))
            if not replaced or left >= remaining:
                raise UnsupportedOutlineError("failed to lift a parameter expression out of the region")
            remaining = left
        return obj

    def _apply_exprs(self, objs: list, subs: list[tuple[Expression, VirtualVariable]]) -> list:
        for old_expr, tmp in subs:
            objs = [self._map_uses(o, lambda x, e=old_expr, t=tmp: self._substitute_expr(x, e, t)) for o in objs]
        return objs

    @staticmethod
    def _map_uses(obj, fn):
        """Apply ``fn`` to the *use* positions of ``obj``.

        An assignment's destination is a definition, not a use: rewriting it
        would turn `x = p + 16` into `p + 16 = p + 16`, which is not an
        assignment to anything and asserts inside variable recovery. Filtering
        the destination out of the walk by identity does not work -- the AIL
        objects are Rust-backed, so attribute access hands back a fresh Python
        wrapper each time and `is` never matches -- hence rebuilding the
        statement around a rewritten source instead."""
        if isinstance(obj, Assignment):
            new_src = fn(obj.src)
            return Assignment(obj.idx, obj.dst, new_src, **obj.tags)
        return fn(obj)

    @staticmethod
    def _rebase_occurrences(obj, root_varid: int, obj_off: int) -> list[BinaryOp]:
        out = []
        for e in _iter_subexprs(obj):
            if not (isinstance(e, BinaryOp) and e.op == "Add" and len(e.operands) == 2):
                continue
            for var, const in (e.operands, e.operands[::-1]):
                if (
                    isinstance(var, VirtualVariable)
                    and var.varid == root_varid
                    and isinstance(const, Const)
                    and isinstance(const.value, int)
                    and const.value >= obj_off
                ):
                    out.append(e)
                    break
        return out

    def _rebase(self, obj, root_varid: int, obj_off: int, tmp: VirtualVariable, aliases=()):
        """Re-express ``root + C`` inside ``obj`` as ``tmp + (C - obj_off)``.

        Occurrences of ``root`` that are *not* a field of this object are left
        alone; they keep ``root`` live into the region, which the callee-interface
        check then rejects -- the safe outcome, since the pattern would otherwise
        name an object it did not actually identify.

        ``aliases`` are variables the matcher established to hold ``root + C``
        themselves; a reference to one is a reference to that address, so it is
        rewritten the same way. That is what a `lea` into a register of its own
        looks like, and leaving it alone would keep it live into the region."""
        for varid, alias_root, disp in aliases:
            if alias_root != root_varid or disp < obj_off:
                continue
            obj = self._map_uses(obj, lambda o, v=varid, d=disp - obj_off: self._substitute_alias(o, v, d, tmp))
        return self._map_uses(obj, lambda o: self._rebase_inner(o, root_varid, obj_off, tmp))

    def _rebase_inner(self, obj, root_varid: int, obj_off: int, tmp: VirtualVariable):
        remaining = len(self._rebase_occurrences(obj, root_varid, obj_off))
        while remaining:
            occ = self._rebase_occurrences(obj, root_varid, obj_off)[0]
            const = next(o for o in occ.operands if isinstance(o, Const))
            delta = const.value - obj_off
            new_tmp = VirtualVariable(
                self._next_idx(), tmp.varid, tmp.bits, tmp.category, oident=tmp.oident, **tmp.tags
            )
            if delta == 0:
                repl: Expression = new_tmp
            else:
                repl = BinaryOp(
                    self._next_idx(), "Add", [new_tmp, Const(self._next_idx(), delta, const.bits)], False, **occ.tags
                )
            replaced, obj = obj.replace(occ, repl)
            left = len(self._rebase_occurrences(obj, root_varid, obj_off))
            if not replaced or left >= remaining:
                raise UnsupportedOutlineError("failed to re-express a field address against the materialized base")
            remaining = left
        return obj

    def _substitute_alias(self, obj, varid: int, delta: int, tmp: VirtualVariable):
        """Replace a variable that holds the object's address by ``tmp + delta``."""

        def occurrences(o):
            return [e for e in _iter_subexprs(o) if isinstance(e, VirtualVariable) and e.varid == varid]

        remaining = len(occurrences(obj))
        while remaining:
            occ = occurrences(obj)[0]
            new_tmp = VirtualVariable(
                self._next_idx(), tmp.varid, tmp.bits, tmp.category, oident=tmp.oident, **tmp.tags
            )
            repl: Expression = (
                new_tmp
                if delta == 0
                else BinaryOp(
                    self._next_idx(), "Add", [new_tmp, Const(self._next_idx(), delta, tmp.bits)], False, **occ.tags
                )
            )
            replaced, obj = obj.replace(occ, repl)
            left = len(occurrences(obj))
            if not replaced or left >= remaining:
                raise UnsupportedOutlineError("failed to re-express an aliased object address")
            remaining = left
        return obj

    def _apply_bases(self, objs: list, rewrites: list[tuple[int, int, VirtualVariable]], aliases=()) -> list:
        for root_varid, obj_off, tmp in rewrites:
            objs = [self._rebase(o, root_varid, obj_off, tmp, aliases) for o in objs]
        return objs

    def _substitute_vvar(self, obj, old_varid: int, new_vvar: VirtualVariable):
        """Replace every occurrence of the vvar ``old_varid`` in ``obj`` (a
        statement or an expression) with a copy of ``new_vvar``."""
        # ``replace`` matches on __eq__, which is idx-aware, so the occurrence
        # itself has to be handed in; distinct occurrences of one vvar may carry
        # distinct indices, hence the loop (each round removes at least the one
        # occurrence it found).
        remaining = sum(1 for e in _iter_subexprs(obj) if isinstance(e, VirtualVariable) and e.varid == old_varid)
        while remaining:
            occurrence = next(e for e in _iter_subexprs(obj) if isinstance(e, VirtualVariable) and e.varid == old_varid)
            replacement = VirtualVariable(
                self._next_idx(),
                new_vvar.varid,
                new_vvar.bits,
                new_vvar.category,
                oident=new_vvar.oident,
                **new_vvar.tags,
            )
            replaced, obj = obj.replace(occurrence, replacement)
            left = sum(1 for e in _iter_subexprs(obj) if isinstance(e, VirtualVariable) and e.varid == old_varid)
            if not replaced or left >= remaining:
                raise UnsupportedOutlineError(f"failed to substitute vvar {old_varid} in the outlined region")
            remaining = left
        return obj

    def _rewrite_in_place(self, match: KnownPatternMatch, g: networkx.DiGraph, block: Block) -> OutlineResult:
        """Replace the matched expression by the pattern's call, with no callee.

        Outlining exists to discover a region's interface; when every argument is
        already an expression in hand -- a stack object's address -- there is no
        interface to discover, and building a callee whose body re-reads slots
        through a pointer would be a semantic rewrite rather than a renaming.
        The peephole optimizations synthesize calls exactly this way.
        """
        if match.matched_expr is None:
            raise UnsupportedOutlineError("in-place rewriting needs an expression match")
        stmts = list(block.statements)
        if match.anchor_stmt_idx >= len(stmts):
            raise UnsupportedOutlineError("stale match: the anchor statement is gone from the block")
        anchor = stmts[match.anchor_stmt_idx]

        args: list[Expression] = []
        for param in match.pattern.params:
            captured = match.captures.get(param.capture)
            if captured is None:
                raise UnsupportedOutlineError(f"pattern {match.pattern.name}: capture {param.capture!r} is unbound")
            args.append(captured.copy())
        for name in match.pattern.extra_args:
            captured = match.captures.get(name)
            if captured is None:
                raise UnsupportedOutlineError(f"pattern {match.pattern.name}: extra arg capture {name!r} is unbound")
            args.append(captured.copy())

        call = Call(
            self._next_idx(),
            match.pattern.call_name,
            args=args,
            bits=match.matched_expr.bits,
            ins_addr=anchor.tags.get("ins_addr"),
            known_pattern=match.pattern.name,
            is_prototype_guessed=False,
        )
        replaced, new_anchor = anchor.replace(match.matched_expr, call)
        if not replaced:
            raise UnsupportedOutlineError("failed to replace the matched expression in the anchor statement")
        stmts[match.anchor_stmt_idx] = new_anchor
        new_block = block.copy()
        new_block.statements = stmts
        networkx.relabel_nodes(g, {block: new_block}, copy=False)
        return OutlineResult(
            graph=g, match=match, call_stmt=new_anchor, child_func=None, child_graph=None, child_funcargs=[]
        )

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
        region_mem = [self._mem_accesses(stmts[i]) for i in matched_set]
        for i in gap_idxs:
            if (
                region_has_side_effects
                and _stmt_touches_memory(stmts[i])
                and not self._commutes_with_region(stmts[i], region_mem)
            ):
                raise UnsupportedOutlineError("memory-touching statements interleave with the matched span")
            if _stmt_uses(stmts[i]) & matched_defs:
                raise UnsupportedOutlineError("interleaved statements use values defined by the matched span")

        ins_addr = stmts[span[0]].tags.get("ins_addr")
        base_stmts, rebases, base_caps = self._materialize_bases(match, ins_addr)
        if base_caps:
            match = dataclass_replace(match, captures={**match.captures, **base_caps})

        pre_stmts = (
            [s for i, s in enumerate(stmts[: span[0]]) if i not in match.consumed_stmt_idxs]
            + [stmts[i] for i in gap_idxs]
            + base_stmts
        )
        mid_stmts = self._apply_bases(
            [stmts[i] for i in consumed] + [stmts[i] for i in span], rebases, match.base_aliases
        )
        post_stmts = stmts[span[-1] + 1 :]
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

        ins_addr = entry_block.statements[min(entry_consumed)].tags.get("ins_addr") if entry_consumed else None

        # a container reached as a field of another object (a std::string member,
        # say): its address is computed into a variable ahead of the region and
        # every block of the region is rebased onto it
        base_stmts, rebases, base_caps = self._materialize_bases(match, ins_addr)
        if base_caps:
            match = dataclass_replace(match, captures={**match.captures, **base_caps})
            for loc in match.block_map.values():
                blk = nodes_dict.get(loc)
                if blk is None:
                    raise UnsupportedOutlineError("stale match: a matched block is gone from the graph")
                blk.statements[:] = self._apply_bases(list(blk.statements), rebases, match.base_aliases)

        src_loc = entry_loc
        if entry_residue or base_stmts:
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
            pre_stmts = [entry_block.statements[i] for i in entry_residue] + base_stmts
            mid_stmts = [s for i, s in enumerate(entry_block.statements) if i not in entry_residue]
            _, b_mid, _ = split_ail_block(g, entry_block, pre_stmts, mid_stmts, [], self._next_block_addr)
            src_loc = (b_mid.addr, b_mid.idx)

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

        # The Outliner's synthesized call is as wide as the return register, but
        # the destination it is assigned to is the vvar lifted from the matched
        # expression, at that expression's own width. Emitting a 64-bit call into
        # a 32-bit vvar produces a width-mismatched Assignment that later blows up
        # in variable recovery ("args' length must all be equal"), so narrow the
        # call to its destination. Sub-byte destinations (1-bit boolean results)
        # keep the register width: narrowing to 1 bit instead breaks the implicit-
        # typecast collapsing in codegen.
        call_bits = old_call.bits
        if not void_call and old_stmt.dst is not None and old_stmt.dst.bits >= 8:
            call_bits = old_stmt.dst.bits

        new_call = Call(
            self._ail_manager.next_atom() if self._ail_manager is not None else None,
            pattern.call_name,
            args=args,
            bits=call_bits,
            ins_addr=ins_addr if ins_addr is not None else old_call.tags.get("ins_addr"),
            known_pattern=pattern.name,
            is_prototype_guessed=False,
        )
        new_stmt: Statement
        if void_call:
            # the Outliner's synthesized destination is a dead return-register
            # vvar; drop it so the call renders as a bare statement
            new_stmt = SideEffectStatement(self._next_idx(), new_call, ret_expr=None, fp_ret_expr=None, **old_stmt.tags)
        else:
            new_stmt = Assignment(self._next_idx(), old_stmt.dst, new_call, **old_stmt.tags)
        call_block.statements[call_stmt_idx] = new_stmt
        return new_stmt

    def _next_idx(self) -> int | None:
        """A fresh AIL atom index. Objects built with ``idx=None`` all end up at
        index 0, and the decompiler's VariableMap is keyed by index -- so two
        outlined results would collide there and render as the same C variable
        even though variable recovery kept them distinct."""
        return self._ail_manager.next_atom() if self._ail_manager is not None else None

    def _next_vvar_id(self) -> int:
        vvar_id = self.vvar_id_start
        self.vvar_id_start += 1
        return vvar_id

    def _next_block_addr(self) -> int:
        block_addr = self.block_addr_start
        self.block_addr_start += 1
        return block_addr


AnalysesHub.register_default("KnownPatternFinder", KnownPatternFinder)
