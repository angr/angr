"""``FuzzyPatternFinder``: discover fuzzy repeated code in a decompiled function."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from angr.analyses.analysis import AnalysesHub, Analysis

from .align import AlignParams, Interval, PatternCluster, discover, select_disjoint
from .exact import ExactCore, find_exact_cores
from .priority import Checkpoint
from .region import Region, snap
from .tokenizer import TokenStream, is_glue_shape, tokenize

if TYPE_CHECKING:
    from collections.abc import Callable

    import networkx

    from angr.ailment import Block
    from angr.knowledge_plugins.functions import Function

_l = logging.getLogger(__name__)

Address = tuple[int, "int | None"]


@dataclass
class PatternOccurrence:
    """One occurrence of a discovered pattern, with its outlining verdict."""

    interval: Interval
    region: Region

    @property
    def outlinable(self) -> bool:
        return self.region.outlinable

    @property
    def block_locs(self) -> list[Address]:
        return self.region.block_locs

    def __repr__(self):
        lo, hi = self.region.block_locs[0][0], self.region.block_locs[-1][0]
        return (
            f"<PatternOccurrence [{self.interval.start},{self.interval.end}) "
            f"{lo:#x}-{hi:#x} {'outlinable' if self.outlinable else self.region.reason}>"
        )


#: statements of an occurrence may come from anywhere in the function's block order
STATEMENTS_ANY = "any"
#: an occurrence continues only into a block that follows in the control flow
STATEMENTS_FOLLOW = "follow"
#: an occurrence is one straight run of code: consecutive lines of the pseudocode
STATEMENTS_CONSECUTIVE = "consecutive"
STATEMENTS_MODES = (STATEMENTS_ANY, STATEMENTS_FOLLOW, STATEMENTS_CONSECUTIVE)


@dataclass
class FuzzyPattern:
    """A family of near-duplicate regions, plus the sub-ranges they share exactly."""

    cluster: PatternCluster
    occurrences: list[PatternOccurrence]
    cores: list[ExactCore] = field(default_factory=list)
    core_occurrences: list[list[PatternOccurrence]] = field(default_factory=list)

    @property
    def identity(self) -> float:
        return self.cluster.identity

    @property
    def size(self) -> int:
        return self.cluster.size

    @property
    def savings(self) -> float:
        return self.cluster.savings

    @property
    def sound_savings(self) -> int:
        """Tokens removable without changing semantics, i.e. via the exact cores."""
        return sum(c.savings for c in self.cores)

    @property
    def outlinable_occurrences(self) -> list[PatternOccurrence]:
        return [o for o in self.occurrences if o.outlinable]

    def __repr__(self):
        return (
            f"<FuzzyPattern {len(self.occurrences)} occurrences, size {self.size}, "
            f"identity {self.identity:.0%}, {len(self.cores)} exact cores>"
        )


class FuzzyPatternFinder(Analysis):
    """Find fuzzy repeated code in an AIL graph.

    Duplicated inlined code (obfuscator-generated decryption stubs, expanded
    macros, copies of an inlined helper) is rarely byte-identical: constants
    differ per site and optimizers reorder and reassociate. Exact matching finds
    nothing, so this analysis linearizes the graph into a canonical token stream
    and runs a sparse local self-alignment over it (see :mod:`.align`).

    Two tiers of result are produced. ``patterns`` holds the fuzzy families,
    which is what you want to understand a function. Each family also carries
    ``cores``: the sub-ranges its members agree on *exactly*, which is what you
    can soundly merge into a single shared function.

    :param func:            The function being analyzed.
    :param ail_graph:       Its AIL graph, e.g. ``Decompiler.ail_graph``.
    :param params:          Alignment knobs; see :class:`.AlignParams`.
    :param disjoint:        Keep only a non-overlapping subset of families
                            (what outlining needs). ``all_patterns`` always has
                            the full list.
    :param min_core_len:    Shortest exact core worth reporting.
    :param resolve_calls:   Render call targets by callee name, which makes
                            calls strong anchors for the aligner.
    """

    def __init__(
        self,
        func: Function,
        ail_graph: networkx.DiGraph[Block],
        *,
        params: AlignParams | None = None,
        disjoint: bool = True,
        min_core_len: int = 4,
        min_core_support: int = 2,
        max_depth: int = 5,
        const_mode: str = "abstract",
        skip_labels: bool = True,
        skip_phis: bool = True,
        skip_dephi: bool = True,
        resolve_calls: bool = True,
        entry: Block | None = None,
        low_priority: bool = False,
        checkpoint: Callable[[], None] | None = None,
        statements: str = STATEMENTS_ANY,
    ):
        if statements not in STATEMENTS_MODES:
            raise ValueError(f"unknown statements mode {statements!r}; expected one of {STATEMENTS_MODES}")
        #: how the statements of one occurrence may follow each other; see STATEMENTS_MODES
        self.statements = statements
        self.func = func
        # low_priority: yield the GIL now and then from the alignment loops, as the CFG does;
        # checkpoint: called at the same cadence, and may raise to abort. A ready Checkpoint
        # is used as it is.
        self._checkpoint: Callable[[], None] | None
        if isinstance(checkpoint, Checkpoint):
            self._checkpoint = checkpoint
        elif low_priority or checkpoint is not None:
            self._checkpoint = Checkpoint(low_priority, checkpoint)
        else:
            self._checkpoint = None
        self.graph = ail_graph
        self.params = params or AlignParams()
        self.min_core_len = min_core_len
        self.min_core_support = min_core_support

        if entry is None:
            entry = next((b for b in ail_graph if b.addr == func.addr and b.idx is None), None)
            if entry is None:
                candidates = [b for b in ail_graph if ail_graph.in_degree[b] == 0]
                if not candidates:
                    raise ValueError("cannot determine the entry block of the given graph")
                entry = min(candidates, key=lambda b: (b.addr, -1 if b.idx is None else b.idx))
        self.entry = entry

        self.stream: TokenStream = tokenize(
            ail_graph,
            entry,
            kb=self.kb if resolve_calls else None,
            loader=self.project.loader if const_mode == "class" else None,
            max_depth=max_depth,
            const_mode=const_mode,
            skip_labels=skip_labels,
            skip_phis=skip_phis,
            skip_dephi=skip_dephi,
        )

        self.all_patterns: list[FuzzyPattern] = []
        self.patterns: list[FuzzyPattern] = []
        self._analyze(disjoint)

    def _analyze(self, disjoint: bool) -> None:
        stream = self.stream
        if len(stream) < self.params.k:
            return

        glue = frozenset(i for i, shape in enumerate(stream.shape_vocab) if is_glue_shape(shape))
        clusters = discover(
            stream.shape_ids, stream.klass_of_shape, self.params, self._checkpoint, self._segments(), glue
        )
        _l.debug("FuzzyPatternFinder: %d clusters over %d tokens", len(clusters), len(stream))

        entry_loc = (self.entry.addr, self.entry.idx)
        self.all_patterns = [self._build(c, entry_loc) for c in clusters]
        if disjoint:
            keep = {id(c) for c in select_disjoint(clusters, self.params.overlap_ratio)}
            self.patterns = [p for p in self.all_patterns if id(p.cluster) in keep]
        else:
            self.patterns = list(self.all_patterns)

    def _segments(self) -> list[int] | None:
        """A segment number per token, changing wherever an occurrence may not continue.

        The stream lists blocks in reverse post-order, which puts unrelated code next to
        each other. With ``follow``, an occurrence may only continue into a block that
        follows the previous one in the control flow; with ``consecutive``, only into a
        block that is its sole successor and has it as sole predecessor, so the occurrence
        is one straight run of code.
        """
        if self.statements == STATEMENTS_ANY:
            return None
        graph = self.graph
        nodes = {(b.addr, b.idx): b for b in graph}
        locs = self.stream.locs
        segment = [0] * len(locs)
        seg = 0
        for t in range(1, len(locs)):
            a, b = locs[t - 1].block_loc, locs[t].block_loc
            if a != b:
                pred, succ = nodes[a], nodes[b]
                follows = graph.has_edge(pred, succ)
                if self.statements == STATEMENTS_CONSECUTIVE:
                    follows = follows and graph.out_degree[pred] == 1 and graph.in_degree[succ] == 1
                if not follows:
                    seg += 1
            segment[t] = seg
        return segment

    def _build(self, cluster: PatternCluster, entry_loc: Address) -> FuzzyPattern:
        occurrences = [
            PatternOccurrence(interval=iv, region=snap(self.stream, self.graph, iv, entry_loc=entry_loc))
            for iv in cluster.occurrences
        ]
        cores = find_exact_cores(
            self.stream.shape_ids,
            cluster.occurrences,
            min_len=self.min_core_len,
            min_support=self.min_core_support,
        )
        core_occurrences = [
            [
                PatternOccurrence(interval=iv, region=snap(self.stream, self.graph, iv, entry_loc=entry_loc))
                for iv in core.occurrences
            ]
            for core in cores
        ]
        return FuzzyPattern(
            cluster=cluster,
            occurrences=occurrences,
            cores=cores,
            core_occurrences=core_occurrences,
        )

    #
    # reporting
    #

    def summary(self, limit: int = 20) -> str:
        """A human-readable report of what was found."""
        lines = [
            (
                f"FuzzyPatternFinder: {len(self.stream)} tokens, "
                f"{len(self.stream.shape_vocab)} distinct shapes, "
                f"{len(self.patterns)} patterns ({len(self.all_patterns)} before de-overlapping)"
            )
        ]
        for i, p in enumerate(self.patterns[:limit]):
            outlinable = len(p.outlinable_occurrences)
            lines.append(
                f"  pattern {i}: {len(p.occurrences)} occurrences, size {p.size}, "
                f"identity {p.identity:.0%}, savings {p.savings:.0f} tokens "
                f"({p.sound_savings} sound), {outlinable}/{len(p.occurrences)} outlinable"
            )
            for occ in p.occurrences:
                lo, hi = self.stream.addr_range(occ.interval.start, occ.interval.end)
                mark = "+" if occ.outlinable else "-"
                lines.append(
                    f"    {mark} [{occ.interval.start:6d},{occ.interval.end:6d}) "
                    f"{len(occ.interval):4d} tok  "
                    f"{lo:#x}-{hi:#x}  {len(occ.block_locs)} blocks"
                    + ("" if occ.outlinable else f"  ({occ.region.reason})")
                )
        return "\n".join(lines)


AnalysesHub.register_default("FuzzyPatternFinder", FuzzyPatternFinder)
