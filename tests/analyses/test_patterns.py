from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os
import random
import unittest
from unittest import TestCase

import networkx

import angr
from angr.ailment.statement import Label
from angr.analyses.patterns import (
    AILCanonicalizer,
    AlignParams,
    Interval,
    discover,
    find_exact_cores,
    select_disjoint,
    snap,
    tokenize,
)
from angr.analyses.patterns.align import (
    ScoreModel,
    banded_sw,
    chain_seeds,
    find_seeds,
    refine_candidates,
)
from angr.utils.ail import is_phi_assignment
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests")


def _ids(seq):
    """Map a string of letters to token ids plus an identity klass table."""
    vocab: dict[str, int] = {}
    ids = [vocab.setdefault(c, len(vocab)) for c in seq]
    return ids, list(range(len(vocab)))


def _klasses(seq, groups):
    """Token ids plus a klass table that folds each group of letters together."""
    vocab: dict[str, int] = {}
    ids = [vocab.setdefault(c, len(vocab)) for c in seq]
    klass_of = {}
    for gi, group in enumerate(groups):
        for c in group:
            klass_of[c] = gi
    table = [0] * len(vocab)
    for c, i in vocab.items():
        table[i] = klass_of.get(c, len(groups) + i)
    return ids, table


class TestFuzzyAlign(TestCase):
    """The algorithm layer, over synthetic token strings."""

    def test_exact_repeat(self):
        seq = "ABCDEFGHIJ" + "zzzzzzzzzz" + "ABCDEFGHIJ"
        ids, klass = _ids(seq)
        clusters = discover(ids, klass, AlignParams(k=3, min_score=10, min_size=6, min_anchors=2))
        assert clusters, "an exact 10-token repeat must be found"
        top = clusters[0]
        assert len(top.occurrences) == 2
        assert top.identity == 1.0
        assert all(len(o) >= 8 for o in top.occurrences)

    def test_repeat_with_substitutions(self):
        # same shape, three positions substituted -- what differing constants look like
        a = "ABCDEFGHIJKLMNOP"
        b = "ABXDEFGHYJKLMNZP"
        ids, klass = _ids(a + "zzzzzzzzzz" + b)
        clusters = discover(ids, klass, AlignParams(k=3, min_score=10, min_size=8, min_anchors=2))
        assert clusters, "a repeat with substitutions must still be found"
        top = clusters[0]
        assert len(top.occurrences) == 2
        assert 0.6 <= top.identity < 1.0

    def test_repeat_with_indels(self):
        a = "ABCDEFGHIJKLMNOP"
        b = "ABCDEFGXYHIJKLMNOP"  # two tokens inserted in the middle
        ids, klass = _ids(a + "zzzzzzzzzz" + b)
        clusters = discover(ids, klass, AlignParams(k=3, min_score=10, min_size=8, min_anchors=2))
        assert clusters, "a repeat spanning an insertion must be found as one pattern"
        top = clusters[0]
        assert len(top.occurrences) == 2
        assert max(len(o) for o in top.occurrences) >= 14

    def test_three_occurrences_cluster(self):
        unit = "ABCDEFGHIJKLMNOP"
        # separators must differ in symbol and length, otherwise the whole
        # unit+separator becomes the period and the framing is arbitrary
        seq = unit + "wwwww" + unit.replace("C", "X") + "qqqqqqq" + unit.replace("K", "Y")
        ids, klass = _ids(seq)
        clusters = discover(ids, klass, AlignParams(k=3, min_score=10, min_size=8, min_anchors=2))
        assert clusters
        assert len(clusters[0].occurrences) == 3, "all three copies belong to one cluster"

    def test_klass_partial_credit(self):
        # every third token differs but stays in the same operator class
        a = "ABCDEFGHIJKL"
        b = "AbCDeFGHiJKL"
        ids, klass = _klasses(a + "zzzzzzzzzz" + b, ["Aa", "Bb", "Ee", "Ii"])
        graded = discover(ids, klass, AlignParams(k=2, min_score=8, min_size=6, min_anchors=2))
        assert graded, "class-equal substitutions must still align"

    def test_no_false_positives_on_random(self):
        rng = random.Random(0xC0FFEE)
        ids = [rng.randrange(40) for _ in range(4000)]
        clusters = discover(ids, list(range(40)), AlignParams(min_score=60, min_identity=0.7, min_size=20))
        assert not clusters, f"random input must not produce patterns, got {len(clusters)}"

    def test_seeds_mask_low_complexity(self):
        ids = [0] * 500 + list(range(1, 200))
        buckets = find_seeds(ids, AlignParams(k=4, max_seed_multiplicity=50))
        assert all(len(v) <= 50 for v in buckets.values()), "over-frequent k-grams must be masked out"

    def test_winnowing_keeps_long_matches(self):
        seq = "ABCDEFGHIJKLMNOPQRST" + "zzzzzzzzzzzzzzz" + "ABCDEFGHIJKLMNOPQRST"
        ids, _ = _ids(seq)
        params = AlignParams(k=4, window=6, min_anchors=1)
        buckets = find_seeds(ids, params)
        assert any(len(v) >= 2 for v in buckets.values()), "a match longer than k+w-1 must survive winnowing"

    def test_banded_sw_finds_local_alignment(self):
        ids, klass = _ids("QQQABCDEFGHQQQ" + "ABCDEFGH")
        score = ScoreModel(klass, AlignParams())
        aln = banded_sw(ids, 0, 14, 14, 22, 12, score, AlignParams())
        assert aln is not None
        assert aln.matched == 8
        assert aln.identity == 1.0

    def test_tandem_repeats_excluded_by_default(self):
        ids, klass = _ids("ABCDEFGH" * 6)
        params = AlignParams(k=3, min_score=10, min_size=6, min_anchors=2)
        clusters = discover(ids, klass, params)
        for c in clusters:
            for i, x in enumerate(c.occurrences):
                for y in c.occurrences[i + 1 :]:
                    assert not x.overlaps(y), "occurrences within a cluster must be disjoint"

    def test_alignment_spans_an_indel(self):
        a = "ABCDEFGHIJKLMNOPQRSTUVWX"
        b = "ABCDEFGHIJKLzzMNOPQRSTUVWX"
        ids, klass = _ids(a + "0000000000" + b)
        params = AlignParams(k=3, min_anchors=2, band=8, max_gap=20, min_score=10, min_size=8)
        cands = chain_seeds(find_seeds(ids, params), params)
        assert cands, "an indel must not prevent chaining"
        # the insertion splits the seeds onto two diagonals; the banded
        # alignment must still span both halves as one match
        alns = refine_candidates(ids, cands, ScoreModel(klass, params), params)
        assert alns
        assert max(len(x.a) for x in alns) >= 20, "the alignment must cover both sides of the insertion"

    def test_chain_does_not_fuse_distinct_repeat_pairs(self):
        unit = "ABCDEFGHIJKLMNOP"
        ids, _ = _ids(unit + "wwwww" + unit + "qqqqqqq" + unit)
        params = AlignParams(k=3, min_anchors=2)
        for d, s, e, _ in chain_seeds(find_seeds(ids, params), params):
            assert e - s <= len(unit) + 4, f"candidate (d={d}, [{s},{e})) fuses two different repeat pairs"

    def test_select_disjoint_prefers_savings(self):
        unit = "ABCDEFGHIJKLMNOPQRSTUVWX"
        seq = unit + "wwwww" + unit + "wwwww" + unit
        ids, klass = _ids(seq)
        clusters = discover(ids, klass, AlignParams(k=3, min_score=10, min_size=8, min_anchors=2))
        chosen = select_disjoint(clusters)
        assert chosen
        claimed: list[Interval] = []
        for c in chosen:
            for occ in c.occurrences:
                for other in claimed:
                    assert occ.overlap_len(other) / max(1, len(occ)) <= 0.25
                claimed.append(occ)


class TestExactCores(TestCase):
    """Tier 2: the sub-ranges a fuzzy family shares exactly."""

    def test_core_of_two_near_duplicates(self):
        a = "AAAA" + "COMMONCORE12" + "BBBB"
        b = "CCCC" + "COMMONCORE12" + "DDDD"
        ids, _ = _ids(a + b)
        occs = [Interval(0, len(a)), Interval(len(a), len(a) + len(b))]
        cores = find_exact_cores(ids, occs, min_len=4)
        assert cores
        assert cores[0].length == 12
        assert cores[0].support == 2

    def test_multiple_cores(self):
        a = "HEAD1234" + "xxxx" + "TAIL5678"
        b = "HEAD1234" + "yyyy" + "TAIL5678"
        ids, _ = _ids(a + b)
        occs = [Interval(0, len(a)), Interval(len(a), len(a) + len(b))]
        cores = find_exact_cores(ids, occs, min_len=4)
        assert len(cores) >= 2, "both the shared head and the shared tail must be reported"
        assert sum(c.length for c in cores) >= 16

    def test_support_counts_distinct_occurrences(self):
        unit = "SHAREDCORE"
        ids, _ = _ids(unit + "aaa" + unit + "bbb" + unit)
        occs = [Interval(0, 13), Interval(13, 26), Interval(26, 36)]
        cores = find_exact_cores(ids, occs, min_len=4, min_support=3)
        assert cores
        assert cores[0].support == 3
        assert cores[0].savings == 2 * cores[0].length

    def test_no_core_below_min_len(self):
        ids, _ = _ids("ABCDEFGH" + "IJKLMNOP")
        occs = [Interval(0, 8), Interval(8, 16)]
        assert not find_exact_cores(ids, occs, min_len=4)


class TestSingleEntrySubrun(TestCase):
    """A run of blocks with one jumped into from outside: the largest sub-run avoiding it."""

    @staticmethod
    def _graph():
        from angr.ailment import Block  # pylint:disable=import-outside-toplevel
        from angr.ailment.expression import Const  # pylint:disable=import-outside-toplevel
        from angr.ailment.manager import Manager  # pylint:disable=import-outside-toplevel
        from angr.ailment.statement import Jump  # pylint:disable=import-outside-toplevel

        manager = Manager()

        def block(addr, target):
            return Block(addr, 1, statements=[Jump(manager.next_atom(), Const(manager.next_atom(), target, 64))])

        entry = block(0x1000, 0x2000)
        chain = [block(0x2000 + 0x100 * i, 0x2100 + 0x100 * i) for i in range(6)]
        exit_ = block(0x2600, 0x2700)
        intruder = block(0x3000, 0x2300)  # jumps into the middle of the chain
        graph = networkx.DiGraph()
        graph.add_edge(entry, chain[0])
        graph.add_edge(entry, intruder)
        for a, b in zip(chain, chain[1:]):
            graph.add_edge(a, b)
        graph.add_edge(chain[-1], exit_)
        graph.add_edge(intruder, chain[3])
        return graph, entry, chain

    def test_largest_subrun_excludes_the_block_jumped_into(self):
        from angr.analyses.patterns.region import (
            largest_single_entry_subrun,  # pylint:disable=import-outside-toplevel
        )

        graph, entry, chain = self._graph()
        stream = tokenize(graph, entry)
        start = stream.block_span[chain[0].addr, None][0]
        end = stream.block_span[chain[5].addr, None][1]
        whole = snap(stream, graph, Interval(start, end), entry_loc=(entry.addr, None))
        assert not whole.outlinable and "entered from outside" in whole.reason

        best = largest_single_entry_subrun(stream, graph, Interval(start, end), entry_loc=(entry.addr, None))
        assert best is not None and best.outlinable
        # blocks 0..2 (three of them) end where the intruder comes in; blocks 3..5 start at it and
        # are entered from the intruder, so the run before the intruder is the largest
        assert best.block_locs == [(b.addr, None) for b in chain[:3]]

    def test_min_ratio_can_refuse_a_small_subrun(self):
        from angr.analyses.patterns.region import (
            largest_single_entry_subrun,  # pylint:disable=import-outside-toplevel
        )

        graph, entry, chain = self._graph()
        stream = tokenize(graph, entry)
        start = stream.block_span[chain[0].addr, None][0]
        end = stream.block_span[chain[5].addr, None][1]
        assert (
            largest_single_entry_subrun(
                graph=graph, stream=stream, interval=Interval(start, end), entry_loc=(entry.addr, None), min_ratio=0.9
            )
            is None
        )


class TestTokenizer(TestCase):
    """The AIL -> token transformation."""

    def test_klass_folds_operators(self):
        assert AILCanonicalizer.klass_of("Asn(VR,Add(VR,C))") == AILCanonicalizer.klass_of("Asn(VR,Sub(VR,C))")
        assert AILCanonicalizer.klass_of("Asn(VR,Add(VR,C))") != AILCanonicalizer.klass_of("Asn(VR,Shl(VR,C))")
        assert AILCanonicalizer.klass_of("St8(VR,C)") == "St8(VR,C)"

    def test_tokenize_is_deterministic_and_covers_every_statement(self):
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["verify_password"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None

        entry = next(b for b in dec.ail_graph if b.addr == func.addr)
        first = tokenize(dec.ail_graph, entry)
        second = tokenize(dec.ail_graph, entry)

        assert first.shapes == second.shapes, "tokenization must be deterministic"
        assert len(first) == sum(len(b.statements) for b in dec.ail_graph)
        assert len(first.blocks) == len(dec.ail_graph)
        # every block owns a contiguous, non-overlapping span
        spans = sorted(first.block_span.values())
        assert spans[0][0] == 0
        for (_, prev_end), (next_start, _) in zip(spans, spans[1:]):
            assert prev_end == next_start

    def test_constants_are_abstracted(self):
        from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment

        dst = VirtualVariable(None, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
        a = Assignment(None, dst, Const(None, 0x1234, 32))
        b = Assignment(None, dst, Const(None, 0xBEEF, 32))

        abstracting = AILCanonicalizer(const_mode="abstract")
        assert abstracting.statement(a) == abstracting.statement(b), (
            "statements differing only in a constant must share a shape"
        )

        exact = AILCanonicalizer(const_mode="exact")
        assert exact.statement(a) != exact.statement(b), "const_mode='exact' must keep the values apart"

    def test_vvars_are_abstracted(self):
        from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment

        canon = AILCanonicalizer()
        first = VirtualVariable(None, 1, 32, VirtualVariableCategory.REGISTER, oident=16)
        second = VirtualVariable(None, 99, 32, VirtualVariableCategory.REGISTER, oident=24)
        stack = VirtualVariable(None, 7, 32, VirtualVariableCategory.STACK, oident=-8)

        assert canon.statement(Assignment(None, first, Const(None, 1, 32))) == canon.statement(
            Assignment(None, second, Const(None, 1, 32))
        ), "different registers must share a shape"
        assert canon.statement(Assignment(None, first, Const(None, 1, 32))) != canon.statement(
            Assignment(None, stack, Const(None, 1, 32))
        ), "a register and a stack slot must not share a shape"


class TestFuzzyPatternFinder(TestCase):
    """End to end on a real function."""

    def test_finder_runs_and_reports_outlinability(self):
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None

        finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph)
        # labels and phis are not statements an idiom is made of; the stream skips them
        assert len(finder.stream) == sum(
            1 for b in dec.ail_graph for s in b.statements if not isinstance(s, Label) and not is_phi_assignment(s)
        )
        for pattern in finder.patterns:
            assert len(pattern.occurrences) >= 2
            for occ in pattern.occurrences:
                assert occ.region.reason
                if occ.outlinable:
                    assert occ.region.frontier
                    assert occ.region.block_locs
            for core in pattern.cores:
                assert core.support >= 2
                assert core.length >= 4
        assert isinstance(finder.summary(), str)

    def test_dedup_keeps_the_graph_consistent(self):
        """Whatever the deduplicator outlines, the result must stay decompilable."""
        from angr.analyses.patterns.dedup import graph_problems

        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None
        assert not graph_problems(dec.ail_graph, func.addr), "baseline graph must be clean"

        finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph)
        dedup = proj.analyses.PatternDeduplicator(func, dec.ail_graph, finder.patterns, finder.stream)

        assert not graph_problems(dedup.result.graph, func.addr), (
            "every outline is validated and rolled back on failure, so the "
            f"result must be clean: {graph_problems(dedup.result.graph, func.addr)[:3]}"
        )
        # the input graph must not have been touched
        assert not graph_problems(dec.ail_graph, func.addr)
        assert len(dec.ail_graph) == len(list(dec.ail_graph.nodes))
        for interval, reason in dedup.result.skipped:
            assert reason, f"every skip must carry a reason ({interval})"

    def test_merged_callees_are_identical_modulo_constants(self):
        """A merge group may only contain callees with the same full-depth shape."""
        from angr.analyses.patterns.dedup import callee_shape

        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        proj.analyses.CompleteCallingConventions()
        func = proj.kb.functions["main"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph)
        dedup = proj.analyses.PatternDeduplicator(func, dec.ail_graph, finder.patterns, finder.stream)

        for group in dedup.result.groups:
            assert group.size >= 2
            shapes = {m.shape for m in group.members}
            assert len(shapes) == 1, "members of a merge group must share one full-depth shape"
            # the representative's body was rewritten, so re-derive from a member's record
            counts = {len(m.consts) for m in group.members}
            assert len(counts) == 1, "shape-equal callees must hold the same number of constants"
            for idx in group.lifted_const_indices:
                assert len({m.consts[idx] for m in group.members}) > 1, (
                    "only constants that actually differ may be lifted into parameters"
                )
        assert callee_shape.__doc__

    def test_synthetic_duplicate_is_found(self):
        """A graph with a block sequence repeated three times must yield one pattern."""
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["verify_password"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        entry = next(b for b in dec.ail_graph if b.addr == func.addr)
        stream = tokenize(dec.ail_graph, entry)

        # replay the real token stream three times: a pattern must span the copies
        ids = stream.shape_ids * 3
        clusters = discover(ids, stream.klass_of_shape, AlignParams(min_score=30, min_size=10))
        assert clusters
        assert len(clusters[0].occurrences) >= 2


if __name__ == "__main__":
    unittest.main()


class TestDeduplicateDoit(TestCase):
    """The error-exit idiom of 1after909's doit, puts(msg); fflush(stdout); return -1, through
    discovery and deduplication."""

    @classmethod
    def setUpClass(cls):
        from angr.analyses.patterns import PatternDeduplicator  # pylint:disable=import-outside-toplevel

        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["doit"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None
        params = AlignParams(min_size=3, min_score=9, min_anchors=1, k=3, min_identity=0.6)
        cls.finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph, params=params, disjoint=False)
        cls.dedup = proj.analyses[PatternDeduplicator](
            func, dec.ail_graph, cls.finder.patterns, cls.finder.stream, granularity="occurrence"
        )
        cls.proj, cls.func, cls.dec = proj, func, dec

    def _error_exit_sites(self) -> list[int]:
        st = self.finder.stream
        seq = ["SE(Call[puts]/1)", "SE(Call[fflush]/1)", "Jf", "Jf", "Ret1(C)"]
        return [i for i in range(len(st) - 4) if st.shapes[i : i + 5] == seq]

    def test_a_failed_larger_region_releases_its_tokens(self):
        """The idiom's copies overlap a looser family that cannot be outlined; they must still
        be outlined themselves."""
        sites = self._error_exit_sites()
        assert len(sites) >= 8
        outlined = [r.interval.start for r in self.dedup.result.outlined]
        assert sum(1 for s in sites if s in outlined) >= 3, outlined

    def test_merged_callee_lifts_values_but_never_targets(self):
        from angr.ailment.expression import Const, VirtualVariable  # pylint:disable=import-outside-toplevel
        from angr.ailment.statement import Jump, Return  # pylint:disable=import-outside-toplevel
        from angr.analyses.patterns.dedup import graph_problems  # pylint:disable=import-outside-toplevel

        sites = set(self._error_exit_sites())
        group = next(g for g in self.dedup.result.groups if any(m.interval.start in sites for m in g.members))
        assert group.size >= 3
        rep = group.members[0]
        # the message and the returned value differ between copies and become parameters
        assert len(group.lifted_const_indices) == 2 and len(rep.child_args) == 2
        for block in rep.child_graph:
            for stmt in block.statements:
                if isinstance(stmt, Jump):
                    assert isinstance(stmt.target, Const), "a jump target is a block address, never a parameter"
                if isinstance(stmt, Return):
                    assert isinstance(stmt.ret_exprs[0], VirtualVariable), "the returned value is a parameter"
        for stmt in (s for b in rep.child_graph for s in b.statements):
            call = getattr(stmt, "expr", None)
            if call is not None and hasattr(call, "target"):
                assert isinstance(call.target, Const), "a callee is what the body does, never a parameter"
        # a closed region's callsite returns the call, with the copy's own constants appended
        blocks = {(b.addr, b.idx): b for b in self.dedup.result.graph}
        for member in group.members:
            (stmt,) = (s for s in blocks[member.call_loc].statements if isinstance(s, Return))
            call = stmt.ret_exprs[0]
            assert call.target == group.name and len(call.args) == 2 and all(isinstance(a, Const) for a in call.args)
        assert graph_problems(self.dedup.result.graph, self.func.addr) == []

    def test_a_failed_merge_leaves_no_trace(self):
        from angr.analyses.patterns import PatternDeduplicator  # pylint:disable=import-outside-toplevel
        from angr.analyses.patterns.dedup import callee_shape  # pylint:disable=import-outside-toplevel

        dedup = self.proj.analyses[PatternDeduplicator](
            self.func,
            self.dec.ail_graph,
            self.finder.patterns,
            self.finder.stream,
            granularity="occurrence",
            merge=False,
        )
        sites = set(self._error_exit_sites())
        members = [r for r in dedup.result.outlined if r.interval.start in sites]
        assert len(members) >= 2
        before = (callee_shape(members[0].child_graph), list(members[0].child_args), members[0].child_func.name)
        # a member whose callsite is gone makes the merge fail after the representative was edited
        members[-1].call_loc = (0xDEAD, None)
        assert dedup._apply_merge(dedup.result.graph, members, [1], "nope") is False
        after = (callee_shape(members[0].child_graph), list(members[0].child_args), members[0].child_func.name)
        assert after == before
