#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import os
import unittest
from collections import Counter
from dataclasses import replace

import angr
from angr.analyses.decompiler.known_patterns import (
    PAny,
    PAnyStmt,
    PAssign,
    PBinOp,
    PConst,
    PLoad,
    PStmtSeq,
    PStore,
    PVVar,
)
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.patterns.align import AlignParams
from angr.analyses.patterns.search import find_template_occurrences, search, template_leaves, verify
from angr.analyses.patterns.template import Fit
from angr.analyses.patterns.tokenizer import AILCanonicalizer, TokenLoc, TokenStream
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests")

# a three-statement idiom and the shapes it renders to
IDIOM = PStmtSeq(
    (
        PAssign(PVVar(), PBinOp("Add", (PVVar(), PConst()))),
        PStore(PVVar(), PVVar(), size=8),
        PAssign(PVVar(), PLoad(PVVar(), size=8)),
    )
)
IDIOM_SHAPES = ["Asn(V,Add(V,C))", "St8(V,V)", "Asn(V,Ld8(V))"]
NOISE = ["L", "Asn(V,C)", "SE(Call[puts]/1)", "CJfb(CmpEQ(V,C))", "Jf", "Asn(V,Phi2)", "Ret1"]


def _stream(shapes: list[str]) -> TokenStream:
    """A token stream made of shapes alone; enough for search, not for verify."""
    vocab: list[str] = []
    index: dict[str, int] = {}
    ids = []
    for s in shapes:
        if s not in index:
            index[s] = len(vocab)
            vocab.append(s)
        ids.append(index[s])
    klass_vocab: list[str] = []
    klass_index: dict[str, int] = {}
    klass_of_shape = []
    for s in vocab:
        k = AILCanonicalizer.klass_of(s)
        if k not in klass_index:
            klass_index[k] = len(klass_vocab)
            klass_vocab.append(k)
        klass_of_shape.append(klass_index[k])
    klass_ids = [klass_of_shape[i] for i in ids]
    return TokenStream(
        blocks=[],
        block_span={},
        locs=[TokenLoc(0x1000, None, i, 0, None) for i in range(len(shapes))],
        shapes=list(shapes),
        klasses=[klass_vocab[k] for k in klass_ids],
        bags=[Counter() for _ in shapes],
        shape_ids=ids,
        klass_ids=klass_ids,
        shape_vocab=vocab,
        klass_vocab=klass_vocab,
        klass_of_shape=klass_of_shape,
    )


class TestSearch(unittest.TestCase):
    def test_finds_an_exact_copy_where_it_is(self):
        stream = _stream(NOISE[:5] + IDIOM_SHAPES + NOISE)
        matches = search(IDIOM, stream)

        assert len(matches) == 1
        m = matches[0]
        assert (m.interval.start, m.interval.end) == (5, 8)
        assert m.similarity == 1.0
        assert m.identity == 1.0
        assert [c.fit for c in m.columns] == [Fit.EXACT] * 3

    def test_finds_every_copy(self):
        stream = _stream(IDIOM_SHAPES + NOISE + IDIOM_SHAPES + NOISE[:3] + IDIOM_SHAPES)
        starts = sorted(m.interval.start for m in search(IDIOM, stream))
        assert starts == [0, 10, 16]

    def test_nothing_in_unrelated_code(self):
        assert search(IDIOM, _stream(NOISE * 4)) == []

    def test_operator_class_variant_scores_below_exact(self):
        variant = ["Asn(V,Sub(V,C))", "St8(V,V)", "Asn(V,Ld8(V))"]
        stream = _stream(NOISE + variant + NOISE)
        (m,) = search(IDIOM, stream)

        assert m.columns[0].fit is Fit.KLASS
        assert 0.5 < m.similarity < 1.0
        assert m.identity == 2 / 3

    def test_extra_statement_inside_is_a_gap(self):
        stream = _stream(NOISE + IDIOM_SHAPES[:2] + ["Asn(V,C)"] + IDIOM_SHAPES[2:] + NOISE)
        (m,) = search(IDIOM, stream)

        assert len(m.interval) == 4, "the interval spans the interleaved statement"
        assert m.placed_leaves == 3
        assert m.similarity < 1.0

    def test_optional_leaf_may_be_absent_for_free(self):
        stmts = list(IDIOM.stmts)
        stmts.insert(1, PAnyStmt(optional=True))
        with_optional = PStmtSeq(tuple(stmts))
        stream = _stream(NOISE + IDIOM_SHAPES + NOISE)

        (m,) = search(with_optional, stream)
        assert m.similarity == 1.0
        assert m.identity == 1.0
        skipped = [c for c in m.columns if c.token is None]
        assert [c.leaf for c in skipped] == [1]

    def test_missing_required_leaf_costs(self):
        stream = _stream(NOISE + IDIOM_SHAPES[:2] + NOISE)
        params = AlignParams(min_identity=0.3)
        (m,) = search(IDIOM, stream, params)

        last = m.columns[2]
        assert last.token is None or last.fit is Fit.NONE, "the third leaf has nothing that fits"
        assert m.similarity < 2 / 3, "a missing statement costs more than its share of the score"

    def test_weight_makes_a_leaf_matter_more(self):
        variant = ["Asn(V,Sub(V,C))", "St8(V,V)", "Asn(V,Ld8(V))"]
        stream = _stream(NOISE + variant + NOISE)
        light = search(IDIOM, stream)[0].similarity

        heavy_first = PStmtSeq((replace(IDIOM.stmts[0], weight=4.0), *IDIOM.stmts[1:]))
        heavy = search(heavy_first, stream)[0].similarity
        assert heavy < light, "the class-only leaf carries more weight, so the same variant scores lower"

    def test_wildcard_only_template_is_tried_everywhere(self):
        stream = _stream([*NOISE, "St8(V,V)", "St4(V,C)", *NOISE])
        template = PStmtSeq((PStore(PAny(), PAny()), PStore(PAny(), PAny())))
        starts = [m.interval.start for m in search(template, stream)]
        assert 7 in starts

    def test_leaves_follow_a_graph_in_reverse_post_order(self):
        from angr.analyses.decompiler.known_patterns import (  # pylint:disable=import-outside-toplevel
            PBlockPat,
            PGraphPat,
        )

        a = PBlockPat("a", PStmtSeq((PAssign(PVVar(), PConst(value=1)),)))
        b = PBlockPat("b", PStmtSeq((PAssign(PVVar(), PConst(value=2)),)))
        c = PBlockPat("c", PStmtSeq((PAssign(PVVar(), PConst(value=3)),)))
        graph = PGraphPat(blocks={"a": a, "b": b, "c": c}, edges=[("a", "c"), ("c", "b"), ("b", "out")], entry="a")

        values = [leaf.src.value for leaf in template_leaves(graph)]
        assert values == [1, 3, 2]


def _first_statement(stream, start: int) -> int:
    """The first token at or after ``start`` that is not a jump: jumps are not leaves."""
    pos = start
    while pos < len(stream) and stream.shapes[pos] in ("Jf", "Jb", "J?"):
        pos += 1
    return pos


class TestVerifyOnARealFunction(unittest.TestCase):
    """Shape search places a template; verification holds it to the constraints shapes
    cannot see. Lift a template from a real function's own statements: it must find
    itself, verified; a wrong constant must be found and refused."""

    @classmethod
    def setUpClass(cls):
        proj = angr.Project(os.path.join(BIN_PATH, "x86_64", "1after909"), auto_load_libs=False)
        cfg = proj.analyses.CFG(normalize=True)
        func = proj.kb.functions["doit"]
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.ail_graph is not None and dec.codegen is not None
        cls.graph = dec.ail_graph
        cls.entry = next(b for b in dec.ail_graph if b.addr == func.addr)
        cls.gen = PatternGenerator(dec.codegen, dec.ail_graph)
        cls.kb = proj.kb

    def _lift(self, stream, start, length):
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        nodes = []
        for loc in stream.locs[start : start + length]:
            stmt = blocks[loc.block_loc].statements[loc.stmt_idx]
            nodes.append(self.gen._gen_stmt(stmt, {}, set()))
        return PStmtSeq(tuple(nodes))

    def _pick_window(self, stream, length=3):
        """The first run of ``length`` statements the generator can render, with a constant in it."""
        for start in range(len(stream) - length):
            try:
                template = self._lift(stream, start, length)
            except PatternGenerationError:
                continue
            if any(isinstance(leaf, PAssign) and isinstance(leaf.src, PConst) for leaf in template.stmts):
                return start, template
        raise AssertionError("no liftable window with a constant assignment in doit")

    def test_a_lifted_template_finds_itself_verified(self):
        from angr.analyses.patterns.search import tokenize_for_templates  # pylint:disable=import-outside-toplevel

        stream = tokenize_for_templates(self.graph, self.entry, kb=self.kb)
        start, template = self._pick_window(stream)

        _stream, matches = find_template_occurrences(template, self.graph, self.entry, kb=self.kb)
        at_origin = [m for m in matches if m.interval.start == start]
        assert at_origin, f"the template lifted from tokens {start}.. was not found there"
        m = at_origin[0]
        assert m.similarity == 1.0
        assert m.verified is True

    def test_long_windows_find_themselves_verified(self):
        """Labels and phis are not pattern statements and conversions are dropped by the
        generator; a lifted window of any length must still match its own statements."""
        from angr.analyses.patterns.search import tokenize_for_templates  # pylint:disable=import-outside-toplevel

        stream = tokenize_for_templates(self.graph, self.entry, kb=self.kb)
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        for start, length in ((20, 30), (50, 60), (100, 100)):
            stmts = [blocks[loc.block_loc].statements[loc.stmt_idx] for loc in stream.locs[start : start + length]]
            template = self.gen.generate_pattern_from_statements(stmts, "w")
            origin = _first_statement(stream, start)
            hits = [m for m in search(template, stream) if m.interval.start <= origin < m.interval.end]
            assert hits, f"window [{start},{start + length}) not found at its origin"
            verify(hits[0], template, stream)
            assert hits[0].similarity == 1.0, (start, length, hits[0].similarity)
            assert hits[0].verified is True, [c for c in hits[0].columns if c.verified is False][:3]

    def test_fully_loosened_windows_still_verify_against_their_source(self):
        """Every loosening the editor offers must keep a pattern matching the statements it
        came from; each one has failed that at some point."""
        from angr.analyses.decompiler.known_patterns.edit import PatternEditor  # pylint:disable=import-outside-toplevel
        from angr.analyses.patterns.search import tokenize_for_templates  # pylint:disable=import-outside-toplevel

        stream = tokenize_for_templates(self.graph, self.entry, kb=self.kb)
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        for start in range(0, len(stream) - 40, 40):
            stmts = [blocks[loc.block_loc].statements[loc.stmt_idx] for loc in stream.locs[start : start + 40]]
            editor = PatternEditor(self.gen.generate_pattern_from_statements(stmts, "w"))
            editor.loosen_constants()
            editor.cut_depth()
            editor.loosen_interior_captures()
            origin = _first_statement(stream, start)
            hits = [m for m in search(editor.pattern, stream) if m.interval.start <= origin < m.interval.end]
            assert hits, f"window [{start},{start + 40}) not found at its origin after loosening"
            verify(hits[0], editor.pattern, stream)
            assert hits[0].verified is True, (start, [c for c in hits[0].columns if c.verified is False][:3])

    def test_a_wrong_constant_is_found_but_refused(self):
        from angr.analyses.patterns.search import tokenize_for_templates  # pylint:disable=import-outside-toplevel

        stream = tokenize_for_templates(self.graph, self.entry, kb=self.kb)
        start, template = self._pick_window(stream)
        stmts = list(template.stmts)
        i = next(i for i, leaf in enumerate(stmts) if isinstance(leaf, PAssign) and isinstance(leaf.src, PConst))
        stmts[i] = replace(stmts[i], src=PConst(value=stmts[i].src.value + 0x7777))
        wrong = PStmtSeq(tuple(stmts))

        matches = search(wrong, stream)
        m = next(m for m in matches if m.interval.start == start)
        assert m.similarity == 1.0, "shapes do not see the constant"
        verify(m, wrong, stream)
        assert m.verified is False
        assert m.columns[i].verified is False


if __name__ == "__main__":
    unittest.main()
