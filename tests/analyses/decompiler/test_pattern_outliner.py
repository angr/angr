#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
import unittest

import angr
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.decompiler.optimization_passes import PatternOutliner
from angr.analyses.patterns.dedup import graph_problems
from angr.analyses.patterns.search import tokenize_for_templates
from tests.common import bin_location

BIN_PATH = os.path.join(bin_location, "tests")
BINARY = os.path.join(BIN_PATH, "x86_64", "1after909")


def _load():
    proj = angr.Project(BINARY, auto_load_libs=False)
    cfg = proj.analyses.CFG(normalize=True)
    return proj, cfg, proj.kb.functions["doit"]


def _lift_a_pattern(proj, cfg, func, call_name, length=3):
    """A pattern from the first run of ``length`` statements of one block that the generator
    can render in full, so the pass has an exact occurrence to find."""
    dec = proj.analyses.Decompiler(func, cfg=cfg.model)
    assert dec.ail_graph is not None and dec.codegen is not None
    entry = next(b for b in dec.ail_graph if b.addr == func.addr)
    stream = tokenize_for_templates(dec.ail_graph, entry, kb=proj.kb)
    blocks = {(b.addr, b.idx): b for b in stream.blocks}
    gen = PatternGenerator(dec.codegen, dec.ail_graph)
    for start in range(len(stream) - length):
        locs = stream.locs[start : start + length]
        if len({loc.block_loc for loc in locs}) != 1:
            continue
        stmts = [blocks[loc.block_loc].statements[loc.stmt_idx] for loc in locs]
        try:
            for stmt in stmts:
                gen._gen_stmt(stmt, {}, set())
        except PatternGenerationError:
            continue
        return gen.generate_pattern_from_statements(stmts, call_name), dec
    raise AssertionError("no liftable run of statements in doit")


class TestPatternOutliner(unittest.TestCase):
    def test_an_error_exit_selection_outlines_every_exit_with_its_own_string(self):
        """puts(msg); fflush(stdout); return -1 in doit: the region ends in a return, so the
        callee returns on the caller's behalf, and the message the pattern left open is
        passed to each occurrence's call."""
        proj, cfg, func = _load()
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        m = re.search(r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n', dec.codegen.text)
        assert m is not None
        pattern = PatternGenerator(dec.codegen, dec.ail_graph).generate_pattern(m.start(), m.end(), "PatternErrorsOut")

        proj2, cfg2, func2 = _load()
        proj2.kb.patterns.add(pattern)
        dec2 = proj2.analyses.Decompiler(func2, cfg=cfg2.model)
        assert dec2.codegen is not None and dec2.ail_graph is not None
        text = dec2.codegen.text

        calls = re.findall(r'return PatternErrorsOut\("([^"]*)"\);', text)
        assert len(calls) == 8, calls
        stats = proj2.kb.patterns.stats(func2.addr, pattern.name)
        assert stats is not None and stats.outlined == 8 and stats.matches >= 8
        assert "Empty title" in calls and "Cannot open document." in calls
        assert text.count("PatternErrorsOut(") == 8
        assert graph_problems(dec2.ail_graph, func2.addr) == []

    def test_a_stored_pattern_is_outlined_by_name(self):
        proj, cfg, func = _load()
        pattern, _ = _lift_a_pattern(proj, cfg, func, "my_idiom")

        # a fresh project, so nothing of the lifting run is around but the pattern
        proj2, cfg2, func2 = _load()
        proj2.kb.patterns.add(pattern, min_similarity=0.9)
        dec = proj2.analyses.Decompiler(func2, cfg=cfg2.model)

        assert dec.codegen is not None and dec.ail_graph is not None
        assert "my_idiom(" in dec.codegen.text, "the occurrence must decompile as a call to the pattern"
        assert graph_problems(dec.ail_graph, func2.addr) == []

    def test_a_disabled_pattern_changes_nothing(self):
        proj, cfg, func = _load()
        pattern, baseline = _lift_a_pattern(proj, cfg, func, "my_idiom")

        proj2, cfg2, func2 = _load()
        proj2.kb.patterns.add(pattern, enabled=False)
        dec = proj2.analyses.Decompiler(func2, cfg=cfg2.model)

        assert dec.codegen is not None and baseline.codegen is not None
        assert "my_idiom(" not in dec.codegen.text

    def test_similarity_alone_can_be_enough(self):
        """A constant the copy does not share fails verification; with require_verified off
        the pass goes by similarity and outlines it anyway."""
        from dataclasses import replace  # pylint:disable=import-outside-toplevel

        from angr.analyses.decompiler.known_patterns import PAssign, PConst  # pylint:disable=import-outside-toplevel

        proj, cfg, func = _load()
        pattern, _ = _lift_a_pattern(proj, cfg, func, "my_idiom")
        stmts = list(pattern.pattern.stmts)
        i = next(i for i, leaf in enumerate(stmts) if isinstance(leaf, PAssign) and isinstance(leaf.src, PConst))
        stmts[i] = replace(stmts[i], src=PConst(value=stmts[i].src.value + 0x7777))
        wrong = replace(pattern, pattern=replace(pattern.pattern, stmts=tuple(stmts)))

        strict, lenient = _load(), _load()
        strict[0].kb.patterns.add(wrong, min_similarity=0.9)
        lenient[0].kb.patterns.add(wrong, min_similarity=0.9, require_verified=False)
        strict_text = strict[0].analyses.Decompiler(strict[2], cfg=strict[1].model).codegen.text
        lenient_text = lenient[0].analyses.Decompiler(lenient[2], cfg=lenient[1].model).codegen.text

        assert "my_idiom(" not in strict_text
        assert "my_idiom(" in lenient_text

    def test_the_pass_reports_what_it_did(self):
        proj, cfg, func = _load()
        pattern, dec = _lift_a_pattern(proj, cfg, func, "my_idiom")
        proj.kb.patterns.add(pattern, min_similarity=0.9)

        assert dec.clinic is not None and dec.ail_graph is not None
        # what Clinic hands a pass: the block indexes it allocates fresh addresses from
        by_addr: dict = {}
        for block in dec.ail_graph:
            by_addr.setdefault(block.addr, set()).add(block)
        pass_ = PatternOutliner(
            func,
            dec.clinic._ail_manager,
            graph=dec.ail_graph,
            blocks_by_addr=by_addr,
            blocks_by_addr_and_idx={(b.addr, b.idx): b for b in dec.ail_graph},
            vvar_id_start=0x10000,
        )
        assert pass_.out_graph is not None
        names = [name for name, _, _ in pass_.outlined]
        assert all(coverage == 1.0 for _, _, coverage in pass_.outlined)
        assert names and set(names) == {"my_idiom"}, names
        assert graph_problems(pass_.out_graph, func.addr) == []


if __name__ == "__main__":
    unittest.main()
