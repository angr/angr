#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import json
import os
import re
import tempfile
import unittest

import angr
from angr.analyses.decompiler.known_patterns import PAny, PCallStmt, PConst, PLoad, PReturn
from angr.analyses.decompiler.known_patterns.edit import PatternEditor
from angr.analyses.decompiler.known_patterns.generator import PatternGenerationError, PatternGenerator
from angr.analyses.decompiler.known_patterns.serialize import dumps, loads
from angr.analyses.decompiler.optimization_passes import PatternOutliner
from angr.analyses.patterns.align import AlignParams
from angr.analyses.patterns.dedup import graph_problems
from angr.analyses.patterns.search import tokenize_for_templates
from angr.knowledge_plugins.patterns import StoredPattern
from tests.common import bin_location, load_project_with_scoped_cfg

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
        # each call is findable in the pseudocode by the address it carries
        rendered = {
            elem.obj.tags.get("ins_addr")
            for elem in dec2.codegen.map_pos_to_node.values()
            if type(elem.obj).__name__ == "CFunctionCall" and "PatternErrorsOut" in str(elem.obj.callee_target)
        }
        assert len(stats.call_addrs) == 8 and set(stats.call_addrs) <= rendered
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


class TestNewBlockAddresses(unittest.TestCase):
    def test_addresses_clear_blocks_an_earlier_pass_added(self):
        import types  # pylint:disable=import-outside-toplevel

        import networkx  # pylint:disable=import-outside-toplevel

        from angr.ailment import Block  # pylint:disable=import-outside-toplevel

        # the stage's map knows the function's own blocks; an earlier pass of the stage has
        # since added a block at the address the map alone would hand out next
        stage_map = {0x1000: None, 0x1040: None}
        taken = 0x1040 + 2048
        graph = networkx.DiGraph()
        for addr in (0x1000, 0x1040, taken):
            graph.add_node(Block(addr, 4, statements=[]))
        pass_ = types.SimpleNamespace(blocks_by_addr=stage_map, _new_block_addrs=set(), _live_graph=graph)
        first = PatternOutliner.new_block_addr(pass_)
        second = PatternOutliner.new_block_addr(pass_)
        assert first == taken + 1 and second == first + 1
        # with nothing added, it is where the base class would start
        pass_ = types.SimpleNamespace(blocks_by_addr=stage_map, _new_block_addrs=set(), _live_graph=None)
        assert PatternOutliner.new_block_addr(pass_) == 0x1040 + 2048


class TestErrorExitPatternSerialization(unittest.TestCase):
    """The pattern lifted from doit's error exits, written out and read back, reused in a
    project that has never seen the one it came from."""

    SELECTION = r'puts\("String is empty."\);\n +fflush\(stdout\);\n +return 0xffffffff;\n'

    @classmethod
    def setUpClass(cls):
        proj, cfg, func = _load()
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None
        m = re.search(cls.SELECTION, dec.codegen.text)
        assert m is not None
        cls.pattern = PatternGenerator(dec.codegen, dec.ail_graph).generate_pattern(
            m.start(), m.end(), "PatternErrorsOut"
        )

    def test_the_lifted_pattern_survives_a_round_trip(self):
        pattern = self.pattern
        assert loads(dumps(pattern)) == pattern

        # what was lifted, and so what the file has to carry: a named string wildcard,
        # a global by symbol, and the returned constant
        puts, fflush, ret = loads(dumps(pattern)).pattern.stmts
        assert isinstance(puts, PCallStmt) and puts.call.names == {"puts"} and puts.call.args == (PAny(name="_s1"),)
        assert isinstance(fflush, PCallStmt) and fflush.call.args == (PLoad(PConst(symbol="stdout"), size=8),)
        assert isinstance(ret, PReturn) and ret.values == (PConst(value=0xFFFFFFFF),)

        # the library's own record, settings included, through JSON text
        stored = StoredPattern(pattern, enabled=False, min_similarity=0.9, require_verified=False)
        back = StoredPattern.from_dict(json.loads(json.dumps(stored.to_dict())))
        assert back.pattern == pattern
        assert (back.enabled, back.min_similarity, back.require_verified) == (False, 0.9, False)

    def test_a_fresh_project_outlines_every_exit_from_the_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "errors_out.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(StoredPattern(self.pattern).to_dict(), f)

            # a new project and CFG: nothing of the lifting run is reachable from here
            proj, cfg, func = _load()
            with open(path, encoding="utf-8") as f:
                loaded = StoredPattern.from_dict(json.load(f))
            # a looser pattern would still outline these exits, so what came back is checked too
            assert loaded.pattern == self.pattern
            proj.kb.patterns.store(loaded)

        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.ail_graph is not None
        calls = re.findall(r'return PatternErrorsOut\("([^"]*)"\);', dec.codegen.text)
        assert len(calls) == 8, calls
        assert "Empty title" in calls and "Cannot open document." in calls
        stats = proj.kb.patterns.stats(func.addr, self.pattern.name)
        assert stats is not None and stats.outlined == 8
        assert graph_problems(dec.ail_graph, func.addr) == []


# discovery settings small enough to find the idioms of one large function
_DISCOVERY = AlignParams(min_size=4, min_score=12.0, min_anchors=1, k=4, min_identity=0.6)


def _scoped(rel_path: str, func_addr: int, include_plt: bool):
    proj, cfg = load_project_with_scoped_cfg(
        os.path.join(BIN_PATH, rel_path),
        func_addr,
        project_kwargs={"auto_load_libs": False},
        include_plt=include_plt,
    )
    return proj, cfg, cfg.functions[func_addr]


class TestDiscoveredPatternsAcrossProjects(unittest.TestCase):
    """A family discovered in a large function, outlined there, written out, read back, and
    applied to the same function in a fresh project of the same binary."""

    @staticmethod
    def _longest_family_pattern(proj, cfg, func, min_size: int):
        """The longest discovered family with more than one outlinable copy, lifted from its first
        outlinable copy and loosened as the Discover tab does."""
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert dec.codegen is not None and dec.ail_graph is not None
        finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph, params=_DISCOVERY, disjoint=False)
        families = [p for p in finder.all_patterns if len(p.outlinable_occurrences) > 1]
        assert families, "the function has a family with two outlinable copies"
        family = max(families, key=lambda p: (p.size, len(p.outlinable_occurrences)))
        assert family.size >= min_size, family.size
        stream = finder.stream
        blocks = {(b.addr, b.idx): b for b in stream.blocks}
        first = min(family.outlinable_occurrences, key=lambda o: o.interval.start).interval
        stmts = [blocks[loc.block_loc].statements[loc.stmt_idx] for loc in stream.locs[first.start : first.end]]
        editor = PatternEditor(
            PatternGenerator(dec.codegen, dec.ail_graph).generate_pattern_from_statements(stmts, "idiom")
        )
        editor.loosen_constants()
        editor.cut_depth()
        return editor.pattern

    def _discover_outline_and_reuse(self, rel_path: str, func_addr: int, include_plt: bool, min_size: int):
        proj, cfg, func = _scoped(rel_path, func_addr, include_plt)
        pattern = self._longest_family_pattern(proj, cfg, func, min_size)

        # outlined in this project, and never by dropping a value the region defines for later: the
        # Outliner can return one value, and says so when a region has more
        proj.kb.patterns.add(pattern)
        with self.assertNoLogs("angr.analyses.outliner.outliner", level="ERROR"):
            dec2 = proj.analyses.Decompiler(func, cfg=cfg.model, use_cache=False, update_cache=False)
        assert dec2.codegen is not None and dec2.ail_graph is not None
        stats = proj.kb.patterns.stats(func.addr, pattern.name)
        assert stats is not None and stats.outlined >= 2, stats
        calls = dec2.codegen.text.count("idiom(")
        assert calls >= 2
        assert graph_problems(dec2.ail_graph, func.addr) == []

        # through a file
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "idiom.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(proj.kb.patterns.get(pattern.name).to_dict(), f)
            with open(path, encoding="utf-8") as f:
                loaded = StoredPattern.from_dict(json.load(f))
        assert loaded.pattern == pattern

        # the same function in a fresh project outlines the same copies
        proj3, cfg3, func3 = _scoped(rel_path, func_addr, include_plt)
        proj3.kb.patterns.store(loaded)
        with self.assertNoLogs("angr.analyses.outliner.outliner", level="ERROR"):
            dec3 = proj3.analyses.Decompiler(func3, cfg=cfg3.model)
        assert dec3.codegen is not None and dec3.ail_graph is not None
        stats3 = proj3.kb.patterns.stats(func3.addr, pattern.name)
        assert stats3 is not None and stats3.outlined == stats.outlined
        assert sorted(stats3.call_addrs) == sorted(stats.call_addrs)
        assert dec3.codegen.text.count("idiom(") == calls
        assert graph_problems(dec3.ail_graph, func3.addr) == []

    def test_ssa_destruction_copies_do_not_keep_a_pattern_from_its_own_source(self):
        # the final graph of this BIOS routine has copies SSA destruction added after the
        # pattern pass's stage; lifted, they made the pattern miss even the copy it came from
        proj, cfg, func = _scoped("i386/bios.bin.elf", 0xFAFAD, include_plt=False)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model)
        assert any(s.tags.get("dephi") for b in dec.ail_graph for s in b.statements)
        finder = proj.analyses.FuzzyPatternFinder(func, dec.ail_graph, params=_DISCOVERY, disjoint=False)
        blocks = {(b.addr, b.idx): b for b in finder.stream.blocks}
        assert not any(blocks[loc.block_loc].statements[loc.stmt_idx].tags.get("dephi") for loc in finder.stream.locs)
        pattern = self._longest_family_pattern(proj, cfg, func, min_size=12)
        proj.kb.patterns.add(pattern)
        proj.analyses.Decompiler(func, cfg=cfg.model, use_cache=False, update_cache=False)
        stats = proj.kb.patterns.stats(func.addr, pattern.name)
        assert stats is not None and stats.outlined >= 1

    def test_an_outline_that_drops_a_live_value_is_kept_with_a_warning(self):
        # in gnulib's quoting loop the family's region hands on more values than a call returns
        proj, cfg, func = _scoped("x86_64/dir_gcc_-O0", 0x410AAE, include_plt=True)
        pattern = self._longest_family_pattern(proj, cfg, func, min_size=10)
        proj.kb.patterns.add(pattern)
        passes = []
        orig = PatternOutliner.__init__

        def keep(self_, *args, **kwargs):
            passes.append(self_)
            orig(self_, *args, **kwargs)

        PatternOutliner.__init__ = keep
        try:
            with self.assertLogs(
                "angr.analyses.decompiler.optimization_passes.pattern_outliner", level="WARNING"
            ) as logs:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model, use_cache=False, update_cache=False)
        finally:
            PatternOutliner.__init__ = orig
        assert dec.codegen is not None
        assert any("the decompilation after that call is wrong" in line for line in logs.output), logs.output
        lossy = [entry for p in passes for entry in p.lossy]
        assert lossy and all(name == pattern.name and dropped >= 1 for name, _, dropped in lossy)
        # kept: the occurrences are outlined all the same
        stats = proj.kb.patterns.stats(func.addr, pattern.name)
        assert stats is not None and stats.outlined >= len(lossy)
        assert dec.codegen.text.count("idiom(") >= 1

    def test_tiff_vget_field_in_tiffinfo(self):
        # libtiff's tag getter, a switch of va_arg stores: a 41-statement family, two copies
        self._discover_outline_and_reuse("x86_64/tiffinfo_gcc17_O0", 0x40A0A6, include_plt=True, min_size=20)

    def test_c_sqrt_in_apcalc(self):
        # apcalc's complex square root: a 12-statement family, two copies
        self._discover_outline_and_reuse(
            "x86_64/ALLSTAR_apcalc-dev_sample_many", 0x44DAA0, include_plt=True, min_size=8
        )

    def test_a_copy_at_a_loop_head_in_echo(self):
        # the region starts at a self-looping block: its phis stay behind in the caller and the
        # back edge leaves the region, instead of the removed head reappearing as a second block
        proj, cfg, func = _scoped("x86_64/echo", 0x403C80, include_plt=True)
        pattern = self._longest_family_pattern(proj, cfg, func, min_size=8)
        proj.kb.patterns.add(pattern)
        dec = proj.analyses.Decompiler(func, cfg=cfg.model, use_cache=False, update_cache=False)
        assert dec.codegen is not None
        stats = proj.kb.patterns.stats(func.addr, pattern.name)
        assert stats is not None and stats.outlined >= 1, stats
        assert "idiom(" in dec.codegen.text

    def test_sub_415e20_in_file(self):
        # a routine of file at -O2 whose 6-statement family the search finds nine times
        self._discover_outline_and_reuse("x86_64/file_gcc13.3.0_O2", 0x415E20, include_plt=True, min_size=4)


if __name__ == "__main__":
    unittest.main()
