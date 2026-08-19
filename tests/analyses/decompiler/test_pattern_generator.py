from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    KnownPatternFinder,
    PatternGenerationError,
    PatternGenerator,
)
from angr.analyses.decompiler.known_patterns.dsl import (
    PBinOp,
    PGraphPat,
    PLoad,
    PStmtSeq,
)
from angr.analyses.decompiler.optimization_passes import KnownPatternOutliner
from angr.knowledge_plugins.functions.function import PrototypeSource
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
MB_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_multiblock")


def _decompile(bin_path: str, func_name: str):
    # The pattern outliner is disabled here on purpose. These tests decompile a
    # function and then run KnownPatternFinder over the result by hand, which
    # only works on a graph where the idioms are still idioms -- once the
    # outliner has replaced one with a call there is nothing left to match. The
    # `fast` preset used to be pattern-free and is not any more, so what used to
    # be implicit has to be said.
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name)
    assert func is not None
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, disable_opts=[KnownPatternOutliner])
    assert dec.codegen is not None and dec.codegen.text is not None
    return proj, cfg, func, dec


def _matches(proj, func, dec, pattern):
    return proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=[pattern])


class TestPatternGeneratorExpr(TestCase):
    def test_generate_vector_size(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_size")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("a0[1]")
        end = t.index(";", start)
        pat = gen.generate(start, end, "std::vector<int>::size", [t.index("a0[1]")], returnty="unsigned long long")
        # (Load(v+8) - Load(v)) >> 2
        assert isinstance(pat.pattern, PBinOp)
        assert [p.capture for p in pat.params] == ["a0"]
        assert pat.call_name == "std::vector<int>::size"
        # round-trips against the same graph
        finder = _matches(proj, func, dec, pat)
        assert len(finder.matches) == 1
        assert finder.matches[0].block_loc[0] == func.addr

    def test_generate_string_length_field_access(self):
        # a0->field_8 is a struct-field render of Load(a0+8); the generator must
        # recover the load structure from the graph
        proj, _, func, dec = _decompile(STL_BIN, "get_len")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("a0->")
        end = t.index(";", start)
        pat = gen.generate(start, end, "std::string::length", [t.index("a0->")], returnty="unsigned long long")
        assert isinstance(pat.pattern, PLoad)
        finder = _matches(proj, func, dec, pat)
        assert len(finder.matches) == 1


class TestPatternGeneratorStmtSeq(TestCase):
    def test_generate_swap(self):
        proj, cfg, func, dec = _decompile(MB_BIN, "do_swap")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("v1 = *(a0)")
        end = t.index("v1;", t.index("= v1")) + 3
        a_off = t.index("a0", t.index("*(a0)"))
        b_off = t.index("a1", start)
        pat = gen.generate(start, end, "std::swap", [a_off, b_off])
        assert isinstance(pat.pattern, PStmtSeq)
        assert len(pat.pattern.stmts) == 3
        assert [p.capture for p in pat.params] == ["a0", "a1"]
        assert pat.returnty is None

        finder = _matches(proj, func, dec, pat)
        assert len(finder.matches) == 1
        # the generated pattern outlines end-to-end
        result = finder.outline(finder.matches[0])
        del proj.kb.dec_variables[func.addr]
        func.prototype_source = PrototypeSource.GUESSED
        dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
            func,
            clinic_graph=result.graph,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            clinic_arg_vvars=dec.clinic.arg_vvars,
            cfg=cfg.model,
        )
        assert "std::swap(" in dec_outer.codegen.text


class TestPatternGeneratorGraph(TestCase):
    def test_generate_route_diamond(self):
        proj, _, func, dec = _decompile(MB_BIN, "route")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("if (")
        end = t.index("return")
        brace = t.index("{")
        cond = t.index("a0", start)
        a = t.index("a1", brace)
        b = t.index("a2", t.index("else"))
        c = t.index("a3", brace)
        v = t.index("a4", brace)
        pat = gen.generate(start, end, "route", [cond, a, b, c, v])

        assert isinstance(pat.pattern, PGraphPat)
        assert len(pat.pattern.blocks) == 3  # head + two branches
        assert pat.pattern.external_labels  # frontier exit(s)
        assert [p.capture for p in pat.params] == ["a0", "a1", "a2", "a3", "a4"]

        finder = _matches(proj, func, dec, pat)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.block_map is not None and len(m.block_map) == 3


class TestPatternGeneratorErrors(TestCase):
    def test_arg_offset_not_a_variable(self):
        _, _, _, dec = _decompile(MB_BIN, "do_swap")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("v1 = *(a0)")
        end = t.index("v1;", t.index("= v1")) + 3
        with self.assertRaises(PatternGenerationError):
            gen.generate(start, end, "x", [t.index(">>") if ">>" in t else t.index("{")])

    def test_arg_set_mismatch(self):
        _, _, _, dec = _decompile(MB_BIN, "do_swap")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        t = dec.codegen.text
        start = t.index("v1 = *(a0)")
        end = t.index("v1;", t.index("= v1")) + 3
        # only one arg given but the region has two inputs (a0, a1)
        with self.assertRaises(PatternGenerationError):
            gen.generate(start, end, "x", [t.index("a0", t.index("*(a0)"))])

    def test_empty_selection(self):
        _, _, _, dec = _decompile(STL_BIN, "get_size")
        gen = PatternGenerator(dec.codegen, dec.ail_graph)
        with self.assertRaises(PatternGenerationError):
            gen.generate(10, 10, "x", [])


if __name__ == "__main__":
    unittest.main()
