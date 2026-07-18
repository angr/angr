from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import archinfo

import angr
from angr.ailment.expression import Load, VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    CONTAINING_RECORD_PATTERN,
    STD_STRING_LENGTH,
    STD_STRING_LENGTH_MSVC,
    STD_VECTOR_INT_SIZE,
    STD_VECTOR_LONG_LONG_SIZE,
    STD_VECTOR_SHORT_SIZE,
    KnownPatternFinder,
)
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimStruct, SimTypeArray, SimTypePointer
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
CR_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_containing_record.exe")


def _decompile(bin_path: str, func_name: str, preset: str = "fast"):
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name)
    assert func is not None
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset=preset)
    assert dec.codegen is not None and dec.codegen.text is not None
    return proj, cfg, func, dec


def _redecompile(proj, cfg, func, dec, graph):
    # drop the previous run's recovered variables and prototype so they do not
    # feed Typehoon as ground truth
    del dec._variable_kb.variables[func.addr]
    func.prototype_source = PrototypeSource.GUESSED
    dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
        func,
        clinic_graph=graph,
        clinic_start_stage=ClinicStage.POST_CALLSITES,
        clinic_arg_vvars=dec.clinic.arg_vvars,
        cfg=cfg.model,
    )
    assert dec_outer.codegen is not None and dec_outer.codegen.text is not None
    return dec_outer


class TestKnownPatternsDsl(TestCase):
    def test_match_and_unification(self):
        s = VirtualVariable(None, 7, 64, VirtualVariableCategory.PARAMETER)
        from angr.ailment.expression import BinaryOp, Const

        load = Load(None, BinaryOp(None, "Add", [s, Const(None, 8, 64)]), 8, "Iend_LE")
        state = STD_STRING_LENGTH.pattern.match(load, MatchState(), MatchCtx())
        assert state is not None
        assert state.bindings["s"].likes(s)

        # commutativity: Const + vvar also matches
        load_swapped = Load(None, BinaryOp(None, "Add", [Const(None, 8, 64), s]), 8, "Iend_LE")
        assert STD_STRING_LENGTH.pattern.match(load_swapped, MatchState(), MatchCtx()) is not None

        # wrong offset does not match
        load_bad = Load(None, BinaryOp(None, "Add", [s, Const(None, 16, 64)]), 8, "Iend_LE")
        assert STD_STRING_LENGTH.pattern.match(load_bad, MatchState(), MatchCtx()) is None

    def test_msvc_string_length_layout(self):
        from angr.ailment.expression import BinaryOp, Const

        s = VirtualVariable(None, 7, 64, VirtualVariableCategory.PARAMETER)
        load_msvc = Load(None, BinaryOp(None, "Add", [s, Const(None, 16, 64)]), 8, "Iend_LE")
        load_gcc = Load(None, BinaryOp(None, "Add", [s, Const(None, 8, 64)]), 8, "Iend_LE")

        # the MSVC variant matches _Mysize at +16 and only that
        assert STD_STRING_LENGTH_MSVC.pattern.match(load_msvc, MatchState(), MatchCtx()) is not None
        assert STD_STRING_LENGTH_MSVC.pattern.match(load_gcc, MatchState(), MatchCtx()) is None
        assert STD_STRING_LENGTH.pattern.match(load_msvc, MatchState(), MatchCtx()) is None

        # platform gating: the MSVC variant applies on Windows, not Linux
        assert STD_STRING_LENGTH_MSVC.applicable("AMD64", "Win32")
        assert not STD_STRING_LENGTH_MSVC.applicable("AMD64", "Linux")
        assert not STD_STRING_LENGTH.applicable("AMD64", "Win32")
        # the vector patterns apply on both (same three-pointer layout)
        assert STD_VECTOR_INT_SIZE.applicable("AMD64", "Win32")
        assert STD_VECTOR_INT_SIZE.applicable("AMD64", "Linux")

        # both string variants share a call name and thus one prototype
        from angr.analyses.decompiler.known_patterns import KNOWN_PATTERNS_BY_CALL_NAME

        assert KNOWN_PATTERNS_BY_CALL_NAME["std::string::length"] is STD_STRING_LENGTH
        assert STD_STRING_LENGTH_MSVC.call_name == STD_STRING_LENGTH.call_name

    def test_msvc_binary_guard(self):
        from angr.analyses.decompiler.known_patterns.pattern import is_cpp_binary, is_msvc_cpp_binary

        # the mingw PE is a C binary: neither guard passes
        proj = angr.Project(CR_BIN, auto_load_libs=False)
        assert not is_msvc_cpp_binary(proj)
        assert not is_cpp_binary(proj)
        # the g++ ELF has C++ evidence but is not MSVC
        proj = angr.Project(STL_BIN, auto_load_libs=False)
        assert is_cpp_binary(proj)
        assert not is_msvc_cpp_binary(proj)

    def test_register_rejects_incompatible_duplicate(self):
        from angr.analyses.decompiler.known_patterns import register_known_pattern
        from angr.analyses.decompiler.known_patterns.pattern import KnownPattern, PatternParam

        clashing = KnownPattern(
            name="bogus_string_length",
            display_name="std::string::length",
            call_name="std::string::length",
            pattern=STD_STRING_LENGTH.pattern,
            params=(PatternParam("s"),),  # different signature: untyped param
            returnty="int",
        )
        with self.assertRaises(ValueError):
            register_known_pattern(clashing)

    def test_vector_size_requires_same_base(self):
        from angr.ailment.expression import BinaryOp, Const

        v = VirtualVariable(None, 3, 64, VirtualVariableCategory.PARAMETER)
        other = VirtualVariable(None, 4, 64, VirtualVariableCategory.PARAMETER)

        def size_expr(base_hi, base_lo):
            return BinaryOp(
                None,
                "Sar",
                [
                    BinaryOp(
                        None,
                        "Sub",
                        [
                            Load(None, BinaryOp(None, "Add", [base_hi, Const(None, 8, 64)]), 8, "Iend_LE"),
                            Load(None, base_lo, 8, "Iend_LE"),
                        ],
                    ),
                    Const(None, 2, 8),
                ],
            )

        assert STD_VECTOR_INT_SIZE.pattern.match(size_expr(v, v), MatchState(), MatchCtx()) is not None
        # unification: _M_finish and _M_start must be loaded off the same vvar
        assert STD_VECTOR_INT_SIZE.pattern.match(size_expr(v, other), MatchState(), MatchCtx()) is None


class TestKnownPatternFinder(TestCase):
    def test_find_std_string_length(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_len")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.pattern is STD_STRING_LENGTH
        assert isinstance(m.captures["s"], VirtualVariable)
        assert isinstance(m.matched_expr, Load)

    def test_find_std_vector_size(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_size")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        # the std::string::length sub-pattern also matches the _M_finish load;
        # the larger vector-size match must win
        assert m.pattern is STD_VECTOR_INT_SIZE
        assert isinstance(m.captures["v"], VirtualVariable)

    def test_find_std_vector_size_variants(self):
        for func_name, expected_pattern in (
            ("get_size_s", STD_VECTOR_SHORT_SIZE),
            ("get_size_ll", STD_VECTOR_LONG_LONG_SIZE),
        ):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(STL_BIN, func_name)
                finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
                assert len(finder.matches) == 1
                assert finder.matches[0].pattern is expected_pattern

    def test_find_containing_record(self):
        proj, _, func, dec = _decompile(CR_BIN, "sum_list")
        # CONTAINING_RECORD is not enabled by default
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern is CONTAINING_RECORD_PATTERN for m in finder.matches)
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(
            func, dec.ail_graph, patterns=[CONTAINING_RECORD_PATTERN]
        )
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.captures["off"].value == 8

    def test_containing_record_record_returnty(self):
        # the return type is specialized per call site from the matched offset:
        # a pointer to a record struct reserving the leading `off` bytes
        arch = archinfo.arch_from_id("AMD64")
        proto = CONTAINING_RECORD_PATTERN.prototype(arch, const_args={"off": 8})
        assert proto is not None
        assert isinstance(proto.returnty, SimTypePointer)
        record = proto.returnty.pts_to
        assert isinstance(record, SimStruct)
        assert record.name == "record_8"
        gap = record.fields["gap0"]
        assert isinstance(gap, SimTypeArray) and gap.length == 8

        # without the constant values, the declared void* fallback is used
        proto = CONTAINING_RECORD_PATTERN.prototype(arch)
        assert proto is not None
        assert isinstance(proto.returnty, SimTypePointer) and not isinstance(proto.returnty.pts_to, SimStruct)


class TestKnownPatternOutlining(TestCase):
    def test_outline_std_string_length(self):
        proj, cfg, func, dec = _decompile(STL_BIN, "get_len")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        result = finder.outline(finder.matches[0])

        # the callee interface is exactly the string pointer
        assert len(result.child_funcargs) == 1
        assert result.child_funcargs[0].varid == finder.matches[0].captures["s"].varid
        # the child graph contains the lifted load
        child_stmts = [s for b in result.child_graph for s in b.statements]
        assert any(isinstance(getattr(s, "src", None), Load) for s in child_stmts)

        dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
        text = dec_outer.codegen.text
        assert "std::string::length(" in text
        assert "+ 8" not in text
        # the type hint reached Typehoon: the argument is typed as std::string*
        assert "std::string *" in text

    def test_outline_std_vector_size(self):
        proj, cfg, func, dec = _decompile(STL_BIN, "get_size")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        result = finder.outline(finder.matches[0])

        dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
        text = dec_outer.codegen.text
        assert "std::vector<int>::size(" in text
        assert "std::vector<int> *" in text

    def test_outline_containing_record(self):
        proj, cfg, func, dec = _decompile(CR_BIN, "sum_list")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(
            func, dec.ail_graph, patterns=[CONTAINING_RECORD_PATTERN]
        )
        result = finder.outline(finder.matches[0])

        dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
        text = dec_outer.codegen.text
        assert "CONTAINING_RECORD(" in text
        # the field offset is rendered as the second argument
        assert "8)" in text or ", 8" in text

    def test_outline_at(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_len")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        m = finder.matches[0]
        result = finder.outline_at(m.block_loc, STD_STRING_LENGTH, dec.ail_graph)
        assert any(
            getattr(s, "src", None) is not None and getattr(s.src, "target", None) == "std::string::length"
            for b in result.graph
            for s in b.statements
        )


class TestKnownPatternPipeline(TestCase):
    def test_automatic_pipeline(self):
        # with the "full" preset, patterns are outlined automatically in a
        # single decompilation and types flow into Typehoon in the same run
        _, _, _, dec = _decompile(STL_BIN, "get_len", preset="full")
        text = dec.codegen.text
        assert "std::string::length(" in text
        assert "std::string *" in text

        _, _, _, dec = _decompile(STL_BIN, "get_size", preset="full")
        text = dec.codegen.text
        assert "std::vector<int>::size(" in text
        assert "std::vector<int> *" in text

        _, _, _, dec = _decompile(STL_BIN, "get_size_ll", preset="full")
        text = dec.codegen.text
        assert "std::vector<long long>::size(" in text
        assert "std::vector<long long> *" in text

    def test_automatic_pipeline_no_false_positives(self):
        # a plain C binary decompiled with the full preset must not grow any
        # known-pattern calls
        bin_path = os.path.join(bin_location, "tests", "x86_64", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for func in cfg.functions.values():
            if func.is_simprocedure or func.is_plt or func.is_alignment:
                continue
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
            if dec.codegen is None or dec.codegen.text is None:
                continue
            assert "std::string::length(" not in dec.codegen.text
            assert "std::vector<int>::size(" not in dec.codegen.text
            assert "CONTAINING_RECORD(" not in dec.codegen.text


if __name__ == "__main__":
    unittest.main()
