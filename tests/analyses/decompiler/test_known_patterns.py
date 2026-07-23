from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import archinfo

import angr
from angr.ailment.expression import Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import SideEffectStatement
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    CONTAINING_RECORD_PATTERN,
    STD_STRING_LENGTH,
    STD_VECTOR_INT_SIZE,
    KnownPatternFinder,
)
from angr.analyses.decompiler.known_patterns.context import LIBSTDCXX, MSVC, PatternContext
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimStruct, SimTypeArray, SimTypePointer
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
CR_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_containing_record.exe")
MB_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_multiblock")
# statically-linked, stripped MSVC C++ binary: no msvcp dependency, no mangled
# symbols — its C++-ness is only evident from RTTI type descriptors in data.
STATIC_MSVC_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_msvc_string_cstr.exe")


def _ctx(bits=64, runtime=LIBSTDCXX, platform="linux", arch="AMD64"):
    return PatternContext(arch, bits, bits // 8, platform, runtime, runtime is not None)


# concrete patterns for the AMD64/libstdc++ context, used by the DSL-unit tests
_AMD64_CTX = _ctx()
_STRLEN = STD_STRING_LENGTH.instantiate(_AMD64_CTX)
_VECSIZE = STD_VECTOR_INT_SIZE.instantiate(_AMD64_CTX)


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
    del dec.kb.dec_variables.function_managers[func.addr]
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
        state = _STRLEN.pattern.match(load, MatchState(), MatchCtx())
        assert state is not None
        assert state.bindings["s"].likes(s)

        # commutativity: Const + vvar also matches
        load_swapped = Load(None, BinaryOp(None, "Add", [Const(None, 8, 64), s]), 8, "Iend_LE")
        assert _STRLEN.pattern.match(load_swapped, MatchState(), MatchCtx()) is not None

        # wrong offset does not match
        load_bad = Load(None, BinaryOp(None, "Add", [s, Const(None, 16, 64)]), 8, "Iend_LE")
        assert _STRLEN.pattern.match(load_bad, MatchState(), MatchCtx()) is None

    def test_string_length_template_is_context_aware(self):
        # one template instantiates the right layout for each context
        s = VirtualVariable(None, 7, 64, VirtualVariableCategory.PARAMETER)
        from angr.ailment.expression import BinaryOp, Const

        load16 = Load(None, BinaryOp(None, "Add", [s, Const(None, 16, 64)]), 8, "Iend_LE")
        load8 = Load(None, BinaryOp(None, "Add", [s, Const(None, 8, 64)]), 8, "Iend_LE")

        gcc = STD_STRING_LENGTH.instantiate(_ctx(runtime=LIBSTDCXX))
        msvc = STD_STRING_LENGTH.instantiate(_ctx(runtime=MSVC, platform="windows"))
        # libstdc++ matches +8, MSVC matches +16
        assert gcc.pattern.match(load8, MatchState(), MatchCtx()) is not None
        assert gcc.pattern.match(load16, MatchState(), MatchCtx()) is None
        assert msvc.pattern.match(load16, MatchState(), MatchCtx()) is not None
        assert msvc.pattern.match(load8, MatchState(), MatchCtx()) is None

        # applicability is on the template, keyed by context
        assert STD_STRING_LENGTH.applicable(_ctx(runtime=LIBSTDCXX))
        assert STD_STRING_LENGTH.applicable(_ctx(runtime=MSVC, platform="windows"))
        assert not STD_STRING_LENGTH.applicable(_ctx(runtime=None))  # not C++

    def test_cxx_runtime_detection(self):
        from angr.analyses.decompiler.known_patterns.context import detect_cxx_runtime

        # the mingw PE is a C binary
        assert detect_cxx_runtime(angr.Project(CR_BIN, auto_load_libs=False)) is None
        # the g++ ELF is libstdc++
        assert detect_cxx_runtime(angr.Project(STL_BIN, auto_load_libs=False)) == LIBSTDCXX
        # a statically-linked, stripped MSVC binary has no msvcp dependency and no
        # mangled symbols; it is still recognized via RTTI type descriptors in data
        assert detect_cxx_runtime(angr.Project(STATIC_MSVC_BIN, auto_load_libs=False)) == MSVC

    def test_register_rejects_duplicate_call_name(self):
        from angr.analyses.decompiler.known_patterns import make_template, register_pattern_template

        dup = make_template("std::string::length", lambda ctx: None)
        with self.assertRaises(ValueError):
            register_pattern_template(dup)

    def test_pphi_and_pcondjump(self):
        from angr.ailment.expression import BinaryOp, Const, Phi
        from angr.ailment.statement import ConditionalJump, Store
        from angr.analyses.decompiler.known_patterns import PBinOp, PCondJump, PConst, PPhi, PVVar

        v = VirtualVariable(None, 7, 64, VirtualVariableCategory.PARAMETER)
        phi = Phi(None, 64, [((0x400000, None), v), ((0x400010, None), None)])
        assert PPhi("p").match(phi, MatchState(), MatchCtx()) is not None
        # a non-phi expression does not match
        assert PPhi().match(v, MatchState(), MatchCtx()) is None

        cj = ConditionalJump(
            None, BinaryOp(None, "CmpEQ", [v, Const(None, 0, 64)]), Const(None, 1, 64), Const(None, 2, 64)
        )
        pat = PCondJump(PBinOp("CmpEQ", (PVVar("c"), PConst(0))))
        st = pat.match(cj, MatchState(), MatchCtx())
        assert st is not None and st.bindings["c"].likes(v)
        # a non-conditional-jump statement does not match
        assert pat.match(Store(None, v, v, 8, "Iend_LE"), MatchState(), MatchCtx()) is None

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

        assert _VECSIZE.pattern.match(size_expr(v, v), MatchState(), MatchCtx()) is not None
        # unification: _M_finish and _M_start must be loaded off the same vvar
        assert _VECSIZE.pattern.match(size_expr(v, other), MatchState(), MatchCtx()) is None


class TestKnownPatternFinder(TestCase):
    def test_find_std_string_length(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_len")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.pattern.name == "std_string_length"
        assert isinstance(m.captures["s"], VirtualVariable)
        assert isinstance(m.matched_expr, Load)

    def test_find_std_vector_size(self):
        proj, _, func, dec = _decompile(STL_BIN, "get_size")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        # the std::string::length sub-pattern also matches the _M_finish load;
        # the larger vector-size match must win
        assert m.pattern.name == "std_vector_int_size"
        assert isinstance(m.captures["v"], VirtualVariable)

    def test_find_std_vector_size_variants(self):
        for func_name, expected_pattern in (
            ("get_size_s", "std_vector_short_size"),
            ("get_size_ll", "std_vector_long_long_size"),
        ):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(STL_BIN, func_name)
                finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
                assert len(finder.matches) == 1
                assert finder.matches[0].pattern.name == expected_pattern

    def test_find_containing_record(self):
        proj, _, func, dec = _decompile(CR_BIN, "sum_list")
        # CONTAINING_RECORD is not enabled by default
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern.name == "containing_record" for m in finder.matches)
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
        cr = CONTAINING_RECORD_PATTERN.instantiate(_AMD64_CTX)
        proto = cr.prototype(arch, const_args={"off": 8})
        assert proto is not None
        assert isinstance(proto.returnty, SimTypePointer)
        record = proto.returnty.pts_to
        assert isinstance(record, SimStruct)
        assert record.name == "record_8"
        gap = record.fields["gap0"]
        assert isinstance(gap, SimTypeArray) and gap.length == 8

        # without the constant values, the declared void* fallback is used
        proto = cr.prototype(arch)
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


class TestKnownPatternStmtSeq(TestCase):
    def test_find_std_swap(self):
        proj, _, func, dec = _decompile(MB_BIN, "do_swap")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.pattern.name == "std_swap"
        assert m.stmt_span is not None and len(m.stmt_span) == 3
        assert m.matched_expr is None and m.expr_path == ()
        assert isinstance(m.captures["a"], VirtualVariable)
        assert isinstance(m.captures["b"], VirtualVariable)
        assert m.captures["a"].varid != m.captures["b"].varid

    def test_outline_std_swap(self):
        proj, cfg, func, dec = _decompile(MB_BIN, "do_swap")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        result = finder.outline(finder.matches[0])

        # a void call: rendered as a bare statement, not an assignment
        assert isinstance(result.call_stmt, SideEffectStatement)
        assert len(result.child_funcargs) == 2
        # the child contains the two stores
        from angr.ailment.statement import Store

        child_stmts = [s for b in result.child_graph for s in b.statements]
        assert sum(1 for s in child_stmts if isinstance(s, Store)) == 2

        dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
        text = dec_outer.codegen.text
        assert "std::swap(" in text
        assert "*(" not in text  # the loads/stores moved into the callee

    def test_automatic_pipeline_std_swap(self):
        _, _, _, dec = _decompile(MB_BIN, "do_swap", preset="full")
        text = dec.codegen.text
        assert "std::swap(" in text


def _route_graph_pattern():
    from angr.analyses.decompiler.known_patterns import (
        KnownPattern,
        PatternParam,
        PBinOp,
        PBlockPat,
        PCondJump,
        PConst,
        PGraphPat,
        PStmtSeq,
        PStore,
        PVVar,
    )

    return KnownPattern(
        name="route_demo",
        display_name="route",
        call_name="route",
        pattern=PGraphPat(
            blocks={
                "head": PBlockPat("head", PStmtSeq((PCondJump(PBinOp("CmpEQ", (PVVar("cond"), PConst(0)))),))),
                "then": PBlockPat("then", PStmtSeq((PStore(PVVar("a"), PVVar("v")), PStore(PVVar("c"), PVVar("v"))))),
                "else": PBlockPat("else", PStmtSeq((PStore(PVVar("b"), PVVar("v")), PStore(PVVar("c"), PVVar("v"))))),
            },
            edges=[("head", "then"), ("head", "else"), ("then", "OUT"), ("else", "OUT")],
            entry="head",
        ),
        params=(
            PatternParam("cond"),
            PatternParam("a"),
            PatternParam("b"),
            PatternParam("c"),
            PatternParam("v"),
        ),
        returnty=None,
    )


class TestKnownPatternGraph(TestCase):
    def test_pgraphpat_validation(self):
        from angr.analyses.decompiler.known_patterns import PBlockPat, PGraphPat, PStmtSeq

        empty = PBlockPat("x", PStmtSeq(()))
        # entry not among blocks
        with self.assertRaises(ValueError):
            PGraphPat(blocks={"a": empty}, edges=[], entry="missing")
        # edge source is not an internal block
        with self.assertRaises(ValueError):
            PGraphPat(blocks={"a": empty}, edges=[("bogus", "a")], entry="a")
        # unreachable block
        with self.assertRaises(ValueError):
            PGraphPat(
                blocks={"a": empty, "b": PBlockPat("b", PStmtSeq(()))},
                edges=[("a", "OUT")],
                entry="a",
            )
        # external labels are reported
        gp = PGraphPat(blocks={"a": empty}, edges=[("a", "OUT")], entry="a")
        assert gp.external_labels == {"OUT"}

    def test_find_route_diamond(self):
        proj, _, func, dec = _decompile(MB_BIN, "route")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(
            func, dec.ail_graph, patterns=[_route_graph_pattern()]
        )
        assert len(finder.matches) == 1
        m = finder.matches[0]
        assert m.block_map is not None and set(m.block_map) == {"head", "then", "else"}
        assert m.frontier_locs is not None and len(m.frontier_locs) == 1
        # v (the stored value) unifies across both branches
        assert m.captures["a"].varid != m.captures["b"].varid
        assert isinstance(m.captures["v"], VirtualVariable)

    def test_outline_route_diamond(self):
        proj, cfg, func, dec = _decompile(MB_BIN, "route")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(
            func, dec.ail_graph, patterns=[_route_graph_pattern()]
        )
        result = finder.outline(finder.matches[0])

        # void call rendered as a bare statement
        assert isinstance(result.call_stmt, SideEffectStatement)
        # the region's three blocks moved into the callee
        assert len(list(result.child_graph.nodes)) == 3
        # all five inputs became call arguments
        assert len(result.child_funcargs) == 5

        dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
        text = dec_outer.codegen.text
        assert "route(" in text
        # the if/else diamond is gone from the caller
        assert "else" not in text


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
