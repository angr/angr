from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import re
import unittest
from unittest import TestCase

import archinfo

import angr
from angr.ailment.expression import BinaryOp, Const, Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompilation_options import parse_known_patterns
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    ALL_KNOWN_PATTERN_TEMPLATES,
    CONTAINING_RECORD_PATTERN,
    KERNEL_TARGET,
    LINUX_KERNEL,
    STD_STRING_LENGTH,
    STD_VECTOR_INT_SIZE,
    GateContext,
    KnownPatternFinder,
    TargetGate,
    UnknownPatternError,
    all_of,
    any_of,
    corroborated_by,
    partition_templates,
    resolve_pattern_selection,
)
from angr.analyses.decompiler.known_patterns.context import LIBSTDCXX, MSVC, PatternContext
from angr.analyses.decompiler.known_patterns.dsl import MatchCtx, MatchState
from angr.analyses.decompiler.known_patterns.stl_accessors2 import STD_STRING_FRONT
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimStruct, SimTypeArray, SimTypePointer
from tests.common import bin_location

STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
# std::vector<T>::size() whose chased definitions are still used by other code
STL3_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl3")
# coreutils mv at -O2: copy_internal keeps `st_mode & S_IFMT` in one register and
# tests it from a dozen other blocks -- the CSE'd-mask shape
MV_BIN = os.path.join(bin_location, "tests", "x86_64", "mv_-O2")
CR_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_containing_record.exe")
MB_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_multiblock")
# statically-linked, stripped MSVC C++ binary: no msvcp dependency, no mangled
# symbols — its C++-ness is only evident from RTTI type descriptors in data.
STATIC_MSVC_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_msvc_string_cstr.exe")
# binary-evidence fixtures for the criteria gates
KMOD_BIN = os.path.join(bin_location, "tests", "armel", "btrfs.ko")
DRIVER_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "cancel.sys")
LIST_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_linux_list")
WDK_EXE_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_list.exe")


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


class TestLargestMatchWins(TestCase):
    # Two statement-set matches anchored at the same statement both sit at the
    # expression root, so len(expr_path) cannot separate them. The finder breaks
    # that tie by footprint size, so a superset pattern beats the subset it
    # contains regardless of the order the patterns were registered in.

    @staticmethod
    def _unlink_stmts():
        from angr.analyses.decompiler.known_patterns.dsl import PAssign, PBinOp, PConst, PLoad, PStore, PVVar

        def field(cap, off):
            addr = PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))
            return PLoad(addr, size=8)

        def addr(cap, off):
            return PVVar(cap) if off == 0 else PBinOp("Add", (PVVar(cap), PConst(off)))

        return (
            PAssign(PVVar("prev"), field("entry", 8)),
            PAssign(PVVar("next"), field("entry", 0)),
            PStore(addr("prev", 0), PVVar("next"), size=8),
            PStore(addr("next", 8), PVVar("prev"), size=8),
        ), addr

    @classmethod
    def _subset_and_superset(cls):
        """A 4-statement list unlink, and the 6-statement unlink+re-init that
        strictly contains it (the list_del_init shape)."""
        from angr.analyses.decompiler.known_patterns import KnownPattern, PatternParam
        from angr.analyses.decompiler.known_patterns.dsl import PStmtSeq, PStore, PVVar

        unlink, addr = cls._unlink_stmts()
        subset = KnownPattern(
            name="unlink_only",
            display_name="unlink_only",
            call_name="unlink_only",
            pattern=PStmtSeq(unlink, ordered=False),
            params=(PatternParam("entry"),),
        )
        superset = KnownPattern(
            name="unlink_and_init",
            display_name="unlink_and_init",
            call_name="unlink_and_init",
            pattern=PStmtSeq(
                (
                    *unlink,
                    PStore(addr("entry", 0), PVVar("entry"), size=8),
                    PStore(addr("entry", 8), PVVar("entry"), size=8),
                ),
                ordered=False,
            ),
            params=(PatternParam("entry"),),
        )
        return subset, superset

    def test_superset_wins_in_either_registration_order(self):
        bin_path = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_kernel_macros")
        subset, superset = self._subset_and_superset()
        for order_name, patterns in (
            ("subset first", [subset, superset]),
            ("superset first", [superset, subset]),
        ):
            with self.subTest(order=order_name):
                proj = angr.Project(bin_path, auto_load_libs=False)
                cfg = proj.analyses.CFGFast(normalize=True)
                proj.analyses.CompleteCallingConventions(cfg=cfg.model)
                func = cfg.functions.function(name="k_list_del_init")
                assert func is not None
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
                finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=patterns)
                assert [m.pattern.name for m in finder.matches] == ["unlink_and_init"], (
                    f"{order_name}: {[m.pattern.name for m in finder.matches]}"
                )


class TestSharedChasedDefinitions(TestCase):
    # A chased definition whose value the surrounding code still uses cannot be
    # moved into the outlined callee, and leaving it behind makes the region's
    # live-in the intermediate value instead of the captured pointer -- the
    # callee interface then disagrees with the declared parameters and the match
    # is lost. Such definitions are copied into the region instead.

    def test_shared_chased_defs_are_duplicated(self):
        for func_name, n_dup in (("vec_size_shared_diff", 1), ("vec_size_shared_chain", 2)):
            with self.subTest(func=func_name):
                proj, cfg, func, dec = _decompile(STL3_BIN, func_name)
                finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
                matches = [m for m in finder.matches if m.pattern.name == "std_vector_T12_size"]
                assert len(matches) == 1, [m.pattern.name for m in finder.matches]
                m = matches[0]
                # the chased definitions are shared, so none of them is consumed
                assert not m.consumed_stmt_idxs
                assert len(m.duplicated_stmt_idxs) == n_dup

                block = next(b for b in dec.ail_graph if (b.addr, b.idx) == m.block_loc)
                originals = [block.statements[i] for i in sorted(m.duplicated_stmt_idxs)]
                original_varids = {s.dst.varid for s in originals}

                result = finder.outline(m)
                # the call takes the vector pointer, not the intermediate value
                assert [a.varid for a in result.child_funcargs] == [m.captures["v"].varid]
                # the originals stay in the caller for their other users
                caller_stmts = [s for b in result.graph for s in b.statements]
                for original in originals:
                    assert any(s is original for s in caller_stmts), f"{original} was moved out of the caller"
                # and the copies inside the callee define fresh vvars
                child_defs = {
                    s.dst.varid
                    for b in result.child_graph
                    for s in b.statements
                    if isinstance(s, Assignment) and isinstance(s.dst, VirtualVariable)
                }
                assert len(child_defs & original_varids) == 0, "the duplicated definitions reused their vvar ids"

                dec_outer = _redecompile(proj, cfg, func, dec, result.graph)
                text = dec_outer.codegen.text
                assert "std::vector<T12>::size(" in text, text

    def test_reaching_match_beats_a_sub_pattern_in_its_chased_def(self):
        # std::string::length is a bare Load(s + 8), i.e. exactly the _M_finish
        # load a std::vector<T>::size() reads through; the vector match covers
        # more of the block and must be the one that is offered.
        proj, _, func, dec = _decompile(STL3_BIN, "vec_size_shared_chain")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert [m.pattern.name for m in finder.matches] == ["std_vector_T12_size"]


class TestRemoteChasedDefinitions(TestCase):
    # An idiom's intermediate value is routinely computed once and consumed from
    # several *other* blocks -- the CSE'd `mode & S_IFMT` feeding an if-chain of
    # S_IS* tests is the canonical case, and on real code it accounts for about
    # half of all S_IS* misses. The same-block chase cannot see such a definition
    # at all, so no block contains the whole idiom and every arm of the chain is
    # lost. Because the computation is pure, the outlined region can recompute it.

    def test_cse_mask_feeding_an_if_chain_is_matched(self):
        proj, _, func, dec = _decompile(MV_BIN, "copy_internal")
        with_remote = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        without = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, chase_remote_defs=False)
        recomputed = [m for m in with_remote.matches if m.recomputed_defs]
        assert recomputed, "no match reached its operand through a definition in another block"
        assert len(with_remote.matches) > len(without.matches)
        assert all(m.pattern.name.startswith("s_is") for m in recomputed)

        # every recomputed definition is the shared mask itself, and it is left
        # where it is -- nothing is consumed out of the anchor block
        for m in recomputed:
            assert not m.consumed_stmt_idxs and not m.duplicated_stmt_idxs
            for _varid, expr in m.recomputed_defs:
                assert isinstance(expr, BinaryOp) and expr.op == "And"
                assert any(isinstance(o, Const) and o.value == 0o170000 for o in expr.operands)

    def test_recomputed_definition_is_outlined_into_the_callee(self):
        proj, _, func, dec = _decompile(MV_BIN, "copy_internal")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        m = next(m for m in finder.matches if m.recomputed_defs)
        block = next(b for b in dec.ail_graph if (b.addr, b.idx) == m.block_loc)
        before = list(block.statements)

        result = finder.outline(m)
        # the call takes the mode, not the masked intermediate the block sees
        assert [a.varid for a in result.child_funcargs] == [m.captures["mode"].varid]
        # the mask is recomputed inside the callee, on a fresh vvar id
        child_defs = [
            s
            for b in result.child_graph
            for s in b.statements
            if isinstance(s, Assignment) and isinstance(s.src, BinaryOp)
        ]
        assert any(
            s.src.op == "And" and any(isinstance(o, Const) and o.value == 0o170000 for o in s.src.operands)
            for s in child_defs
        )
        assert all(s.dst.varid != varid for s in child_defs for varid, _ in m.recomputed_defs)
        # and the anchor block keeps every statement it had apart from the anchor
        kept = [s for b in result.graph for s in b.statements]
        for stmt in before[: m.anchor_stmt_idx]:
            assert any(s is stmt for s in kept), f"{stmt} was moved out of the caller"


class TestOutlinedResultIdentity(TestCase):
    # Two regressions in _rewrite_callsite / outline(), both reachable as soon as a
    # pattern's result is narrower than the return register, or a function contains
    # more than one outlined match. Uses ad-hoc absolute-address load patterns so the
    # test does not depend on any particular shipped pattern.

    KSUD_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_ksud.exe")

    @staticmethod
    def _abs_load_pattern(name: str, addr: int, size: int):
        """A nullary accessor: a fixed-size load from an absolute address."""
        from angr.analyses.decompiler.known_patterns import KnownPattern
        from angr.analyses.decompiler.known_patterns.dsl import PConst, PLoad

        return KnownPattern(
            name=name,
            display_name=name,
            call_name=name,
            pattern=PLoad(PConst(addr), size=size),
            params=(),
            returnty="unsigned int",
        )

    def _decompile_full(self, patterns, func_name):
        from angr.analyses.decompiler.known_patterns import ALL_KNOWN_PATTERN_TEMPLATES, TEMPLATE_BY_CALL_NAME
        from angr.analyses.decompiler.known_patterns.templates import make_template

        def _const_build(pat):
            return lambda ctx: pat

        templates = [make_template(p.call_name, _const_build(p)) for p in patterns]
        saved, saved_map = list(ALL_KNOWN_PATTERN_TEMPLATES), dict(TEMPLATE_BY_CALL_NAME)
        ALL_KNOWN_PATTERN_TEMPLATES[:] = templates
        TEMPLATE_BY_CALL_NAME.clear()
        TEMPLATE_BY_CALL_NAME.update({t.call_name: t for t in templates})
        try:
            proj = angr.Project(self.KSUD_BIN, auto_load_libs=False)
            cfg = proj.analyses.CFGFast(normalize=True)
            proj.analyses.CompleteCallingConventions(cfg=cfg.model)
            func = cfg.functions.function(name=func_name)
            assert func is not None
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
            assert dec.codegen is not None and dec.codegen.text is not None
            return dec.codegen.text
        finally:
            ALL_KNOWN_PATTERN_TEMPLATES[:] = saved
            TEMPLATE_BY_CALL_NAME.clear()
            TEMPLATE_BY_CALL_NAME.update(saved_map)

    def test_two_outlined_results_stay_distinct(self):
        # every AIL object built with idx=None lands at index 0, and the decompiler's
        # VariableMap is keyed by index -- so two outlined results used to collide
        # there and render as the same C variable, silently changing the arithmetic.
        text = self._decompile_full(
            [
                self._abs_load_pattern("KsudMajor", 0x7FFE026C, 4),
                self._abs_load_pattern("KsudMinor", 0x7FFE0270, 4),
            ],
            "ksud_version_combined",
        )
        assert "KsudMajor(" in text and "KsudMinor(" in text, text
        major = re.search(r"(\w+) = KsudMajor\(\)", text)
        minor = re.search(r"(\w+) = KsudMinor\(\)", text)
        assert major is not None and minor is not None, text
        assert major.group(1) != minor.group(1), f"both outlined results collapsed into one variable:\n{text}"

    def test_subword_result_widths(self):
        # 1- and 2-byte pattern results outline cleanly. (The width mismatch itself
        # is pinned by test_two_outlined_results_stay_distinct, which crashes in
        # variable recovery without the fix because it uses the result in
        # arithmetic; these two only need the result to survive codegen.)
        for func_name, addr, size in (
            ("ksud_image_number_low", 0x7FFE002C, 2),
            ("ksud_kd_debugger_enabled", 0x7FFE02D4, 1),
        ):
            with self.subTest(func=func_name):
                text = self._decompile_full([self._abs_load_pattern("KsudField", addr, size)], func_name)
                assert "KsudField(" in text, text


class TestPITE(TestCase):
    # ITERegionConverter (AFTER_GLOBAL_SIMPLIFICATION) folds a two-armed value
    # select into `x = c ? a : b` before the KnownPatternOutliner
    # (BEFORE_VARIABLE_RECOVERY) runs, so such idioms reach the matcher as an ITE
    # expression and a PGraphPat for them can never fire.

    STL2_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl2")

    def test_anchor_key_is_ite(self):
        from angr.analyses.decompiler.known_patterns import PITE
        from angr.analyses.decompiler.known_patterns.dsl import PConst, PVVar, pattern_anchor_key

        assert pattern_anchor_key(PITE(PVVar("c"), PConst(1), PConst(2))) == ("ITE", None)

    def test_pchoice_keeps_a_shared_anchor_key(self):
        # a PChoice is usually a polarity alternation of one shape; when every
        # alternative discriminates the same way, pruning must be preserved
        from angr.analyses.decompiler.known_patterns import PChoice
        from angr.analyses.decompiler.known_patterns.dsl import PBinOp, PConst, PLoad, PVVar, pattern_anchor_key

        same = PChoice(
            PBinOp("CmpEQ", (PVVar("a"), PConst(0))),
            PBinOp("CmpEQ", (PVVar("a"), PConst(1))),
        )
        assert pattern_anchor_key(same) == ("BinaryOp", "CmpEQ")
        mixed = PChoice(PBinOp("CmpEQ", (PVVar("a"), PConst(0))), PLoad(PVVar("a")))
        assert pattern_anchor_key(mixed) is None

    def test_pite_matches_a_converted_select(self):
        from angr.analyses.decompiler.known_patterns import (
            PITE,
            KnownPattern,
            KnownPatternFinder,
            PatternParam,
            PBinOp,
            PConst,
            PLoad,
            PVVar,
        )

        # the libstdc++ SSO capacity select: _M_p == &_M_local_buf ? 15 : _M_allocated_capacity
        local_buf = PBinOp("Add", (PVVar("s"), PConst(16)))
        pat = KnownPattern(
            name="sso_capacity",
            display_name="sso_capacity",
            call_name="sso_capacity",
            pattern=PITE(
                PBinOp("CmpEQ", (PLoad(PVVar("s"), size=8), local_buf)),
                PConst(15),
                PLoad(local_buf, size=8),
            ),
            params=(PatternParam("s"),),
            returnty="unsigned long long",
        )
        proj = angr.Project(self.STL2_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name="str_capacity")
        assert func is not None
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=[pat])
        assert [m.pattern.name for m in finder.matches] == ["sso_capacity"]


class TestPatternSelection(TestCase):
    # Feature 1: the user-facing force-enable selection. Names resolve against the
    # registry by call name or short name; an unknown name is an error, never a
    # silent no-op.

    def test_all_selects_every_template(self):
        assert resolve_pattern_selection("all") == ALL_KNOWN_PATTERN_TEMPLATES
        assert resolve_pattern_selection(["ALL"]) == ALL_KNOWN_PATTERN_TEMPLATES

    def test_nothing_selects_nothing(self):
        assert resolve_pattern_selection(None) == []
        assert resolve_pattern_selection([]) == []
        assert resolve_pattern_selection("") == []

    def test_names_resolve_by_call_name_or_short_name(self):
        # std::string::front is registered under call name "std::string::front"
        # and short name "std_string_front"; both must select it
        by_call = resolve_pattern_selection(["std::string::front"])
        by_name = resolve_pattern_selection(["std_string_front"])
        assert by_call == by_name == [STD_STRING_FRONT]

    def test_comma_separated_string(self):
        selected = resolve_pattern_selection("IsListEmpty, std::string::front")
        assert [t.call_name for t in selected] == ["IsListEmpty", "std::string::front"]

    def test_duplicates_are_collapsed(self):
        assert resolve_pattern_selection(["std::string::front", "std_string_front"]) == [STD_STRING_FRONT]

    def test_unknown_name_raises(self):
        # hlist_empty was measured at 24 false positives in /bin/ls and never shipped
        with self.assertRaises(UnknownPatternError) as cm:
            resolve_pattern_selection(["std::string::front", "hlist_empty"])
        assert "hlist_empty" in str(cm.exception)

    def test_option_value_normalization(self):
        assert parse_known_patterns(None) is None
        assert parse_known_patterns("") is None
        assert parse_known_patterns("  all ") == "all"
        assert parse_known_patterns(["all"]) == "all"
        assert parse_known_patterns("a, b ,c") == ("a", "b", "c")
        assert parse_known_patterns(["a", "b"]) == ("a", "b")

    def test_decompiler_rejects_an_unknown_name(self):
        # the decompilation itself runs under _resilience() and retries with the
        # basic preset, so a bad name has to be rejected before that
        proj = angr.Project(STL_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        func = cfg.functions.function(name="str_index")
        with self.assertRaises(UnknownPatternError):
            proj.analyses[Decompiler].prep(fail_fast=True)(
                func, cfg=cfg.model, preset="full", options=[("known_patterns", ["no_such_pattern"])]
            )


class TestForceEnableDuringDecompilation(TestCase):
    # An opt-in pattern must stay off in a normal full-preset run and fire when
    # the user force-enables it through the known_patterns option.

    @classmethod
    def setUpClass(cls):
        cls.proj = angr.Project(STL_BIN, auto_load_libs=False)
        cls.cfg = cls.proj.analyses.CFGFast(normalize=True)
        cls.proj.analyses.CompleteCallingConventions(cfg=cls.cfg.model)

    def _text(self, func_name, options=None):
        func = self.cfg.functions.function(name=func_name)
        assert func is not None
        dec = self.proj.analyses[Decompiler].prep(fail_fast=True)(
            func, cfg=self.cfg.model, preset="full", options=options
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_string_index_is_opt_in(self):
        assert "std::string::operator[](" not in self._text("str_index")

    def test_string_index_with_all_patterns(self):
        assert "std::string::operator[](" in self._text("str_index", [("known_patterns", "all")])

    def test_string_index_by_name(self):
        assert "std::string::operator[](" in self._text("str_index", [("known_patterns", ["std::string::operator[]"])])

    def test_selecting_another_pattern_does_not_enable_this_one(self):
        # the selection is exact: naming an unrelated opt-in pattern leaves
        # operator[] off
        assert "std::string::operator[](" not in self._text("str_index", [("known_patterns", ["IsListEmpty"])])


class TestBinaryEvidence(TestCase):
    # Feature 2, target evidence: the facts PatternContext derives about what kind
    # of program this is.

    def test_linux_kernel_module(self):
        proj = angr.Project(KMOD_BIN, auto_load_libs=False)
        ctx = PatternContext.from_project(proj)
        assert ctx.is_linux_kernel_object
        assert not ctx.is_windows_kernel_driver

    def test_windows_kernel_driver(self):
        proj = angr.Project(DRIVER_BIN, auto_load_libs=False)
        ctx = PatternContext.from_project(proj)
        assert ctx.is_windows_kernel_driver
        assert not ctx.is_linux_kernel_object

    def test_user_space_binaries_are_neither(self):
        # a user-space ELF that uses list_head, and a user-space PE that uses
        # LIST_ENTRY: the idioms are there, the kernel evidence is not
        for path in (LIST_BIN, WDK_EXE_BIN):
            with self.subTest(binary=os.path.basename(path)):
                ctx = PatternContext.from_project(angr.Project(path, auto_load_libs=False))
                assert not ctx.is_linux_kernel_object
                assert not ctx.is_windows_kernel_driver

    def _gate_opened(self, path):
        proj = angr.Project(path, auto_load_libs=False)
        gctx = GateContext(ctx=PatternContext.from_project(proj), project=proj)
        enabled, _ = partition_templates(gctx)
        return {t.call_name for t in enabled if not t.enabled_by_default}

    def test_kernel_gate_opens_the_list_family(self):
        driver = self._gate_opened(DRIVER_BIN)
        module = self._gate_opened(KMOD_BIN)
        assert {"IsListEmpty", "InitializeListHead", "RemoveEntryList"} <= driver
        # the poisoned-unlink supersets and IS_ERR are Linux-only evidence
        assert "list_del" not in driver and "IS_ERR" not in driver
        assert {"list_del", "list_del_init", "hlist_del", "IS_ERR", "IS_ERR_OR_NULL"} <= module

    def test_gates_stay_shut_on_user_space_binaries(self):
        for path in (LIST_BIN, WDK_EXE_BIN, STL_BIN):
            with self.subTest(binary=os.path.basename(path)):
                assert self._gate_opened(path) == set()


class TestGateObjects(TestCase):
    # Feature 2, the gate primitives themselves.

    def test_corroboration_gate(self):
        gate = corroborated_by("std::string::length", "std::string::capacity")
        assert gate.requires_evidence
        ctx = GateContext(ctx=_AMD64_CTX)
        assert not gate(ctx)
        assert not gate(ctx.with_evidence({"std::vector<int>::size"}))
        assert gate(ctx.with_evidence({"std::string::length"}))

    def test_target_gate_needs_no_evidence(self):
        assert not LINUX_KERNEL.requires_evidence
        assert not KERNEL_TARGET.requires_evidence

    def test_combinators(self):
        yes = TargetGate("yes", lambda _: True)
        no = TargetGate("no", lambda _: False)
        ctx = GateContext(ctx=_AMD64_CTX)
        assert any_of(no, yes)(ctx)
        assert not any_of(no, no)(ctx)
        assert all_of(yes, yes)(ctx)
        assert not all_of(yes, no)(ctx)
        # a combinator needs evidence iff one of its members does
        assert any_of(no, corroborated_by("x")).requires_evidence
        assert not any_of(no, yes).requires_evidence

    def test_a_gate_never_disables_a_default_on_template(self):
        # enabled_for() is only consulted for opt-in templates
        assert STD_STRING_LENGTH.enabled_by_default
        assert STD_STRING_LENGTH.enabled_for(GateContext(ctx=_AMD64_CTX))
        assert not STD_STRING_FRONT.enabled_for(GateContext(ctx=_AMD64_CTX))


class TestUnderscorePrefixedMangling(TestCase):
    # 32-bit PE and Mach-O prefix every symbol with an underscore, so an
    # Itanium-mangled name arrives as "__ZNSt...". Matching only "_Z" made
    # detect_cxx_runtime report "c" for an i386 mingw C++ binary, which silently
    # declined every languages=("cpp",) template -- reading as a flat 0% recall
    # for all libstdc++ families on that arm rather than as a detection failure.

    def test_double_underscore_mangling_is_cpp(self):
        from angr.analyses.decompiler.known_patterns.context import LIBSTDCXX, _mangled_symbol_prefixes

        class _Sym:
            def __init__(self, name):
                self.name = name

        class _Obj:
            deps = []

            def __init__(self, names):
                self.symbols = [_Sym(n) for n in names]

        assert "_Z" in _mangled_symbol_prefixes(
            type("P", (), {"loader": type("L", (), {"main_object": _Obj(["__ZNSt6vectorIiE9push_backEi"])})()})()
        )
        assert "_Z" in _mangled_symbol_prefixes(
            type("P", (), {"loader": type("L", (), {"main_object": _Obj(["_ZNSt6vectorIiE9push_backEi"])})()})()
        )
        assert LIBSTDCXX == "libstdcxx"

    def test_msvc_x86_binary_still_detects_msvc(self):
        bin_path = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_stl_msvc_17_x86.exe")
        from angr.analyses.decompiler.known_patterns.context import MSVC, detect_cxx_runtime

        assert detect_cxx_runtime(angr.Project(bin_path, auto_load_libs=False)) == MSVC


class TestMemberContainers(TestCase):
    # PField: a container that is a *field of another object* rather than the
    # thing a register points at. Templates that spell their fields as
    # `Load(PVVar("v") + off)` require the object to sit at offset 0, which over
    # the benchmark corpus is only 10-25% of the DWARF sites for a vector
    # accessor -- `this->items.size()` lifts to `Load(this + 8)` /
    # `Load(this + 16)` and could not bind `v` at all.
    #
    # The two field displacements still constrain each other, so the pattern is
    # no less specific; the outliner materializes `tmp = this + K` ahead of the
    # region so the synthesized call keeps taking a variable, and `tmp` is what
    # carries the container's type.

    STL4_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl4")

    def test_pfield_binds_the_object_not_the_pointer(self):
        from angr.ailment.expression import BinaryOp, Const, VirtualVariable, VirtualVariableCategory
        from angr.analyses.decompiler.known_patterns.dsl import PField

        this = VirtualVariable(None, 7, 64, VirtualVariableCategory.REGISTER, oident=16)
        addr = BinaryOp(None, "Add", [this, Const(None, 16, 64)], False)

        # a field at +8 reached through `this + 16` means the object is at +8
        st = PField("v", 8).match(addr, MatchState(), MatchCtx())
        assert st is not None
        base = st.bindings["v"]
        assert isinstance(base, BinaryOp) and base.op == "Add"
        assert base.operands[1].value == 8

        # the same address as the +16 field pins the object at offset 0
        st = PField("v", 16).match(addr, MatchState(), MatchCtx())
        assert st is not None and st.bindings["v"].likes(this)

        # two fields of one object must agree on where the object starts
        st = PField("v", 0).match(this, MatchState(), MatchCtx())
        assert st is not None
        assert PField("v", 8).match(addr, st, MatchCtx()) is None  # would put it at +8
        assert PField("v", 16).match(addr, st, MatchCtx()) is not None

    def test_pfield_rejects_a_negative_object_offset(self):
        # without this a bare `Load(p)` would satisfy a field at +8, and
        # std::string::length would match every one-word load in the binary
        from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
        from angr.analyses.decompiler.known_patterns.dsl import PField

        p = VirtualVariable(None, 7, 64, VirtualVariableCategory.REGISTER, oident=16)
        assert PField("v", 8).match(p, MatchState(), MatchCtx()) is None

    def test_member_vector_size(self):
        _, _, _, dec = _decompile(self.STL4_BIN, "doc_item_count", preset="full")
        text = dec.codegen.text
        assert "std::vector<long long>::size(" in text
        # the object pointer is computed into a variable of its own, and it --
        # not the enclosing Doc * -- is what carries the container type
        assert "std::vector<long long> *" in text

    def test_member_vector_empty(self):
        # empty() is gated on a size/capacity witness (see
        # TestStlContainerPatterns), and doc_items_empty contains nothing else --
        # so force it on to test the *base* shape, which is what this class is about
        proj, cfg, func, _ = _decompile(self.STL4_BIN, "doc_items_empty", preset="fast")
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            func,
            cfg=cfg.model,
            preset="full",
            options=[("known_patterns", ["std::vector<int>::empty"])],
        )
        assert "std::vector<int>::empty(" in dec.codegen.text

    def test_member_string_capacity(self):
        # the SSO select on a member string: _M_p at this+32 tested against the
        # local buffer at this+48
        _, _, _, dec = _decompile(self.STL4_BIN, "doc_name_capacity", preset="full")
        text = dec.codegen.text
        assert "std::string::capacity(" in text
        assert "std::string *" in text

    def test_member_string_back(self):
        _, _, _, dec = _decompile(self.STL4_BIN, "doc_name_back", preset="full")
        assert "std::string::back(" in dec.codegen.text


class TestVectorElementSizes(TestCase):
    # size()/capacity()/operator[] carry sizeof(T) in their divisor or scale, so
    # each needs a template per element size. Three gaps, each measured against
    # the benchmark corpus:
    #   capacity() had only the 4-byte template, and the corpus contains ZERO
    #     4-byte-element capacity sites -- it could not fire at all;
    #   operator[] likewise, against 78% of sites being 8-byte elements;
    #   size() covered powers of two only up to 8, so std::vector<std::string>
    #     (sizeof == 32) -- the corpus' most common element type -- was missed.

    STL4_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl4")

    def test_capacity_is_generated_per_element_size(self):
        from angr.analyses.decompiler.known_patterns import STD_VECTOR_CAPACITY_TEMPLATES

        names = {t.call_name for t in STD_VECTOR_CAPACITY_TEMPLATES}
        assert "std::vector<int>::capacity" in names
        assert "std::vector<long long>::capacity" in names
        assert "std::vector<T32>::capacity" in names  # a power of two above 8
        assert "std::vector<T112>::capacity" in names  # exact-division magic

    def test_member_vector_capacity(self):
        # 8-byte elements: unrepresentable before, since only int existed
        _, _, _, dec = _decompile(self.STL4_BIN, "doc_items_capacity", preset="full")
        assert "std::vector<long long>::capacity(" in dec.codegen.text

    def test_power_of_two_element_above_eight(self):
        # sizeof(std::string) == 32 -> a bare `>> 5` with no named element type
        _, _, _, dec = _decompile(self.STL4_BIN, "names_count", preset="full")
        assert "std::vector<T32>::size(" in dec.codegen.text

    def test_index_with_an_eight_byte_element(self):
        proj, cfg, func, _ = _decompile(self.STL4_BIN, "items_at", preset="fast")
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            func,
            cfg=cfg.model,
            preset="full",
            options=[("known_patterns", ["std::vector<long long>::operator[]"])],
        )
        assert "std::vector<long long>::operator[](" in dec.codegen.text


class TestSwapWidthsAndInterleaving(TestCase):
    # std::swap fired zero times over the whole benchmark corpus, for two
    # independent reasons:
    #
    #   the template was word-sized only, and pointer-sized T is 8% of the
    #   DWARF records for std::swap<T> (int is 11%, the rest are 1-byte types,
    #   doubles and small structs);
    #
    #   the outliner refused any match with a memory-touching statement between
    #   its statements -- and an instruction scheduler *always* interleaves the
    #   next field's load between this field's store and its writeback, so the
    #   idiom was found and then thrown away. The veto is now a disjointness
    #   test on (base, offset, size) intervals.

    STL4_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl4")

    def test_both_statement_orders_are_generated(self):
        # the scheduled order -- both loads hoisted -- is a separate shape, and it
        # is the one an optimizing compiler actually emits
        from angr.analyses.decompiler.known_patterns import STD_SWAP_TEMPLATES

        names = {t.name for t in STD_SWAP_TEMPLATES}
        assert "std_swap_8" in names
        assert "std_swap_8_scheduled" in names
        # narrower widths are deliberately absent: a statement pattern is tried at
        # every statement of every block, so each extra one multiplies a quadratic
        # term, and a three-statement byte shuffle matches a great deal of code
        # that is not a swap. See _SWAP_WIDTHS.
        assert not any(n.startswith(("std_swap_1", "std_swap_2", "std_swap_4")) for n in names)

    def test_interleaved_field_swap(self):
        _, _, _, dec = _decompile(self.STL4_BIN, "pair_swap", preset="full")
        assert "std::swap(" in dec.codegen.text, dec.codegen.text

    def test_disjointness_admits_a_nonaliasing_gap(self):
        # a read of `*(b + 8)` between a write of `*a` and a write of `*b`
        from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
        from angr.ailment.statement import Assignment, Store
        from angr.analyses.decompiler.known_patterns.finder import KnownPatternFinder as F

        a = VirtualVariable(None, 1, 64, VirtualVariableCategory.PARAMETER)
        b = VirtualVariable(None, 2, 64, VirtualVariableCategory.PARAMETER)
        t = VirtualVariable(None, 3, 32, VirtualVariableCategory.REGISTER, oident=16)
        store_a = Store(None, a, VirtualVariable(None, 4, 64, VirtualVariableCategory.REGISTER, oident=8), 8, "Iend_LE")
        gap_far = Assignment(None, t, Load(None, BinaryOp(None, "Add", [b, Const(None, 8, 64)]), 4, "Iend_LE"))
        gap_near = Assignment(None, t, Load(None, b, 4, "Iend_LE"))

        region = [F._mem_accesses(store_a)]
        # [b+8, +4) does not overlap [a, +8) even if a and b are the same object
        assert F._commutes_with_region(gap_far, region)
        # [b, +4) does overlap it under that assumption, so the motion is refused
        assert not F._commutes_with_region(gap_near, region)


class TestStackFields(TestCase):
    # A stack container never reaches the matcher as an object: variable recovery
    # has already split it into one virtual variable per slot, so there is no
    # `Load(s)` and no `s + 16`. Measured over the benchmark corpus, that is
    # 40-54% of the std::string accessor sites and 15-35% of std::vector<T>::size.
    #
    # PStackField binds the object's *stack offset*, so two fields of one object
    # unify on it exactly as PField's two displacements do.

    @staticmethod
    def _slot(varid, off, bits=64):
        return VirtualVariable(None, varid, bits, VirtualVariableCategory.STACK, oident=off)

    def test_two_fields_unify_on_the_object_offset(self):
        from angr.ailment.expression import UnaryOp
        from angr.analyses.decompiler.known_patterns import PStackField

        # libstdc++ std::string at s-112: _M_p at +0, the local buffer at +16
        data = self._slot(1, -112)
        localbuf = self._slot(2, -96)

        st = PStackField("s", 0).match(data, MatchState(), MatchCtx())
        # the binding is the object's own address -- which is also, directly, the
        # argument the synthesized call takes
        assert st is not None and st.bindings["s"].offset == -112

        # `&_M_local_buf` lifts to a Reference, and it is the same object
        ref = UnaryOp(None, "Reference", localbuf)
        assert PStackField("s", 16, as_address=True).match(ref, st, MatchCtx()) is not None
        # ... at any other offset it is not
        assert PStackField("s", 8, as_address=True).match(ref, st, MatchCtx()) is None

    def test_value_and_address_forms_are_distinct(self):
        from angr.ailment.expression import UnaryOp
        from angr.analyses.decompiler.known_patterns import PStackField

        slot = self._slot(1, -96)
        ref = UnaryOp(None, "Reference", slot)
        # capacity() needs both: it compares the data pointer against the *address*
        # of the local buffer and returns the *value* of the same slot
        assert PStackField("s", 0).match(slot, MatchState(), MatchCtx()) is not None
        assert PStackField("s", 0).match(ref, MatchState(), MatchCtx()) is None
        assert PStackField("s", 0, as_address=True).match(ref, MatchState(), MatchCtx()) is not None
        assert PStackField("s", 0, as_address=True).match(slot, MatchState(), MatchCtx()) is None

    def test_register_slots_are_not_stack_fields(self):
        from angr.analyses.decompiler.known_patterns import PStackField

        reg = VirtualVariable(None, 1, 64, VirtualVariableCategory.REGISTER, oident=16)
        assert PStackField("s", 0).match(reg, MatchState(), MatchCtx()) is None


class TestStackSlotResolution(TestCase):
    # A local container's fields are stack slots, but the compiler keeps one of
    # them in a register across the accessor -- often behind a phi, one arm per
    # branch. The idiom then arrives half in slots and half in registers, and the
    # two halves do not look like one object until the copies are followed back.

    def test_pstackfield_needs_the_resolver_for_a_register_copy(self):
        from angr.analyses.decompiler.known_patterns import PStackField

        slot = VirtualVariable(None, 1, 64, VirtualVariableCategory.STACK, oident=-56)
        reg = VirtualVariable(None, 2, 64, VirtualVariableCategory.REGISTER, oident=16)

        # without a resolver a register is simply not a slot
        assert PStackField("v", 0).match(reg, MatchState(), MatchCtx()) is None
        # with one, it resolves to the slot it was copied from and binds that object
        ctx = MatchCtx(stack_slot_fn=lambda varid: slot if varid == 2 else None)
        st = PStackField("v", 0).match(reg, MatchState(), ctx)
        assert st is not None and st.bindings["v"].offset == -56
        # and the offsets still have to agree with the other field's
        assert PStackField("v", 8).match(slot, st, ctx) is None
        st2 = PStackField("v", 8).match(
            VirtualVariable(None, 3, 64, VirtualVariableCategory.STACK, oident=-48), st, ctx
        )
        assert st2 is not None
