from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import re
import unittest
from unittest import TestCase

import archinfo

import angr
from angr.ailment.expression import Load, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, SideEffectStatement
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompilation_options import parse_known_patterns
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    ALL_KNOWN_PATTERN_TEMPLATES,
    CONTAINING_RECORD_PATTERN,
    STD_STRING_LENGTH,
    STD_VECTOR_INT_SIZE,
    KnownPatternFinder,
    UnknownPatternError,
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
