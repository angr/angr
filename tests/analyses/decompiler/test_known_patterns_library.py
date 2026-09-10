from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import re
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    ALL_KERNEL_ERR_TEMPLATES,
    ALL_LIBM_TEMPLATES,
    ALL_LINKED_LIST_TEMPLATES,
    ALL_POSIX_MACRO_TEMPLATES,
    ALL_PROTOBUF_TEMPLATES,
    ALL_STL2_TEMPLATES,
    ALL_STL_TEMPLATES,
    ALL_VECTOR_MATH_TEMPLATES,
    ALL_WDK_TEMPLATES,
    STD_STRING_CSTR,
    KnownPatternFinder,
)
from angr.analyses.decompiler.optimization_passes import KnownPatternOutliner
from angr.knowledge_plugins.functions.function import PrototypeSource
from tests.common import bin_location, load_project_with_scoped_cfg

WDK_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_list.exe")
LINUX_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_linux_list")
STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
PB_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_protobuf")
VM_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_vecmath")
MSVC_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_stl_msvc_17_x64.exe")
CSTR_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_msvc_string_cstr.exe")
MSVC_X86_BIN = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_stl_msvc_17_x86.exe")
CR_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_containing_record.exe")
GLIBC_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_glibc_macros")
KERNEL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_kernel_macros")
LIBM_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_libm_bits")
GO_PE_BIN = os.path.join(
    bin_location, "tests", "x86_64", "windows", "131252a8059fdbb12d77cd4711e597c45bb48e6d4bc3ddc808697a5e0488ff2c"
)
KSUD_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_ksud.exe")
STL2_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl2")
KSUD_X86_BIN = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_wdk_ksud.exe")
# criteria-gate fixtures: a real WDK driver, and a real libstdc++
DRIVER_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "cancel.sys")
LIBSTDCXX_BIN = os.path.join(bin_location, "tests", "x86_64", "libstdc++.so.6")

_LINKED_LIST_NAMES = {"is_list_empty", "initialize_list_head", "remove_entry_list"}
_PROTOBUF_NAMES = {"protobuf_has_field", "protobuf_set_has_field", "protobuf_clear_has_field"}
_VECMATH_NAMES = {"vec_dot3", "vec_length_sq"}


def _decompile(bin_path: str, func_name: str | None = None, addr: int | None = None):
    # The pattern outliner is disabled here on purpose. These tests decompile a
    # function and then run KnownPatternFinder over the result by hand, which
    # only works on a graph where the idioms are still idioms -- once the
    # outliner has replaced one with a call there is nothing left to match. The
    # `fast` preset used to be pattern-free and is not any more, so what used to
    # be implicit has to be said.
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name) if func_name is not None else cfg.functions.function(addr=addr)
    assert func is not None
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, disable_opts=[KnownPatternOutliner])
    assert dec.codegen is not None and dec.codegen.text is not None
    return proj, cfg, func, dec


def _find(proj, func, dec, templates=ALL_LINKED_LIST_TEMPLATES):
    return proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=templates)


def _outline_text(proj, cfg, func, dec, finder):
    result = finder.outline(finder.matches[0])
    del dec.kb.dec_variables.function_managers[func.addr]
    func.prototype_source = PrototypeSource.GUESSED
    dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
        func,
        clinic_graph=result.graph,
        clinic_start_stage=ClinicStage.POST_CALLSITES,
        clinic_arg_vvars=dec.clinic.arg_vvars,
        cfg=cfg.model,
    )
    return dec_outer.codegen.text


class TestLinkedListPatterns(TestCase):
    # each idiom is exercised on BOTH the WDK PE and the Linux ELF, proving one
    # template set matches LIST_ENTRY (Flink/Blink) and list_head (next/prev).

    def _check(self, bin_path, func_name, pattern_name, call_name):
        proj, cfg, func, dec = _decompile(bin_path, func_name)
        finder = _find(proj, func, dec)
        assert len(finder.matches) == 1, f"{func_name}: {[m.pattern.name for m in finder.matches]}"
        assert finder.matches[0].pattern.name == pattern_name
        text = _outline_text(proj, cfg, func, dec, finder)
        assert call_name + "(" in text

    def test_is_list_empty_wdk(self):
        self._check(WDK_BIN, "wdk_is_empty", "is_list_empty", "IsListEmpty")

    def test_is_list_empty_linux(self):
        self._check(LINUX_BIN, "lx_is_empty", "is_list_empty", "IsListEmpty")

    def test_initialize_list_head_wdk(self):
        self._check(WDK_BIN, "wdk_init", "initialize_list_head", "InitializeListHead")

    def test_initialize_list_head_linux(self):
        self._check(LINUX_BIN, "lx_init", "initialize_list_head", "InitializeListHead")

    def test_remove_entry_list_wdk(self):
        self._check(WDK_BIN, "wdk_remove", "remove_entry_list", "RemoveEntryList")

    def test_remove_entry_list_linux(self):
        self._check(LINUX_BIN, "lx_del", "remove_entry_list", "RemoveEntryList")

    def test_not_enabled_by_default(self):
        proj, _, func, dec = _decompile(LINUX_BIN, "lx_del")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern.name in _LINKED_LIST_NAMES for m in finder.matches)


class TestStlContainerPatterns(TestCase):
    def _check(self, func_name, pattern_name, call_fragment):
        proj, cfg, func, dec = _decompile(STL_BIN, func_name)
        finder = _find(proj, func, dec, ALL_STL_TEMPLATES)
        assert len(finder.matches) == 1, f"{func_name}: {[m.pattern.name for m in finder.matches]}"
        assert finder.matches[0].pattern.name == pattern_name
        text = _outline_text(proj, cfg, func, dec, finder)
        assert call_fragment in text

    def test_vector_empty(self):
        self._check("vec_empty", "std_vector_int_empty", "std::vector<int>::empty(")

    def test_vector_capacity(self):
        self._check("vec_capacity", "std_vector_int_capacity", "std::vector<int>::capacity(")

    def test_vector_index(self):
        self._check("vec_index", "std_vector_int_index", "std::vector<int>::operator[](")

    def test_string_empty(self):
        self._check("str_empty", "std_string_empty", "std::string::empty(")

    def test_string_index(self):
        self._check("str_index", "std_string_index", "std::string::operator[](")

    def test_empty_is_gated_on_a_size_or_capacity_witness(self):
        # `Load(v + 8) == Load(v)` is two adjacent pointer fields compared for
        # equality -- 2.4% precision over the benchmark corpus once the base was
        # allowed to float. It fires only where a size()/capacity() match in the
        # same function already identified the object.
        proj, _, func, dec = _decompile(STL_BIN, "vec_empty")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        names = {m.pattern.name for m in finder.matches}
        if any(n.startswith("std_vector_") and n.endswith(("_size", "_capacity")) for n in names):
            assert "std_vector_int_empty" in names, names
        else:
            assert "std_vector_int_empty" not in names, names


class TestProtobufHasBitsPatterns(TestCase):
    def _check(self, func_name, pattern_name, call_name):
        proj, cfg, func, dec = _decompile(PB_BIN, func_name)
        finder = _find(proj, func, dec, ALL_PROTOBUF_TEMPLATES)
        assert len(finder.matches) == 1, f"{func_name}: {[m.pattern.name for m in finder.matches]}"
        assert finder.matches[0].pattern.name == pattern_name
        text = _outline_text(proj, cfg, func, dec, finder)
        assert call_name + "(" in text

    def test_has_field(self):
        self._check("has_field", "protobuf_has_field", "_pb_has_field")

    def test_set_has_field(self):
        self._check("set_has_field", "protobuf_set_has_field", "_pb_set_has_field")

    def test_clear_has_field(self):
        self._check("clear_has_field", "protobuf_clear_has_field", "_pb_clear_has_field")

    def test_opt_in(self):
        proj, _, func, dec = _decompile(PB_BIN, "set_has_field")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern.name in _PROTOBUF_NAMES for m in finder.matches)


class TestVectorMathPatterns(TestCase):
    def _check(self, func_name, pattern_name, call_name):
        proj, cfg, func, dec = _decompile(VM_BIN, func_name)
        finder = _find(proj, func, dec, ALL_VECTOR_MATH_TEMPLATES)
        assert len(finder.matches) == 1, f"{func_name}: {[m.pattern.name for m in finder.matches]}"
        assert finder.matches[0].pattern.name == pattern_name
        text = _outline_text(proj, cfg, func, dec, finder)
        assert call_name + "(" in text

    def test_dot3(self):
        self._check("vec_dot3", "vec_dot3", "dot3")

    def test_length_sq(self):
        self._check("vec_length_sq", "vec_length_sq", "length_sq")

    def test_opt_in(self):
        proj, _, func, dec = _decompile(VM_BIN, "vec_dot3")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern.name in _VECMATH_NAMES for m in finder.matches)


class TestMsvcStlPatterns(TestCase):
    # The one STL template set covers the MSVC binaries too: string length/empty
    # instantiate the +16 MSVC layout, vector accessors the shared three-pointer
    # layout. Matched by address (the binaries have no symbols).
    # unified pattern names (no per-arch/runtime suffix).
    ACCESSORS = {
        0x1400013A0: ("std_string_length", "std::string::length"),
        0x140001690: ("std_string_empty", "std::string::empty"),
        0x1400013B0: ("std_vector_int_size", "std::vector<int>::size"),
        0x1400016A0: ("std_vector_int_capacity", "std::vector<int>::capacity"),
        0x1400016B0: ("std_vector_int_empty", "std::vector<int>::empty"),
        0x1400016C0: ("std_vector_int_index", "std::vector<int>::operator[]"),
    }
    BIN = MSVC_BIN
    EXPECT_ARCH = "AMD64"

    def test_msvc_accessors(self):
        for addr, (pattern_name, call_name) in self.ACCESSORS.items():
            with self.subTest(addr=hex(addr)):
                proj, cfg, func, dec = _decompile(self.BIN, addr=addr)
                assert proj.arch.name == self.EXPECT_ARCH
                finder = _find(proj, func, dec, ALL_STL_TEMPLATES)
                assert len(finder.matches) == 1, f"{addr:#x}: {[m.pattern.name for m in finder.matches]}"
                assert finder.matches[0].pattern.name == pattern_name
                text = _outline_text(proj, cfg, func, dec, finder)
                assert call_name + "(" in text

    def test_is_msvc_runtime(self):
        from angr.analyses.decompiler.known_patterns.context import MSVC, detect_cxx_runtime

        assert detect_cxx_runtime(angr.Project(self.BIN, auto_load_libs=False)) == MSVC


class TestMsvcStlPatternsX86(TestMsvcStlPatterns):
    # 32-bit MSVC: the SAME templates produce 4-byte loads and vector offsets 4/8.
    ACCESSORS = {
        0x4012B0: ("std_string_length", "std::string::length"),
        0x401520: ("std_string_empty", "std::string::empty"),
        0x4012C0: ("std_vector_int_size", "std::vector<int>::size"),
        0x401530: ("std_vector_int_capacity", "std::vector<int>::capacity"),
        0x401540: ("std_vector_int_empty", "std::vector<int>::empty"),
        0x401550: ("std_vector_int_index", "std::vector<int>::operator[]"),
    }
    BIN = MSVC_X86_BIN
    EXPECT_ARCH = "X86"


class TestUnorderedStmtSeqDecl(TestCase):
    def test_unordered_matching_is_order_insensitive(self):
        # the WDK and Linux builds emit the init/remove stores in different
        # orders; a single ordered=False pattern matches both.
        from angr.analyses.decompiler.known_patterns import INITIALIZE_LIST_HEAD, REMOVE_ENTRY_LIST
        from angr.analyses.decompiler.known_patterns.context import PatternContext
        from angr.analyses.decompiler.known_patterns.dsl import PStmtSeq

        ctx = PatternContext("AMD64", 64, 8, "linux", None, False)
        for t in (INITIALIZE_LIST_HEAD, REMOVE_ENTRY_LIST):
            p = t.instantiate(ctx)
            assert isinstance(p.pattern, PStmtSeq) and p.pattern.ordered is False


class TestMsvcStringCstr(TestCase):
    # MSVC std::string::c_str() is inlined as a small-string-optimization select
    # (a control-flow diamond / PGraphPat), matched in clean pre-de-phi SSA so
    # the KnownPatternOutliner pass recognizes and outlines it *during*
    # decompilation. The target function inlines c_str() three times.
    CSTR_FUNC = 0x140009280

    def test_find_msvc_string_cstr(self):
        # the clean SSA form (no de-phi copies) is present right after Stage-1 SSA
        proj = angr.Project(CSTR_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(addr=self.CSTR_FUNC)
        assert func is not None
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            func, cfg=cfg.model, preset="fast", clinic_end_stage=ClinicStage.SSA_LEVEL1_TRANSFORMATION
        )
        finder = _find(proj, func, dec, templates=[STD_STRING_CSTR])
        assert len(finder.matches) == 3, [m.pattern.name for m in finder.matches]
        for m in finder.matches:
            assert m.block_map is not None and set(m.block_map) == {"entry", "heap"}
            assert m.frontier_locs is not None and len(m.frontier_locs) == 1

    def test_outlines_during_decompilation(self):
        # c_str is enabled by default, so a normal full-preset decompile outlines
        # all three SSO diamonds. This exercises the whole in-pipeline path:
        # matching the clean SSA form at BEFORE_VARIABLE_RECOVERY, outlining a
        # value-producing diamond, and the Outliner collapsing the frontier phi so
        # the subsequent de-phi succeeds. (Also pins c_str as enabled-by-default.)
        proj = angr.Project(CSTR_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(addr=self.CSTR_FUNC)
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None
        assert dec.codegen.text.count("std::string::c_str(") == 3, dec.codegen.text


#: force-enable every template, opt-in ones included, through the normal decompilation-option machinery
ALL_PATTERNS_OPTION = [("known_patterns", "all")]


def _assert_outlines_during(test, bin_path, targets):
    """Assert each (func-name-or-address, call-fragment) is outlined by the pass
    during a normal full-preset decompile (not only via a finder afterwards).
    The opt-in templates are force-enabled with the ``known_patterns`` option."""
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    for ref, frag in targets:
        with test.subTest(target=ref):
            func = cfg.functions.function(name=ref) if isinstance(ref, str) else cfg.functions.function(addr=ref)
            assert func is not None, ref
            dec = proj.analyses[Decompiler].prep(fail_fast=True)(
                func, cfg=cfg.model, preset="full", options=ALL_PATTERNS_OPTION
            )
            assert dec.codegen is not None and dec.codegen.text is not None
            assert frag in dec.codegen.text, f"{ref!r}: {frag!r} not outlined DURING decompilation"


class TestOutlinerEntry(TestCase):
    def test_a_loop_head_entry_still_outlines(self):
        # runtime.printfloat in a Windows Go binary: the stack-check preamble jumps back to the entry, so no block
        # of the graph is predecessor-less. The Outliner used to pick the entry as the unique such block and died
        # on an empty min(); the finder now tells it where the function starts.
        # no call-tree expansion: the Go runtime's call tree is most of the binary and none of it matters here
        proj, cfg = load_project_with_scoped_cfg(GO_PE_BIN, 0x436B40, expand_call_tree=False, run_ccc=False)
        func = cfg.functions[0x436B40]
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None
        assert "fneg(" in dec.codegen.text, dec.codegen.text


class TestPosixMacros(TestCase):
    # <sys/stat.h> file-type predicates: ((mode) & 0170000) == S_IFxxx. The mask/value
    # pairing is self-guarding, so these are enabled by default.

    _S_ISTYPES = [
        ("chk_isreg", "s_isreg", "S_ISREG"),
        ("chk_isdir", "s_isdir", "S_ISDIR"),
        ("chk_ischr", "s_ischr", "S_ISCHR"),
        ("chk_isblk", "s_isblk", "S_ISBLK"),
        ("chk_isfifo", "s_isfifo", "S_ISFIFO"),
        ("chk_islnk", "s_islnk", "S_ISLNK"),
        ("chk_issock", "s_issock", "S_ISSOCK"),
    ]

    def test_a_predicate_used_as_a_value_is_an_int(self):
        # The call that replaces `(m & S_IFMT) == S_IFREG` is one bit wide, and
        # the C emitter used to cast such a call to the byte-rounded width of
        # its result -- `(uint0_t)S_ISREG(...)`, a type that is no type, which
        # blew up in address arithmetic on git's check_one_conflict. A sub-byte
        # call keeps its declared return type.
        for func_name, macros in (
            ("kind_count", ("S_ISREG", "S_ISDIR")),
            ("kind_tab", ("S_ISREG",)),
            ("kind_ptr", ("S_ISREG",)),
            ("kind_mix", ("S_ISREG", "S_ISDIR")),
        ):
            with self.subTest(func=func_name):
                proj, cfg, func, _ = _decompile(GLIBC_BIN, func_name)
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
                text = dec.codegen.text
                for macro in macros:
                    assert f"{macro}(" in text, text
                assert "uint0_t" not in text and "uint1_t" not in text, text

    def test_s_istype_predicates(self):
        for func_name, pattern_name, macro in self._S_ISTYPES:
            with self.subTest(macro=macro):
                proj, cfg, func, dec = _decompile(GLIBC_BIN, func_name)
                finder = _find(proj, func, dec, ALL_POSIX_MACRO_TEMPLATES)
                assert len(finder.matches) == 1, f"{macro}: {[m.pattern.name for m in finder.matches]}"
                assert finder.matches[0].pattern.name == pattern_name
                text = _outline_text(proj, cfg, func, dec, finder)
                assert macro + "(" in text

    def test_s_istype_outlines_by_default(self):
        # these are default-on, so a plain full-preset decompile must outline them
        # without the opt-in templates being force-enabled
        proj = angr.Project(GLIBC_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for func_name, _, macro in self._S_ISTYPES:
            with self.subTest(macro=macro):
                func = cfg.functions.function(name=func_name)
                assert func is not None
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
                assert dec.codegen is not None and dec.codegen.text is not None
                assert macro + "(" in dec.codegen.text, f"{macro} not outlined during decompilation"


class TestWaitStatusMacros(TestCase):
    # <sys/wait.h> status decoders. WIFEXITED/WIFSIGNALED keep enough residue to be
    # identifying and are default-on; WIFSTOPPED (a bare `(char)x == 0x7f`) and
    # WTERMSIG (a bare `x & 0x7f`) are opt-in.

    _CASES = [
        ("st_ifexited", "wifexited", "WIFEXITED"),
        ("st_ifsignaled", "wifsignaled", "WIFSIGNALED"),
        ("st_ifstopped", "wifstopped", "WIFSTOPPED"),
        ("st_termsig", "wtermsig", "WTERMSIG"),
    ]

    def test_wait_status_macros(self):
        for func_name, pattern_name, macro in self._CASES:
            with self.subTest(macro=macro):
                proj, cfg, func, dec = _decompile(GLIBC_BIN, func_name)
                finder = _find(proj, func, dec, ALL_POSIX_MACRO_TEMPLATES)
                names = [m.pattern.name for m in finder.matches]
                assert pattern_name in names, f"{macro}: {names}"
                match = next(m for m in finder.matches if m.pattern.name == pattern_name)
                result = finder.outline(match)
                del dec.kb.dec_variables.function_managers[func.addr]
                func.prototype_source = PrototypeSource.GUESSED
                dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
                    func,
                    clinic_graph=result.graph,
                    clinic_start_stage=ClinicStage.POST_CALLSITES,
                    clinic_arg_vvars=dec.clinic.arg_vvars,
                    cfg=cfg.model,
                )
                assert macro + "(" in dec_outer.codegen.text

    def test_wifsignaled_requires_a_signed_compare(self):
        # the (signed char) cast is the whole idiom: an unsigned compare against the
        # same constants is an unrelated test, so the pattern must reject it.
        from angr.analyses.decompiler.known_patterns import PatternContext, patterns_for

        proj = angr.Project(GLIBC_BIN, auto_load_libs=False)
        ctx = PatternContext.from_project(proj)
        pat = next(p for p in patterns_for(ctx, ALL_POSIX_MACRO_TEMPLATES) if p.name == "wifsignaled")
        assert pat.where is not None

        class _FakeCmp:
            signed = False

        assert pat.where({"cmp": _FakeCmp()}) is False
        _FakeCmp.signed = True
        assert pat.where({"cmp": _FakeCmp()}) is True

    def test_opt_in_macros_are_not_default_on(self):
        # WIFSTOPPED / WTERMSIG must not fire in a plain full-preset decompile
        proj = angr.Project(GLIBC_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for func_name, _, macro in self._CASES[2:]:
            with self.subTest(macro=macro):
                func = cfg.functions.function(name=func_name)
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
                assert macro + "(" not in dec.codegen.text, f"{macro} is opt-in but fired by default"


class TestSysMacros(TestCase):
    # <sys/sysmacros.h> major(): glibc scatters the major number over bits 8-19 and
    # 32-63, which gcc reassociates into ((dev >> 8) & 0xfff) | ((dev >> 32) & 0xfffff000).

    def test_major(self):
        proj, cfg, func, dec = _decompile(GLIBC_BIN, "dev_major")
        finder = _find(proj, func, dec, ALL_POSIX_MACRO_TEMPLATES)
        assert [m.pattern.name for m in finder.matches] == ["gnu_dev_major"]
        assert "major(" in _outline_text(proj, cfg, func, dec, finder)

    def test_major_has_a_32bit_form(self):
        # glibc's dev_t is 64 bits on 32-bit targets too, so the same encoding
        # applies -- but it lives in a register pair, and each half of major()
        # reads a different half of the pair. The 32-bit template therefore has a
        # different shape and takes the two halves as separate arguments.
        import dataclasses

        from angr.analyses.decompiler.known_patterns import MAJOR, PatternContext

        ctx64 = PatternContext.from_project(angr.Project(GLIBC_BIN, auto_load_libs=False))
        p64 = MAJOR.instantiate(ctx64)
        p32 = MAJOR.instantiate(dataclasses.replace(ctx64, bits=32, ptr_size=4))
        assert p64 is not None and p32 is not None
        assert [prm.capture for prm in p64.params] == ["dev"]
        assert [prm.capture for prm in p32.params] == ["dev_lo", "dev_hi"]


class TestContainingRecordPresentation(TestCase):
    # container_of's *detection* was never the problem (90%+ function-level recall
    # on real C): its presentation was. No compiler keeps the adjusted pointer
    # around, it folds the subtraction into every field displacement, so one
    # source idiom emitted a call per field, each naming a record base wrong by
    # that field's offset -- and `p - 1` on a loop counter came along for the ride.

    _CALL = re.compile(r"CONTAINING_RECORD\(\s*([^,()]+?)\s*,\s*(\d+)\s*\)")

    def _calls(self, bin_path, ref):
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name=ref) if isinstance(ref, str) else cfg.functions.function(addr=ref)
        assert func is not None, ref
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(
            func, cfg=cfg.model, preset="full", options=ALL_PATTERNS_OPTION
        )
        assert dec.codegen is not None and dec.codegen.text is not None
        return self._CALL.findall(dec.codegen.text)

    def test_one_call_per_base_pointer(self):
        # this driver function walks a LIST_ENTRY and reads six fields of the
        # record through it, so gcc emitted CONTAINING_RECORD(iter, 96/80/64/48/
        # 32/16) -- six different claims about where the record starts, five of
        # them wrong. Only the largest survives, and 96 is the true offsetof.
        calls = self._calls(DRIVER_BIN, 0x140003EC0)
        by_base: dict[str, set[int]] = {}
        for base, off in calls:
            by_base.setdefault(base, set()).add(int(off))
        assert all(len(offs) == 1 for offs in by_base.values()), calls
        assert 96 in by_base.get("iter", set()), calls

    def test_small_offsets_are_not_records(self):
        # `p - 1` is a decrement; a record base is at least a machine word away
        calls = self._calls(WDK_BIN, "mark_section_writable")
        assert [int(o) for _, o in calls] == [64], calls
        assert all(int(o) >= 8 for _, o in self._calls(DRIVER_BIN, 0x140003EC0))

    def test_the_genuine_unfolded_idiom_still_matches(self):
        # the shape the pattern gets *right* -- the record pointer handed to a
        # callee rather than folded into a field load -- must survive the above
        assert self._calls(CR_BIN, "sum_list")


class TestKernelListPatterns(TestCase):
    # <linux/list.h> operations beyond the empty/init/unlink trio: head and tail
    # insertion, and the two unlink supersets the kernel actually calls.

    def _check(self, bin_path, func_name, pattern_name, call_name):
        proj, cfg, func, dec = _decompile(bin_path, func_name)
        finder = _find(proj, func, dec)
        names = [m.pattern.name for m in finder.matches]
        assert pattern_name in names, f"{func_name}: {names}"
        match = next(m for m in finder.matches if m.pattern.name == pattern_name)
        result = finder.outline(match)
        del dec.kb.dec_variables.function_managers[func.addr]
        func.prototype_source = PrototypeSource.GUESSED
        dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
            func,
            clinic_graph=result.graph,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            clinic_arg_vvars=dec.clinic.arg_vvars,
            cfg=cfg.model,
        )
        assert call_name + "(" in dec_outer.codegen.text
        return dec_outer.codegen.text

    def test_insert_head_list(self):
        self._check(KERNEL_BIN, "k_list_add", "insert_head_list", "InsertHeadList")

    def test_insert_tail_list(self):
        self._check(KERNEL_BIN, "k_list_add_tail", "insert_tail_list", "InsertTailList")

    def test_insert_tail_list_matches_wdk_list_entry(self):
        # one template covers both list_head (next/prev) and LIST_ENTRY (Flink/Blink)
        proj, _, func, dec = _decompile(WDK_BIN, "wdk_insert_tail")
        finder = _find(proj, func, dec)
        assert "insert_tail_list" in [m.pattern.name for m in finder.matches]

    def test_list_del_poisoned(self):
        # the real kernel list_del() unlinks and then stores LIST_POISON1/2
        self._check(KERNEL_BIN, "k_list_del_poison", "list_del", "list_del")

    def test_list_del_init(self):
        self._check(KERNEL_BIN, "k_list_del_init", "list_del_init", "list_del_init")

    def test_supersets_beat_the_bare_unlink(self):
        # list_del and list_del_init both strictly contain RemoveEntryList; the
        # finder's largest-match-wins rule must pick the superset
        for func_name, expected in (("k_list_del_poison", "list_del"), ("k_list_del_init", "list_del_init")):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(KERNEL_BIN, func_name)
                finder = _find(proj, func, dec)
                names = [m.pattern.name for m in finder.matches]
                assert names == [expected], names
                assert "remove_entry_list" not in names

    def test_hlist_del(self):
        # a control-flow diamond: *pprev = next; if (next) next->pprev = pprev
        self._check(KERNEL_BIN, "k_hlist_del_plain", "hlist_del", "hlist_del")


class TestKernelErrPatterns(TestCase):
    # <linux/err.h>: IS_ERR(p) is (unsigned long)p >= (unsigned long)-MAX_ERRNO.

    def _check(self, func_name, pattern_name, call_name):
        proj, cfg, func, dec = _decompile(KERNEL_BIN, func_name)
        finder = _find(proj, func, dec, ALL_KERNEL_ERR_TEMPLATES)
        names = [m.pattern.name for m in finder.matches]
        assert pattern_name in names, f"{func_name}: {names}"
        match = next(m for m in finder.matches if m.pattern.name == pattern_name)
        result = finder.outline(match)
        del dec.kb.dec_variables.function_managers[func.addr]
        func.prototype_source = PrototypeSource.GUESSED
        dec_outer = proj.analyses[Decompiler].prep(fail_fast=True)(
            func,
            clinic_graph=result.graph,
            clinic_start_stage=ClinicStage.POST_CALLSITES,
            clinic_arg_vvars=dec.clinic.arg_vvars,
            cfg=cfg.model,
        )
        assert call_name + "(" in dec_outer.codegen.text

    def test_is_err_value_form(self):
        self._check("k_is_err", "is_err", "IS_ERR")

    def test_is_err_branch_form(self):
        # gcc emits the operand-swapped comparison when the test becomes a branch
        # condition; the pattern must cover that shape too
        self._check("k_is_err_branch", "is_err", "IS_ERR")

    def test_is_err_or_null(self):
        self._check("k_is_err_or_null", "is_err_or_null", "IS_ERR_OR_NULL")

    def test_is_err_or_null_beats_is_err(self):
        # IS_ERR_OR_NULL strictly contains IS_ERR; the nested-expression
        # largest-match rule must prefer the outer one
        proj, _, func, dec = _decompile(KERNEL_BIN, "k_is_err_or_null")
        finder = _find(proj, func, dec, ALL_KERNEL_ERR_TEMPLATES)
        assert [m.pattern.name for m in finder.matches] == ["is_err_or_null"]

    def test_is_err_requires_an_unsigned_compare(self):
        from angr.analyses.decompiler.known_patterns import PatternContext, patterns_for

        proj = angr.Project(KERNEL_BIN, auto_load_libs=False)
        ctx = PatternContext.from_project(proj)
        pat = next(p for p in patterns_for(ctx, ALL_KERNEL_ERR_TEMPLATES) if p.name == "is_err")

        class _FakeCmp:
            signed = True

        assert pat.where({"err_cmp": _FakeCmp()}) is False
        _FakeCmp.signed = False
        assert pat.where({"err_cmp": _FakeCmp()}) is True

    def test_ptr_err_leaves_no_residue(self):
        # PTR_ERR/ERR_PTR are pure casts: nothing to match, and nothing must be
        # invented for them
        for func_name in ("k_ptr_err", "k_err_ptr"):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(KERNEL_BIN, func_name)
                finder = _find(proj, func, dec, ALL_KERNEL_ERR_TEMPLATES)
                assert not finder.matches


class TestLibmBitPatterns(TestCase):
    # fabs / -x / copysign / isnan / isinf are compiler intrinsics: on x86-64 SSE
    # each is a single andpd/xorpd/andnpd/ucomisd against a sign-mask constant,
    # which angr's constant_derefs peephole folds into a plain integer bit op.

    _CASES = [
        ("f_fabs", "libm_fabs", "fabs"),
        ("f_fabs_bits", "libm_fabs", "fabs"),
        ("f_fabsf", "libm_fabsf", "fabsf"),
        ("f_neg", "libm_fneg", "fneg"),
        ("f_negf", "libm_fnegf", "fnegf"),
        ("f_copysign", "libm_copysign", "copysign"),
        ("f_copysignf", "libm_copysignf", "copysignf"),
        ("f_isnan", "libm_isnan", "isnan"),
        ("f_isnan_bits", "libm_isnan", "isnan"),
        ("f_isnanf", "libm_isnanf", "isnanf"),
        ("f_isinf_bits", "libm_isinf", "isinf"),
    ]

    def test_libm_bit_idioms(self):
        for func_name, pattern_name, call_name in self._CASES:
            with self.subTest(func=func_name):
                proj, cfg, func, dec = _decompile(LIBM_BIN, func_name)
                finder = _find(proj, func, dec, ALL_LIBM_TEMPLATES)
                names = [m.pattern.name for m in finder.matches]
                assert names == [pattern_name], f"{func_name}: {names}"
                assert call_name + "(" in _outline_text(proj, cfg, func, dec, finder)

    def test_float_widths_survive_a_guessed_prototype(self):
        # the float patterns must not pin the mask/Conv widths: with a recovered
        # (guessed) prototype a float argument arrives through the 64-bit xmm
        # register, so fabsf is `x & 0x7fffffff<64>` rather than <32>.
        for func_name, pattern_name in (
            ("f_fabsf", "libm_fabsf"),
            ("f_negf", "libm_fnegf"),
            ("f_copysignf", "libm_copysignf"),
        ):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(LIBM_BIN, func_name)
                finder = _find(proj, func, dec, ALL_LIBM_TEMPLATES)
                assert [m.pattern.name for m in finder.matches] == [pattern_name]

    def test_computed_argument_does_not_match(self):
        # a call argument must bind a virtual variable, so fabs(a - b) must not
        # produce a match that could never be outlined
        proj, _, func, dec = _decompile(LIBM_BIN, "f_near")
        finder = _find(proj, func, dec, ALL_LIBM_TEMPLATES)
        assert not finder.matches

    def test_isnan_wins_over_isunordered_on_a_self_compare(self):
        proj, _, func, dec = _decompile(LIBM_BIN, "f_isnan")
        finder = _find(proj, func, dec, ALL_LIBM_TEMPLATES)
        assert [m.pattern.name for m in finder.matches] == ["libm_isnan"]


class TestWdkSharedDataPatterns(TestCase):
    # KUSER_SHARED_DATA is mapped at the fixed address 0x7FFE0000 in every Windows
    # process, so a field read is a bare load from an absolute constant. The address
    # is its own guard, which is why these are default-on nullary accessors.

    _CASES = [
        ("ksud_tick_count_low", "SharedUserData_TickCountLow"),
        ("ksud_interrupt_time", "SharedUserData_InterruptTime"),
        ("ksud_nt_major_version", "SharedUserData_NtMajorVersion"),
        ("ksud_kd_debugger_enabled", "SharedUserData_KdDebuggerEnabled"),
        ("ksud_image_number_low", "SharedUserData_ImageNumberLow"),
        ("ksud_cookie", "SharedUserData_Cookie"),
    ]

    def _full(self, bin_path, func_name):
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name=func_name)
        assert func is not None, func_name
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_shared_user_data_fields(self):
        for func_name, call_name in self._CASES:
            with self.subTest(func=func_name):
                assert call_name + "()" in self._full(KSUD_BIN, func_name)

    def test_nullary_accessor_takes_no_arguments(self):
        # a Load(Const) region has no live-in vvars, so the synthesized call is
        # nullary; this is the only pattern family with params=()
        text = self._full(KSUD_BIN, "ksud_tick_count_low")
        assert "SharedUserData_TickCountLow()" in text, text

    def test_kernel_mode_base_address(self):
        # kernel-mode code reaches the same page through KI_USER_SHARED_DATA
        assert "SharedUserData_NtMajorVersion()" in self._full(KSUD_BIN, "ksud_km_nt_major_version")

    def test_x86_uses_the_same_user_mode_address(self):
        # KUSER_SHARED_DATA sits at 0x7FFE0000 on x86 too, so one template covers
        # both. (32-bit mingw prefixes cdecl symbols with an underscore.)
        assert "SharedUserData_TickCountLow()" in self._full(KSUD_X86_BIN, "_ksud_tick_count_low")

    def test_x86_ksystem_time_high_half(self):
        # A KSYSTEM_TIME is three words, not two: the 64-bit value is not
        # atomically readable on a 32-bit machine, so the page publishes the high
        # half twice. A source-level 64-bit read therefore *never* compiles to one
        # load on x86 -- it is always LowPart plus High1Time, twelve bytes apart.
        # Covering only LowPart left every such read half-named.
        text = self._full(KSUD_X86_BIN, "_ksud_get_tick_count")
        assert "SharedUserData_TickCountHigh1Time()" in text, text
        assert "0x7ffe0324" not in text, text

    def test_uncovered_offset_stays_raw(self):
        # negative control: offset 0x30 (NtSystemRoot) has no pattern
        text = self._full(KSUD_BIN, "ksud_nt_system_root_first_wchar")
        assert "SharedUserData_" not in text, text

    def test_systemcall_is_opt_in(self):
        # SystemCall moved from 0x300 to 0x308 in Windows 8, so neither offset can
        # be named with confidence without knowing the target's version
        from angr.analyses.decompiler.known_patterns import TEMPLATE_BY_CALL_NAME

        for call_name in ("SharedUserData_SystemCall_pre_win8", "SharedUserData_SystemCall_win8"):
            assert TEMPLATE_BY_CALL_NAME[call_name].enabled_by_default is False

    def test_ntstatus_severity_predicates(self):
        for func_name, macro in (
            ("ntstatus_information", "NT_INFORMATION"),
            ("ntstatus_warning", "NT_WARNING"),
            ("ntstatus_error", "NT_ERROR"),
        ):
            with self.subTest(macro=macro):
                assert macro + "(" in self._full(KSUD_BIN, func_name)

    def test_ntstatus_in_branch_position(self):
        assert "NT_ERROR(" in self._full(KSUD_BIN, "ntstatus_error_if")

    def test_nt_success_is_not_a_pattern(self):
        # NT_SUCCESS(s) is a bare `(NTSTATUS)s >= 0` sign test; naming it would
        # rename every sign comparison in the program
        from angr.analyses.decompiler.known_patterns import TEMPLATE_BY_CALL_NAME

        assert "NT_SUCCESS" not in TEMPLATE_BY_CALL_NAME

    def test_no_false_positives_on_a_non_ksud_windows_binary(self):
        proj = angr.Project(WDK_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        total = 0
        for func in list(cfg.functions.values()):
            if func.is_plt or func.is_simprocedure or func.is_alignment:
                continue
            try:
                dec = proj.analyses[Decompiler](func, cfg=cfg.model)
                if dec.ail_graph is None:
                    continue
                finder = proj.analyses[KnownPatternFinder](func, dec.ail_graph, patterns=ALL_WDK_TEMPLATES)
                total += len(finder.matches)
            except Exception:  # pylint:disable=broad-except
                continue
        assert total == 0, f"{total} spurious KUSER_SHARED_DATA/NTSTATUS matches"


class TestVectorExactDivSize(TestCase):
    # (_M_finish - _M_start) / sizeof(T) is an *exact* division, so for a
    # non-power-of-two sizeof(T) the compiler emits a shift by ctz(sizeof(T))
    # followed by a plain multiply by the modular inverse of the odd part --
    # not the usual mulhi-and-shift. Both operands follow from sizeof(T), so the
    # templates can be generated per element size.

    _SIZES = [6, 12, 20, 24, 40, 48]

    def test_element_sizes_cover_real_record_types(self):
        # The covered sizes must not be a handful chosen from the fixtures: sizeof(T)
        # is whatever the program's record happens to be, and an uncovered size leaves
        # the raw magic multiply in the output. 112 is sizeof(CryptoPP::ECPPoint),
        # which a hand-picked list missed entirely.
        from angr.analyses.decompiler.known_patterns import STD_VECTOR_STRUCT_SIZE_TEMPLATES

        names = {t.name for t in STD_VECTOR_STRUCT_SIZE_TEMPLATES}
        for n in (3, 6, 12, 40, 48, 80, 96, 112, 224, 384):
            assert f"std_vector_T{n}_size" in names, f"sizeof(T)={n} is not covered"
        # powers of two up to 8 divide with a bare shift and have a named element
        # type (short/int/long long), so they are not in the opaque set
        for n in (2, 4, 8):
            assert f"std_vector_T{n}_size" not in names
        # above 8 there is no named type of that width, so they get an opaque
        # element class too. sizeof(std::string) is 32, and std::vector<std::string>
        # is the most common element type in the benchmark corpus.
        for n in (16, 32, 64, 256):
            assert f"std_vector_T{n}_size" in names, f"sizeof(T)={n} is not covered"

    def test_exact_div_magic_matches_the_compiler(self):
        from angr.analyses.decompiler.known_patterns import exact_div_magic

        # shift/magic pairs read off g++ 12.2 -O2 output
        assert exact_div_magic(12, 64) == (2, 0xAAAAAAAAAAAAAAAB)
        assert exact_div_magic(20, 64) == (2, 0xCCCCCCCCCCCCCCCD)
        assert exact_div_magic(40, 64) == (3, 0xCCCCCCCCCCCCCCCD)
        assert exact_div_magic(48, 64) == (4, 0xAAAAAAAAAAAAAAAB)
        assert exact_div_magic(56, 64) == (3, 0x6DB6DB6DB6DB6DB7)
        # 32-bit targets get the inverse mod 2**32
        assert exact_div_magic(12, 32) == (2, 0xAAAAAAAB)

    def test_struct_element_vector_sizes(self):
        proj = angr.Project(STL2_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for n in self._SIZES:
            with self.subTest(elt_size=n):
                func = cfg.functions.function(name=f"vec_size_s{n}")
                assert func is not None
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
                text = dec.codegen.text
                assert f"std::vector<T{n}>::size(" in text, text
                # the whole division must be absorbed: no bare magic multiply left
                assert "12297829382473034411" not in text, text
                assert "std::string" not in text, text


class TestStlAccessors2(TestCase):
    # libstdc++ round two: the SSO capacity select, string back/front, vector back.

    def _full(self, func_name):
        proj = angr.Project(STL2_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name=func_name)
        assert func is not None, func_name
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None and dec.codegen.text is not None
        return dec.codegen.text

    def test_string_capacity_is_outlined_during_decompilation(self):
        # the two-armed SSO select survives to the matcher as an ITE (see PITE),
        # so this is the real end-to-end check that a converted select outlines
        assert "std::string::capacity(" in self._full("str_capacity")

    def test_string_capacity_tail_duplicated_does_not_match(self):
        # when gcc copies the join into both arms there is no merge and no single
        # region exit, so there is nothing to outline; it must stay raw
        text = self._full("str_capacity_dup")
        assert "std::string::capacity(" not in text, text

    def test_string_back(self):
        assert "std::string::back(" in self._full("str_back")

    def test_opt_in_accessors(self):
        # string::front is operator[] with i == 0 folded away, and vector::back is
        # a bare end-pointer dereference: both too generic for default-on
        proj, _, func, dec = _decompile(STL2_BIN, "str_front")
        finder = _find(proj, func, dec, ALL_STL2_TEMPLATES)
        assert "std_string_front" in [m.pattern.name for m in finder.matches]
        assert "std::string::front(" not in self._full("str_front")

        for func_name, pattern_name in (
            ("vec_back_s", "std_vector_short_back"),
            ("vec_back", "std_vector_int_back"),
            ("vec_back_ll", "std_vector_long_long_back"),
        ):
            with self.subTest(func=func_name):
                proj, _, func, dec = _decompile(STL2_BIN, func_name)
                finder = _find(proj, func, dec, ALL_STL2_TEMPLATES)
                assert pattern_name in [m.pattern.name for m in finder.matches]

    def test_bare_one_word_loads_are_not_patterns(self):
        # c_str/data/begin/get all compile to the identical `mov (%rdi),%rax`;
        # naming any of them would rewrite ~1 in 37 AIL statements of a C++ binary
        from angr.analyses.decompiler.known_patterns import TEMPLATE_BY_CALL_NAME

        for call_name in (
            "std::vector<int>::data",
            "std::unique_ptr::get",
            "std::shared_ptr::get",
        ):
            assert call_name not in TEMPLATE_BY_CALL_NAME
        for func_name in ("str_cstr", "vec_data", "uptr_get"):
            with self.subTest(func=func_name):
                text = self._full(func_name)
                assert "::data(" not in text and "::get(" not in text, text


class TestPatternsOutlineDuringDecompilation(TestCase):
    # Every pattern must be recognized and outlined *during* decompilation (by the
    # KnownPatternOutliner pass at BEFORE_VARIABLE_RECOVERY), not only when a finder
    # is run on the final graph afterwards. The opt-in templates are enabled here so
    # the pass exercises them; this guards against a pattern being calibrated only
    # for the final (post-de-phi) form — the bug that made c_str match after but not
    # during decompilation. (std::swap: see test_known_patterns.TestAutomaticPipeline;
    # std::string::c_str: see TestMsvcStringCstr.test_outlines_during_decompilation.)

    def test_stl_elf(self):
        _assert_outlines_during(
            self,
            STL_BIN,
            [
                ("get_len", "std::string::length("),
                ("get_size", "std::vector<int>::size("),
                ("get_size_ll", "std::vector<long long>::size("),
                ("str_empty", "std::string::empty("),
                ("str_index", "std::string::operator[]("),
                ("vec_empty", "std::vector<int>::empty("),
                ("vec_capacity", "std::vector<int>::capacity("),
                ("vec_index", "std::vector<int>::operator[]("),
            ],
        )

    def test_linked_list(self):
        _assert_outlines_during(
            self,
            LINUX_BIN,
            [("lx_is_empty", "IsListEmpty("), ("lx_init", "InitializeListHead("), ("lx_del", "RemoveEntryList(")],
        )
        _assert_outlines_during(self, WDK_BIN, [("wdk_remove", "RemoveEntryList(")])
        _assert_outlines_during(
            self,
            KERNEL_BIN,
            [
                ("k_list_add", "InsertHeadList("),
                ("k_list_add_tail", "InsertTailList("),
                ("k_list_del_poison", "list_del("),
                ("k_list_del_init", "list_del_init("),
                ("k_hlist_del_plain", "hlist_del("),
            ],
        )

    def test_posix_macros(self):
        _assert_outlines_during(
            self,
            GLIBC_BIN,
            [
                ("chk_isreg", "S_ISREG("),
                ("chk_isdir", "S_ISDIR("),
                ("chk_issock", "S_ISSOCK("),
                ("st_ifexited", "WIFEXITED("),
                ("st_ifsignaled", "WIFSIGNALED("),
                ("st_ifstopped", "WIFSTOPPED("),
                ("st_termsig", "WTERMSIG("),
                ("dev_major", "major("),
            ],
        )

    def test_kernel_err(self):
        _assert_outlines_during(
            self,
            KERNEL_BIN,
            [("k_is_err", "IS_ERR("), ("k_is_err_or_null", "IS_ERR_OR_NULL(")],
        )

    def test_libm_bits(self):
        _assert_outlines_during(
            self,
            LIBM_BIN,
            [
                ("f_fabs", "fabs("),
                ("f_neg", "fneg("),
                ("f_copysign", "copysign("),
                ("f_isnan", "isnan("),
                ("f_isinf_bits", "isinf("),
            ],
        )

    def test_stl_accessors2(self):
        _assert_outlines_during(
            self,
            STL2_BIN,
            [("str_capacity", "std::string::capacity("), ("str_back", "std::string::back(")],
        )

    def test_containing_record(self):
        _assert_outlines_during(self, CR_BIN, [("sum_list", "CONTAINING_RECORD(")])

    def test_protobuf(self):
        _assert_outlines_during(
            self,
            PB_BIN,
            [
                ("has_field", "_pb_has_field("),
                ("set_has_field", "_pb_set_has_field("),
                ("clear_has_field", "_pb_clear_has_field("),
            ],
        )

    def test_vecmath(self):
        _assert_outlines_during(self, VM_BIN, [("vec_dot3", "dot3("), ("vec_length_sq", "length_sq(")])

    def test_msvc_stl(self):
        _assert_outlines_during(
            self,
            MSVC_BIN,
            [
                (0x1400013A0, "std::string::length("),
                (0x140001690, "std::string::empty("),
                (0x1400013B0, "std::vector<int>::size("),
                (0x1400016A0, "std::vector<int>::capacity("),
                (0x1400016B0, "std::vector<int>::empty("),
                (0x1400016C0, "std::vector<int>::operator[]("),
            ],
        )


if __name__ == "__main__":
    unittest.main()


class TestBswapPeephole(TestCase):
    # Not a KnownPattern -- the bswap peephole -- but calibrated on the same
    # fixture. gcc recognizes the hand-rolled shift/mask spellings too, so the
    # builtin and manual wrappers compile to identical code.

    def test_bswap32_and_bswap64(self):
        # bswap_64 lowers to a 3-level SWAR tree (byte/word/dword exchanges),
        # not the flat 4-way Or the bswap_32 matcher flattens for, so it used to
        # render as an 8-line mask tree.
        proj = angr.Project(LIBM_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for func_name, expected in (
            ("i_bswap32", "__builtin_bswap32("),
            ("i_bswap32_manual", "__builtin_bswap32("),
            ("i_bswap64", "__builtin_bswap64("),
            ("i_bswap64_manual", "__builtin_bswap64("),
        ):
            with self.subTest(func=func_name):
                func = cfg.functions.function(name=func_name)
                assert func is not None
                dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
                text = dec.codegen.text
                assert expected in text, f"{func_name}: {text}"
                assert "0xff00ff00ff00ff00" not in text, f"{func_name}: SWAR mask tree survived"


class TestKernelTargetGate(TestCase):
    # A criteria gate turns the intrusive linked-list family on for binaries that
    # are demonstrably kernel objects, and leaves it off everywhere else. The
    # negative case is the point: the same idiom, in a user-space program, must
    # stay raw unless the user asks for it.

    # cancel.sys is the WDK cancel-safe-queue sample; this is its DriverEntry,
    # where InitializeListHead sits between KeInitializeSemaphore and
    # IoCsqInitialize -- i.e. an unmistakable true positive.
    DRIVER_ENTRY = 0x14000D000

    def test_driver_gate_opens_the_list_family(self):
        proj, cfg = load_project_with_scoped_cfg(
            DRIVER_BIN, self.DRIVER_ENTRY, window=0x800, project_kwargs={"auto_load_libs": False}
        )
        func = cfg.functions.function(addr=self.DRIVER_ENTRY)
        assert func is not None
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None
        assert "InitializeListHead(" in dec.codegen.text, dec.codegen.text

    def test_user_space_binary_keeps_the_same_idiom_raw(self):
        proj = angr.Project(LINUX_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        for func_name, call in (("lx_init", "InitializeListHead("), ("lx_is_empty", "IsListEmpty(")):
            with self.subTest(func=func_name):
                func = cfg.functions.function(name=func_name)
                assert func is not None
                gated = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
                assert call not in gated.codegen.text, gated.codegen.text
                # ... and the only reason it stayed raw is the gate: force-enabling brings it back
                forced = proj.analyses[Decompiler].prep(fail_fast=True)(
                    func, cfg=cfg.model, preset="full", options=ALL_PATTERNS_OPTION
                )
                assert call in forced.codegen.text, forced.codegen.text


class TestCorroborationGate(TestCase):
    # std::string::front() is `**(char **)p`, one of the most common shapes in any
    # C++ binary. It is enabled only where another, self-guarding string idiom has
    # already identified the object.

    # libstdc++ basic_string::_M_assign(const basic_string&): reads _M_string_length
    # (std::string::length) and, on the one-character path, *_M_p (front)
    ASSIGN = 0x524B90

    def test_corroborated_front_is_outlined_by_default(self):
        proj, cfg = load_project_with_scoped_cfg(
            LIBSTDCXX_BIN, self.ASSIGN, window=0x1000, project_kwargs={"auto_load_libs": False}
        )
        func = cfg.functions.function(addr=self.ASSIGN)
        assert func is not None
        dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert dec.codegen is not None
        text = dec.codegen.text
        # the witness is what opens the gate, so both must be present
        assert "std::string::length(" in text, text
        assert "std::string::front(" in text, text

    def test_uncorroborated_front_stays_raw(self):
        # str_front(const std::string &s) { return s.front(); } -- nothing else in
        # the function says "string", so the gate stays shut
        proj = angr.Project(STL2_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name="str_front")
        assert func is not None
        gated = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert "std::string::front(" not in gated.codegen.text, gated.codegen.text
        forced = proj.analyses[Decompiler].prep(fail_fast=True)(
            func, cfg=cfg.model, preset="full", options=[("known_patterns", ["std::string::front"])]
        )
        assert "std::string::front(" in forced.codegen.text, forced.codegen.text

    def test_circular_corroboration_is_rejected(self):
        # str_empty(const std::string &s) { return s.empty(); } is
        # `CmpEQ(Load(s + 8), 0)`, and the inner load is the very std::string::length
        # match that would open the gate. Naming the whole thing `empty` erases that
        # witness, so the corroboration is circular and must be refused -- the
        # function keeps the length() reading.
        proj = angr.Project(STL_BIN, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)
        proj.analyses.CompleteCallingConventions(cfg=cfg.model)
        func = cfg.functions.function(name="str_empty")
        assert func is not None
        gated = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model, preset="full")
        assert "std::string::empty(" not in gated.codegen.text, gated.codegen.text
        assert "std::string::length(" in gated.codegen.text, gated.codegen.text
        forced = proj.analyses[Decompiler].prep(fail_fast=True)(
            func, cfg=cfg.model, preset="full", options=ALL_PATTERNS_OPTION
        )
        assert "std::string::empty(" in forced.codegen.text, forced.codegen.text
