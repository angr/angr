from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import (
    ALL_LINKED_LIST_TEMPLATES,
    ALL_PROTOBUF_TEMPLATES,
    ALL_STL_TEMPLATES,
    ALL_VECTOR_MATH_TEMPLATES,
    KnownPatternFinder,
)
from angr.knowledge_plugins.functions.function import PrototypeSource
from tests.common import bin_location

WDK_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_list.exe")
LINUX_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_linux_list")
STL_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_stl")
PB_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_protobuf")
VM_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_vecmath")
MSVC_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_stl_msvc_17_x64.exe")
MSVC_X86_BIN = os.path.join(bin_location, "tests", "i386", "windows", "known_patterns_stl_msvc_17_x86.exe")

_LINKED_LIST_NAMES = {"is_list_empty", "initialize_list_head", "remove_entry_list"}
_PROTOBUF_NAMES = {"protobuf_has_field", "protobuf_set_has_field", "protobuf_clear_has_field"}
_VECMATH_NAMES = {"vec_dot3", "vec_length_sq"}


def _decompile(bin_path: str, func_name: str | None = None, addr: int | None = None):
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name) if func_name is not None else cfg.functions.function(addr=addr)
    assert func is not None
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    return proj, cfg, func, dec


def _find(proj, func, dec, templates=ALL_LINKED_LIST_TEMPLATES):
    return proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=templates)


def _outline_text(proj, cfg, func, dec, finder):
    result = finder.outline(finder.matches[0])
    del dec._variable_kb.variables[func.addr]
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

    def test_empty_capacity_enabled_by_default(self):
        proj, _, func, dec = _decompile(STL_BIN, "vec_empty")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert any(m.pattern.name == "std_vector_int_empty" for m in finder.matches)


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


if __name__ == "__main__":
    unittest.main()
