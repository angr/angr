from __future__ import annotations

# pylint: disable=missing-class-docstring,no-self-use
import os.path
import unittest
from unittest import TestCase

import angr
from angr.analyses.decompiler.clinic import ClinicStage
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.known_patterns import ALL_LINKED_LIST_PATTERNS, KnownPatternFinder
from angr.knowledge_plugins.functions.function import PrototypeSource
from tests.common import bin_location

WDK_BIN = os.path.join(bin_location, "tests", "x86_64", "windows", "known_patterns_wdk_list.exe")
LINUX_BIN = os.path.join(bin_location, "tests", "x86_64", "decompiler", "known_patterns_linux_list")


def _decompile(bin_path: str, func_name: str):
    proj = angr.Project(bin_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model)
    func = cfg.functions.function(name=func_name)
    assert func is not None
    dec = proj.analyses[Decompiler].prep(fail_fast=True)(func, cfg=cfg.model)
    assert dec.codegen is not None and dec.codegen.text is not None
    return proj, cfg, func, dec


def _find(proj, func, dec, patterns=ALL_LINKED_LIST_PATTERNS):
    return proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph, patterns=patterns)


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
    # pattern set matches LIST_ENTRY (Flink/Blink) and list_head (next/prev).

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
        # the list patterns are opt-in; the default finder must not match them
        proj, _, func, dec = _decompile(LINUX_BIN, "lx_del")
        finder = proj.analyses[KnownPatternFinder].prep(fail_fast=True)(func, dec.ail_graph)
        assert not any(m.pattern in ALL_LINKED_LIST_PATTERNS for m in finder.matches)

    def test_unordered_matching_is_order_insensitive(self):
        # the WDK and Linux builds emit the init/remove stores in different
        # orders; a single ordered=False pattern matches both. Confirm the
        # patterns are declared unordered.
        from angr.analyses.decompiler.known_patterns import INITIALIZE_LIST_HEAD, REMOVE_ENTRY_LIST
        from angr.analyses.decompiler.known_patterns.dsl import PStmtSeq

        for p in (INITIALIZE_LIST_HEAD, REMOVE_ENTRY_LIST):
            assert isinstance(p.pattern, PStmtSeq) and p.pattern.ordered is False


if __name__ == "__main__":
    unittest.main()
