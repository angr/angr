#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import unittest

import cle

from angr.analyses.decompiler.structured_codegen.go import GoStructuredCodeGenerator
from tests.common import bin_location, load_project_with_scoped_cfg

test_location = os.path.join(bin_location, "tests")
GO_CORPUS = os.path.join(test_location, "x86_64", "go")


def go_binary(version: str, name: str) -> str:
    return os.path.join(GO_CORPUS, version, name)


def go_func_addrs(path: str, *names: str) -> dict[str, int]:
    """Resolve Go function names through the symbol table (pclntab-derived for stripped binaries)."""
    loader = cle.Loader(path, auto_load_libs=False)
    addrs = {}
    for name in names:
        sym = loader.find_symbol(name)
        assert sym is not None, f"{name} not found in {path}"
        addrs[name] = sym.rebased_addr
    return addrs


class GoDecompilationTarget(unittest.TestCase):
    """
    Per-binary base: pins one corpus binary and the functions to decompile. Decompilation runs once per class on a
    scoped CFG so every feature assertion stays cheap.
    """

    BINARY: str = ""
    FUNCS: tuple[str, ...] = ()
    CALL_TREE_DEPTH = 1

    proj = None
    cfg = None
    addrs: dict[str, int] = {}
    texts: dict[str, str] = {}

    @classmethod
    def setUpClass(cls):
        if not cls.BINARY:
            raise unittest.SkipTest("abstract target")
        cls.addrs = go_func_addrs(cls.BINARY, *cls.FUNCS)
        first, *rest = (cls.addrs[n] for n in cls.FUNCS)
        cls.proj, cls.cfg = load_project_with_scoped_cfg(
            cls.BINARY, first, extra_func_addrs=rest, call_tree_depth=cls.CALL_TREE_DEPTH
        )
        cls.texts = {name: cls.decompile(name) for name in cls.FUNCS}

    @classmethod
    def decompile(cls, name: str) -> str:
        func = cls.proj.kb.functions[cls.addrs[name]]
        dec = cls.proj.analyses.Decompiler(func, cfg=cls.cfg.model, flavor="go", fail_fast=True)
        assert dec.codegen is not None, f"no codegen for {name}"
        assert isinstance(dec.codegen, GoStructuredCodeGenerator)
        assert dec.codegen.text
        return dec.codegen.text

    @staticmethod
    def header(text: str) -> str:
        return next(line for line in text.splitlines() if line.startswith("func "))


class TestBasicsGo122(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "basics")
    FUNCS = ("main.fib", "main.add", "main.main")

    def test_go_flavor_is_selected(self):
        assert self.proj.is_go_binary
        assert (self.addrs["main.fib"], "go") in self.proj.kb.decompilations
        assert "go" in self.proj.kb.decompilations.all_flavors(self.addrs["main.fib"])

    def test_function_header_is_go(self):
        header = self.header(self.texts["main.fib"])
        assert header.startswith("func main.fib(")
        assert header.endswith((") int64 {", ") uint64 {")), header
        assert "long" not in header
        assert "void" not in self.texts["main.main"]

    def test_locals_use_var_declarations(self):
        text = self.texts["main.fib"]
        assert "    var " in text
        assert ";  //" not in text  # C-style declaration trailer

    def test_main_header(self):
        header = self.header(self.texts["main.main"])
        assert header.startswith("func main.main(")
        assert header.endswith(" {"), header

    def test_recursion_renders(self):
        assert "main.fib(" in self.texts["main.fib"].split("{", 1)[1]


class TestBasicsGo122Stripped(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "basics_stripped")
    FUNCS = ("main.fib",)

    def test_pclntab_names_survive_stripping(self):
        assert self.header(self.texts["main.fib"]).startswith("func main.fib(")


class TestBasicsGo127(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "basics")
    FUNCS = ("main.fib", "main.add")

    def test_function_header_is_go(self):
        assert self.header(self.texts["main.add"]).startswith("func main.add(")


if __name__ == "__main__":
    unittest.main()
