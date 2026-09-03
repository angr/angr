#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import os
import re
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
    FUNCS = (
        "main.fib",
        "main.add",
        "main.main",
        "main.parse",
        "main.divmod",
        "main.count",
        "main.bump",
        "runtime.acquirem",
    )

    def test_go_flavor_is_selected(self):
        assert self.proj.is_go_binary
        assert (self.addrs["main.fib"], "go") in self.proj.kb.decompilations
        assert "go" in self.proj.kb.decompilations.all_flavors(self.addrs["main.fib"])

    def test_function_header_is_go(self):
        header = self.header(self.texts["main.fib"])
        assert header.startswith("func main.fib(")
        assert header.endswith(") int {"), header
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

    def test_stack_growth_check_is_removed(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert "morestack" not in text
                # the compare against g.stackguard0 (r14+16) must not survive either
                assert "+ 16)" not in text

    def test_argument_spills_are_removed(self):
        # parse spills its string argument into the caller-provided slot and never reads it back
        body = self.texts["main.parse"].split("{", 1)[1]
        assert not re.search(r"^\s+\w+ = a\d+;$", body, re.MULTILINE), body

    def test_zero_register_is_not_a_variable(self):
        assert "xmm15" not in self.texts["main.main"]

    def test_prototypes_come_from_dwarf(self):
        assert self.header(self.texts["main.parse"]) == "func main.parse(s string) (int, error) {"
        assert self.header(self.texts["main.divmod"]) == "func main.divmod(a int, b int) (int, int) {"
        assert self.header(self.texts["main.fib"]) == "func main.fib(n int) int {"
        assert self.header(self.texts["main.main"]) == "func main.main() {"

    def test_multiple_results_are_returned_together(self):
        assert re.search(r"return \w+, \w+$", self.texts["main.divmod"], re.MULTILINE)
        parse = self.texts["main.parse"]
        # multi-result calls are destructured and the error checked idiomatically
        assert re.search(r"^\s+\w+, err = strconv\.Atoi\(s\)$", parse, re.MULTILINE), parse
        assert "if err != nil {" in parse
        assert "return 0, err\n" in parse
        assert "return 0, main.errNegative\n" in parse
        assert re.search(r"return \w+, nil$", parse, re.MULTILINE), parse
        assert "~r" not in parse

    def test_values_are_fused_at_call_sites(self):
        main = self.texts["main.main"]
        assert 'main.count("hello, world", ' in main
        assert re.search(r"main\.sum\(\w+\)$", main, re.MULTILINE), main
        assert re.search(r"main\.parse\([^,()]+\)$", main, re.MULTILINE), main

    def test_go_statement_syntax(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                body = text.split("{", 1)[1]
                assert not re.search(r";\s*$", body, re.MULTILINE), text
                assert "if (" not in body and "while" not in body and "->" not in body
        fib = self.texts["main.fib"]
        assert "if n > 1 {" in fib
        assert "return n\n" in fib
        parse = self.texts["main.parse"]
        assert "!= nil {" in parse or "== nil {" in parse
        assert "else if " in parse

    def test_package_variables_are_typed(self):
        main = self.texts["main.main"]
        assert "os.Args []string" in main
        assert "if len(os.Args) <= 1 {" in main
        assert "main.parse(os.Args[1])" in main
        assert "main.counter int" in self.texts["main.main"]

    def test_println_is_folded(self):
        main = self.texts["main.main"]
        assert re.search(r"^\s+println\([^\n]+, main\.counter\)$", main, re.MULTILINE), main
        assert "runtime.print" not in main
        assert not main.rstrip().endswith("return\n}")

    def test_range_loops(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                assert ".ptr[" not in text and ".len" not in text, text
        assert re.search(r"for \w+ = range s \{", self.texts["main.count"]), self.texts["main.count"]
        assert re.search(r"if s\[\w+\] == c \{", self.texts["main.count"])
        assert re.search(r"for \w+ = range xs \{", self.texts["main.bump"])
        assert "return xs\n" in self.texts["main.bump"]

    def test_g_register_is_named(self):
        text = self.texts["runtime.acquirem"]
        assert "var g *runtime.g" in text
        assert "g.m" in text


class TestIfaceGo122(GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "iface")
    FUNCS = ("main.describe", "main.box", "main.unbox", "main.asSquare")

    def test_interface_method_calls(self):
        describe = self.texts["main.describe"]
        assert re.search(r"= s\.Name\(\)$", describe, re.MULTILINE), describe
        assert "strconv.Itoa(s.Area())" in describe
        assert ".tab[" not in describe

    def test_type_descriptors_are_named(self):
        assert "&type:int" in self.texts["main.box"]
        assert "&type:int" in self.texts["main.unbox"]
        assert "&go:itab.*main.Square,main.Shape" in self.texts["main.asSquare"]


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
