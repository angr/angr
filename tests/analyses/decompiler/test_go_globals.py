#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

import cle

from tests.analyses.decompiler.test_go_decompiler import GoDecompilationTarget, go_binary


class TestGoGlobalsStripped(GoDecompilationTarget):
    """Package-level variables of a stripped binary: runtime globals by shape, package variables by initializer."""

    BINARY = go_binary("go1.27.1", "basics_stripped")
    FUNCS = ("main.init", "main.main")

    def test_runtime_globals_are_located_by_shape(self):
        # the unstripped twin carries the data symbols the shapes must reproduce
        loader = cle.Loader(go_binary("go1.27.1", "basics"), auto_load_libs=False)
        found = {v.name: v.addr for v in self.proj.kb.go_globals.variables.values()}
        for name in ("runtime.writeBarrier", "runtime.zerobase", "runtime.staticuint64s", "runtime.firstmoduledata"):
            assert found[name] == loader.find_symbol(name).rebased_addr, name

    def test_package_variables_are_typed_from_initializers(self):
        init = self.texts["main.init"]
        assert "main.var_0 error" in init
        assert "main.var_0.tab = " in init and "main.var_0.data = " in init
        main = self.texts["main.main"]
        assert re.search(r"os\.var_\d+ \[\]string", main), main
        assert re.search(r"if len\(os\.var_\d+\) <= 1 \{", main), main


class TestGoMapGlobals(GoDecompilationTarget):
    """A map-typed package variable keeps its Go type through the variable manager (not *runtime.hmap)."""

    BINARY = go_binary("go1.27.1", "maps_stripped")
    FUNCS = ("main.init", "main.main")

    def test_map_global_keeps_its_type(self):
        init = self.texts["main.init"]
        assert re.search(r"main\.var_\d+ map\[string\]int", init), init
        assert re.search(r"(\w+) := make\(map\[string\]int\)\n(.*\n)*\s+main\.var_\d+ = \1$", init, re.MULTILINE), init
        main = self.texts["main.main"]
        assert re.search(r"main\.lookup\(main\.var_\d+, \"two\"\)", main), main
        assert "runtime.hmap" not in init + main


class TestGoMapGlobalsDwarf(GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "maps")
    FUNCS = ("main.init",)

    def test_map_global_keeps_its_type(self):
        init = self.texts["main.init"]
        assert "main.table map[string]int" in init and "main.table = v" in init, init


if __name__ == "__main__":
    unittest.main()
