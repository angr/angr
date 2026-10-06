#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from tests.analyses.decompiler.test_go_decompiler import GoDecompilationTarget, go_binary


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


if __name__ == "__main__":
    unittest.main()
