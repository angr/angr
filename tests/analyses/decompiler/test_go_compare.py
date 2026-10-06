#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary


class RuntimeComparisonsAndCopies:
    """ifaceeq under its tab guard, makeslicecopy/typedslicecopy, and a byte array converted to a string."""

    FUNCS = ("main.same", "main.clonePtrs", "main.hexOf")

    def check_comparisons_and_copies(self):
        for name in RuntimeComparisonsAndCopies.FUNCS:
            text = self.texts[name]
            for call in ("ifaceeq", "makeslicecopy", "typedslicecopy", "slicebytetostring", "&type:"):
                assert call not in text, f"{call} survived in {name}:\n{text}"
        assert "return a == b\n" in self.texts["main.same"], self.texts["main.same"]
        assert "append([]*main.T{}, s...)" in self.texts["main.clonePtrs"], self.texts["main.clonePtrs"]
        assert re.search(r"return string\(\w+\[:2\]\)\n", self.texts["main.hexOf"]), self.texts["main.hexOf"]


class TestCompareGo122(RuntimeComparisonsAndCopies, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "compare")

    def test_compare(self):
        self.run_checks()


class TestCompareGo127(RuntimeComparisonsAndCopies, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "compare")
    FUNCS = (*RuntimeComparisonsAndCopies.FUNCS, "main.digits")

    def test_compare(self):
        self.run_checks()

    def check_division_by_constants(self):
        # signed modulo and unsigned division by constants
        digits = self.texts["main.digits"]
        assert re.search(r"^\s+\w+ := n % 8 \+ 1$", digits, re.MULTILINE), digits
        assert re.search(r"uint64\(\w+\) / 10$", digits, re.MULTILINE), digits
        assert ">> 63" not in digits, digits


if __name__ == "__main__":
    unittest.main()
