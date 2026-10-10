#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, TargetChecks, go_binary


class RuntimeComparisonsAndCopies(TargetChecks):
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


class TestFloatCompareGo127(GoDecompilationTarget):
    """Float constants in branch conditions and in ITE arms must not be read as ints by the Go passes."""

    BINARY = go_binary("go1.27.1", "floatcmp_stripped")
    FUNCS = ("main.stage", "main.perSecond")

    def test_float_compare(self):
        stage = self.texts["main.stage"]
        assert re.search(r"^\s+if \w+ > 0\.5 \{$", stage, re.MULTILINE), stage
        assert re.search(r"^\s+if \w+ != 1\.0 \{$", stage, re.MULTILINE), stage
        per_second = self.texts["main.perSecond"]
        assert "1000000000.0" in per_second, per_second
        assert "1000000.0" in per_second, per_second


if __name__ == "__main__":
    unittest.main()
