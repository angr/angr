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
    FUNCS = ("main.stage", "main.perSecond", "main.main")

    def test_float(self):
        self.run_checks()

    def check_float_compare(self):
        stage = self.texts["main.stage"]
        assert re.search(r"^\s+if \w+ > 0\.5 \{$", stage, re.MULTILINE), stage
        assert re.search(r"^\s+if \w+ != 1\.0 \{$", stage, re.MULTILINE), stage
        per_second = self.texts["main.perSecond"]
        assert "1000000000.0" in per_second, per_second
        assert "1000000.0" in per_second, per_second

    def check_float_literals_and_types(self):
        per_second = self.texts["main.perSecond"]
        # bit-pattern Consts of float-typed values print as float literals
        assert "0x3ff0000000000000" not in per_second, per_second
        assert re.search(r"^\s+\w+ = 1\.0$", per_second, re.MULTILINE), per_second
        # temporaries hoisted from float ITEs are float64, and int->float conversions are explicit
        assert "uint64" not in per_second, per_second
        assert len(re.findall(r"^\s+var \w+ float64$", per_second, re.MULTILINE)) == 2, per_second
        assert re.search(r"return float64\(\w+\) / \w+$", per_second, re.MULTILINE), per_second
        assert re.search(r"return float64\(\w+\) \* \w+$", per_second, re.MULTILINE), per_second
        # convT64's argument is the float's bits; the boxed value is the float itself
        main = self.texts["main.main"]
        assert re.search(r"fmt\.Println\(main\.stage\(\w+\), \w+\)", main), main


class TestFloatNaNGo127(GoDecompilationTarget):
    """x86 float compares test the parity flag for NaN; NaN tests must be valid Go, or folded where redundant."""

    BINARY = go_binary("go1.27.1", "floatnan_stripped")
    FUNCS = ("main.eqConst", "main.neConst", "main.eqVars", "main.isNaN", "main.root", "main.zeroIfEq")

    def test_float_nan(self):
        self.run_checks()

    def check_valid_go(self):
        for name, text in self.texts.items():
            for bad in ("UnaryOp", "CmpUN", "isnan", "isunordered"):
                assert bad not in text, f"{bad} in {name}:\n{text}"
        assert re.search(r"return math\.IsNaN\(\w+\)\n", self.texts["main.isNaN"]), self.texts["main.isNaN"]
        assert re.search(r"return math\.Sqrt\(\w+\)\n", self.texts["main.root"]), self.texts["main.root"]


if __name__ == "__main__":
    unittest.main()
