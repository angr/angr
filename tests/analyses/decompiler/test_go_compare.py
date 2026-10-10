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
        assert re.search(r"^\s+(\} else )?if \w+ [!=]= 1\.0 \{$", stage, re.MULTILINE), stage
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

    def check_redundant_nan_tests(self):
        # x == c: jne and jp both leave; Go's != is true for NaN, so the parity test folds away
        for name, cmp, taken, other in (
            ("main.eqConst", "a0 != 1.5", "2", "1"),
            ("main.neConst", "a0 != 2.5", "3", "4"),
            ("main.eqVars", "a0 != a1", "9", "7"),
        ):
            text = self.texts[name]
            assert re.search(rf"if {cmp} {{\n\s+return {taken}\n\s+}}\n\s+return {other}\n", text), text
            assert "IsNaN" not in text, text

    def check_zeroing_branch(self):
        # the float64 argument in xmm1 is zeroed (all 128 bits) on one path only
        text = self.texts["main.zeroIfEq"]
        assert re.search(r"if a0 == 4\.0 \{\n\s+a1 = 0\n\s+\}\n", text), text
        assert re.search(r"return .* \+ a1\n", text), text
        dec = self.proj.analyses.Decompiler(self.addrs["main.zeroIfEq"], cfg=self.cfg.model, fail_fast=True)
        assert dec.codegen is not None and "a1 = 0;" in dec.codegen.text, dec.codegen.text


class TestFloatResultsGo127(GoDecompilationTarget):
    """Float results travel in X0, X1, ... independently of RAX, RBX, ...; a caller's reads of them reach the guess."""

    BINARY = go_binary("go1.27.1", "floatret_stripped")
    FUNCS = ("main.main", "main.ratio", "main.grade", "main.bounds")

    def test_float_results(self):
        assert self.header(self.texts["main.ratio"]).endswith("(int, float64) {"), self.texts["main.ratio"]
        assert self.header(self.texts["main.grade"]).endswith("(string, float64) {"), self.texts["main.grade"]
        assert re.search(r"return \"A\", \w+ - ", self.texts["main.grade"]), self.texts["main.grade"]
        # bounds returns (float64, float64)
        assert self.header(self.texts["main.bounds"]).endswith("float64, float64) {"), self.texts["main.bounds"]


if __name__ == "__main__":
    unittest.main()
