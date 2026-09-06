#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary


class RuntimeComparisonsAndCopies(GoDecompilationTarget):
    """ifaceeq under its tab guard, makeslicecopy/typedslicecopy, and a byte array converted to a string."""

    FUNCS = ("main.same", "main.clonePtrs", "main.hexOf")

    def test_no_raw_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in ("ifaceeq", "makeslicecopy", "typedslicecopy", "slicebytetostring", "&type:"):
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_interface_equality(self):
        assert "return a == b\n" in self.texts["main.same"], self.texts["main.same"]

    def test_slice_clone(self):
        assert "append([]*main.T{}, s...)" in self.texts["main.clonePtrs"], self.texts["main.clonePtrs"]

    def test_array_to_string(self):
        assert re.search(r"return string\(\w+\[:2\]\)\n", self.texts["main.hexOf"]), self.texts["main.hexOf"]


class TestCompareGo122(RuntimeComparisonsAndCopies):
    BINARY = go_binary("go1.22.5", "compare")


class TestCompareGo127(RuntimeComparisonsAndCopies):
    BINARY = go_binary("go1.27.1", "compare")


if __name__ == "__main__":
    unittest.main()
