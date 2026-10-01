#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary

# compiler-inserted checks and runtime helpers that the Go passes must turn back into source-level constructs
CHECK_NAMES = ("gcWriteBarrier", "writeBarrier", "panicIndex", "panicSlice", "panicBounds", "panicdivide")
HELPER_NAMES = (
    "growslice",
    "newobject",
    "mallocgc",
    "makeslice",
    "concatstring",
    "memequal",
    "memmove",
    "slicebytetostring",
    "stringtoslicebyte",
)


class GoBuiltinsTarget(GoDecompilationTarget):
    def assert_absent(self, names, funcs=None):
        for name, text in self.texts.items():
            if funcs is not None and name not in funcs:
                continue
            with self.subTest(func=name):
                for needle in names:
                    assert needle not in text, f"{needle} survives in {name}:\n{text}"

    def body(self, name: str) -> str:
        return self.texts[name].split("{", 1)[1]


class TestBuiltinsGo122(GoBuiltinsTarget):
    BINARY = go_binary("go1.22.5", "builtins")
    FUNCS = (
        "main.push",
        "main.newNode",
        "main.mkslice",
        "main.appendOne",
        "main.third",
        "main.at",
        "main.tail",
        "main.window",
        "main.concat",
        "main.concat3",
        "main.equal",
        "main.toBytes",
        "main.toString",
        "main.copyInts",
    )

    def test_checks_and_write_barriers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert "return s[i]\n" in self.texts["main.at"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])

    def test_runtime_helpers_are_rewritten(self):
        self.assert_absent(HELPER_NAMES)

    def test_new(self):
        assert "= new(main.node)\n" in self.texts["main.newNode"]
        assert "runtime." not in self.body("main.newNode")

    def test_make(self):
        assert "= make([]int, n)\n" in self.texts["main.mkslice"]

    def test_append(self):
        assert "return append(s, v)\n" in self.texts["main.appendOne"]
        assert "if " not in self.body("main.appendOne")

    def test_string_concatenation(self):
        assert "return a + b\n" in self.texts["main.concat"]
        assert "return a + b + c\n" in self.texts["main.concat3"]

    def test_string_equality(self):
        assert "return a == b\n" in self.texts["main.equal"]
        assert "func()" not in self.texts["main.equal"]

    def test_conversions(self):
        assert "return []byte(s)\n" in self.texts["main.toBytes"]
        assert "return string(b)\n" in self.texts["main.toString"]

    def test_copy(self):
        assert "copy(dst, src)\n" in self.texts["main.copyInts"]

    def test_slicing(self):
        assert "return s[1:]\n" in self.texts["main.tail"]
        assert "return s[i:j]\n" in self.texts["main.window"]


class TestBuiltinsGo122Unoptimized(GoBuiltinsTarget):
    BINARY = go_binary("go1.22.5", "builtins_N")
    FUNCS = ("main.push", "main.newNode", "main.appendOne", "main.third", "main.concat", "main.equal", "main.toBytes")

    def test_checks_and_write_barriers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])

    def test_runtime_helpers_are_rewritten(self):
        self.assert_absent(HELPER_NAMES)
        assert "new(main.node)" in self.texts["main.newNode"]
        assert "append(s, v)" in self.texts["main.appendOne"]
        assert "a + b" in self.texts["main.concat"]
        assert "a == b" in self.texts["main.equal"]
        assert "[]byte(s)" in self.texts["main.toBytes"]


class TestBuiltinsGo127(GoBuiltinsTarget):
    BINARY = go_binary("go1.27.1", "builtins")
    FUNCS = (
        "main.push",
        "main.newNode",
        "main.mkslice",
        "main.appendOne",
        "main.third",
        "main.concat",
        "main.equal",
        "main.toBytes",
        "main.toString",
        "main.copyInts",
    )

    def test_checks_and_write_barriers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])

    def test_runtime_helpers_are_rewritten(self):
        self.assert_absent(HELPER_NAMES)
        # go1.25+ inlines newobject into a size-class specialized mallocgc
        assert "= new(main.node)\n" in self.texts["main.newNode"]
        assert "= make([]int, n)\n" in self.texts["main.mkslice"]
        assert "return append(s, v)\n" in self.texts["main.appendOne"]
        assert "return a + b\n" in self.texts["main.concat"]
        assert "return a == b\n" in self.texts["main.equal"]
        assert "return []byte(s)\n" in self.texts["main.toBytes"]
        assert "return string(b)\n" in self.texts["main.toString"]
        assert "copy(dst, src)\n" in self.texts["main.copyInts"]


class TestBuiltinsGo122Stripped(GoBuiltinsTarget):
    """pclntab still names the runtime helpers; type names need DWARF, so only the check removal is asserted."""

    BINARY = go_binary("go1.22.5", "builtins_stripped")
    FUNCS = ("main.push", "main.third", "main.at")

    def test_checks_and_write_barriers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "if " not in self.body("main.third")
        assert "if " not in self.body("main.at")
        # the global keeps its placeholder name; the two stores are the whole body
        assert re.search(r"(\w+)\.\w+ = (g_\w+)\n\s+\2 = \1\n", self.texts["main.push"])
        assert "if " not in self.body("main.push")


class SliceGrowth(GoBuiltinsTarget):
    """growslice diamonds: a struct field, a loop-carried header in scalars, a variadic copy and array-backed bases."""

    FUNCS = ("main.(*bag).add", "main.(*bag).addName", "main.squares", "main.concat", "main.withPrefix", "main.pair")

    def test_no_growth_helpers(self):
        self.assert_absent(("growslice", "memmove", "typedslicecopy"))

    def test_append_to_struct_field(self):
        assert "b.items = append(b.items, v)\n" in self.texts["main.(*bag).add"]
        assert "b.names = append(b.names, s)\n" in self.texts["main.(*bag).addName"]
        assert "if " not in self.body("main.(*bag).add")

    def test_append_variadic(self):
        assert "return append(a, b...)\n" in self.texts["main.concat"]
        assert re.search(r"return append\(\w+\[:2\], s\.\.\.\)\n", self.texts["main.withPrefix"])

    def test_append_in_loop(self):
        # the header lives in three scalars; the appended element is the computed square
        text = self.texts["main.squares"]
        assert re.search(r"= append\(\[\]int\{ptr: \w+, len: \w+, cap: \w+\}, (\w+) \* \1\)\n", text), text


class TestSlicesGo122(SliceGrowth):
    BINARY = go_binary("go1.22.5", "slices")

    def test_append_to_array_literal(self):
        assert re.search(r"return append\(\w+\[:1\], b\)\[:2\]\n", self.texts["main.pair"])


class TestSlicesGo127(SliceGrowth):
    BINARY = go_binary("go1.27.1", "slices")


if __name__ == "__main__":
    unittest.main()
