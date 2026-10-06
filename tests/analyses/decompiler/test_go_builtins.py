#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest
from typing import TYPE_CHECKING

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

    def test_checks_and_helpers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert "return s[i]\n" in self.texts["main.at"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])
        assert "return s[1:]\n" in self.texts["main.tail"]
        assert "return s[i:j]\n" in self.texts["main.window"]
        self.assert_absent(HELPER_NAMES)
        assert "= new(main.node)\n" in self.texts["main.newNode"]
        assert "runtime." not in self.body("main.newNode")
        assert "= make([]int, n)\n" in self.texts["main.mkslice"]
        assert "return append(s, v)\n" in self.texts["main.appendOne"]
        assert "if " not in self.body("main.appendOne")
        assert "return a + b\n" in self.texts["main.concat"]
        assert "return a + b + c\n" in self.texts["main.concat3"]
        assert "return a == b\n" in self.texts["main.equal"]
        assert "func()" not in self.texts["main.equal"]
        assert "return []byte(s)\n" in self.texts["main.toBytes"]
        assert "return string(b)\n" in self.texts["main.toString"]
        assert "copy(dst, src)\n" in self.texts["main.copyInts"]


class TestBuiltinsGo122Unoptimized(GoBuiltinsTarget):
    BINARY = go_binary("go1.22.5", "builtins_N")
    FUNCS = ("main.push", "main.newNode", "main.appendOne", "main.third", "main.concat", "main.equal", "main.toBytes")

    def test_checks_and_helpers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])
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

    def test_checks_and_helpers_are_removed(self):
        self.assert_absent(CHECK_NAMES)
        assert "return s[2]\n" in self.texts["main.third"]
        assert re.search(r"(\w+)\.next = main\.head\n\s+main\.head = \1\n", self.texts["main.push"])
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
    """pclntab still names the functions and runtime helpers; type names need DWARF, so only the check removal is
    asserted."""

    BINARY = go_binary("go1.22.5", "builtins_stripped")
    FUNCS = ("main.push", "main.third", "main.at")

    def test_checks_and_write_barriers_are_removed(self):
        assert self.header(self.texts["main.third"]).startswith("func main.third(")
        self.assert_absent(CHECK_NAMES)
        assert "if " not in self.body("main.third")
        assert "if " not in self.body("main.at")
        # the global keeps its placeholder name; the two stores are the whole body
        assert re.search(r"(\w+)\.\w+ = (g_\w+)\n\s+\2 = \1\n", self.texts["main.push"])
        assert "if " not in self.body("main.push")


# check mixins are combined with a target class; type them as one
if TYPE_CHECKING:
    BuiltinsChecks = GoBuiltinsTarget
else:
    BuiltinsChecks = object


class SliceGrowth(BuiltinsChecks):
    """growslice diamonds: a struct field, a loop-carried header in scalars, a variadic copy and array-backed bases."""

    FUNCS = ("main.(*bag).add", "main.(*bag).addName", "main.squares", "main.concat", "main.withPrefix", "main.pair")

    def assert_array_literal(self):
        pass

    def test_slice_growth(self):
        self.assert_absent(("growslice", "memmove", "typedslicecopy"))
        # append to a struct field
        assert "b.items = append(b.items, v)\n" in self.texts["main.(*bag).add"]
        assert "b.names = append(b.names, s)\n" in self.texts["main.(*bag).addName"]
        assert "if " not in self.body("main.(*bag).add")
        # variadic append
        assert "return append(a, b...)\n" in self.texts["main.concat"]
        assert re.search(r"return append\(\w+\[:2\], s\.\.\.\)\n", self.texts["main.withPrefix"])
        # in a loop, the header lives in three scalars; the appended element is the computed square
        text = self.texts["main.squares"]
        assert re.search(r"= append\(\[\]int\{ptr: \w+, len: \w+, cap: \w+\}, (\w+) \* \1\)\n", text), text
        self.assert_array_literal()


class TestSlicesGo122(SliceGrowth, GoBuiltinsTarget):
    BINARY = go_binary("go1.22.5", "slices")

    def assert_array_literal(self):
        assert re.search(r"return append\(\w+\[:1\], b\)\[:2\]\n", self.texts["main.pair"])


class TestSlicesGo127(SliceGrowth, GoBuiltinsTarget):
    BINARY = go_binary("go1.27.1", "slices")


if __name__ == "__main__":
    unittest.main()
