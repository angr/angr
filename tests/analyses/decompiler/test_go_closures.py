#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from tests.analyses.decompiler.test_go_decompiler import GoDecompilationTarget, go_binary


class TestClosuresGo127(GoDecompilationTarget):
    """Closure records built in a parent read as func literals; the bodies read their captures through ``ctx``."""

    BINARY = go_binary("go1.27.1", "closures")
    # parents first: a body is typed from the record its parent built
    FUNCS = (
        "main.firstUpper",
        "main.scaler",
        "main.scaler.func1",
        "main.applyAll",
        "main.sortItems",
        "main.sortItems.func1",
        "main.counter",
        "main.counter.func1",
        "main.main",
        "main.main.func1",
    )

    def test_static_funcval_is_the_function(self):
        text = self.texts["main.firstUpper"]
        assert "strings.IndexFunc(s, main.firstUpper.func1)" in text, text
        assert "runtime.funcval" not in text

    def test_heap_closure_record_is_a_literal(self):
        assert "return main.scaler.func1{X0: k}" in self.texts["main.scaler"]
        text = self.texts["main.counter"]
        assert re.search(r"return main\.counter\.func1\{X0: (\w+)\}, main\.counter\.func2\{X0: \1\}", text), text
        assert "new(struct" not in text and "field_8" not in text

    def test_closure_body_reads_captures_through_ctx(self):
        text = self.texts["main.scaler.func1"]
        assert "var ctx *struct { F uintptr; X0 int }" in text, text
        assert "return ctx.X0 * x" in text, text
        text = self.texts["main.counter.func1"]
        assert "*ctx.X0 = " in text, text
        assert "field_" not in text

    def test_stack_closure_record_carries_captures(self):
        # the slice captured by value is one field, reassembled from its ptr/len/cap words
        text = self.texts["main.sortItems"]
        assert "sort.Slice(items, main.sortItems.func1{cap_0: items})" in text, text
        text = self.texts["main.sortItems.func1"]
        assert "var ctx *struct { F uintptr; cap_0 []main.item }" in text, text
        assert "ctx.cap_0[j].score < ctx.cap_0[i].score" in text, text

    def test_calls_through_func_values(self):
        text = self.texts["main.applyAll"]
        assert re.search(r"\bf\(", text) and "(*(*int64)(&f))" not in text, text
        text = self.texts["main.main"]
        # the (func() int, func()) results are two variables (older renders folded the tuple into count[2])
        assert re.search(r"count, count1 := main\.counter\(\)", text) or "count[0]()" in text, text
        assert re.search(r"\bcount(\[0\])?\(\)", text) and re.search(r"\bcount(1|\[1\])\(\)", text), text
        assert "(*&" not in text, text
        assert re.search(r"go main\.main\.func1\{X0: \w+, X1: count(\[0\])?\}\(\)", text), text
        text = self.texts["main.main.func1"]
        assert "main.scaler(ctx.X1())" in text and "ctx.X0 <- " in text, text


class TestClosuresStrippedGo127(GoDecompilationTarget):
    """The same shapes without symbols or DWARF: descriptors and the pclntab carry the names and layouts."""

    BINARY = go_binary("go1.27.1", "closures_stripped")
    FUNCS = ("main.init", "main.scaler", "main.scaler.func1", "main.counter", "main.counter.func1")

    def test_package_variables_from_initializers(self):
        text = self.texts["main.init"]
        assert re.search(r"main\.var_\d+ error", text), text
        assert re.search(r"main\.var_\d+ \[\]string", text), text
        # the map type survives as the runtime's hmap pointer once the variable model is cached
        assert re.search(r"main\.var_\d+ (map\[string\]int|\*runtime\.hmap)", text), text
        assert re.search(r"main\.var_\d+ = v\d+$", text, re.MULTILINE), text
        assert "g_" not in text[text.index("func main.init") :], text

    def test_closures(self):
        assert re.search(r"return main\.scaler\.func1\{X0: \w+\}", self.texts["main.scaler"])
        assert "var ctx *struct { F uintptr; X0 int }" in self.texts["main.scaler.func1"]
        assert re.search(
            r"return main\.counter\.func1\{X0: (\w+)\}, main\.counter\.func2\{X0: \1\}", self.texts["main.counter"]
        )
        assert "*ctx.X0 = " in self.texts["main.counter.func1"]


class TestStackClosuresConc(GoDecompilationTarget):
    """A deferred closure capturing a named result by address: the body's context knows it as *any."""

    BINARY = go_binary("go1.27.1", "conc")
    FUNCS = ("main.safeDiv", "main.safeDiv.func1")

    def test_address_capture_is_typed(self):
        assert re.search(r"defer main\.safeDiv\.func1\{cap_0: &\w+\}\(\)", self.texts["main.safeDiv"])
        text = self.texts["main.safeDiv.func1"]
        assert "var ctx *struct { F uintptr; cap_0 *any }" in text, text
        assert "field_" not in text and "recover()" in text, text


if __name__ == "__main__":
    unittest.main()
