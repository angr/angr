#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest
from unittest import mock

from angr.ailment.expression import UnaryOp, VirtualVariable
from angr.ailment.expression import VirtualVariableCategory as VVC
from angr.ailment.statement import Assignment
from angr.go.optimization_passes.runtime_rewriter import GoRuntimeRewriter
from tests.analyses.decompiler.test_go_decompiler import GoDecompilationTarget, go_binary, go_func_addrs
from tests.common import load_project_with_scoped_cfg


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

    def test_closures(self):
        self.run_checks()

    def check_closure_records_and_bodies(self):
        # a static funcval is the function
        text = self.texts["main.firstUpper"]
        assert "strings.IndexFunc(s, main.firstUpper.func1)" in text, text
        assert "runtime.funcval" not in text

        # a heap closure record is a literal
        assert "return main.scaler.func1{X0: k}" in self.texts["main.scaler"]
        text = self.texts["main.counter"]
        assert re.search(r"return main\.counter\.func1\{X0: (\w+)\}, main\.counter\.func2\{X0: \1\}", text), text
        assert "new(struct" not in text and "field_8" not in text

        # the body reads its captures through ctx, a hidden first parameter rather than an unassigned local
        text = self.texts["main.scaler.func1"]
        assert self.header(text) == "func main.scaler.func1(ctx *struct { F uintptr; X0 int }, x int) int {", text
        assert "var ctx" not in text and "return ctx.X0 * x" in text, text
        text = self.texts["main.counter.func1"]
        assert "*ctx.X0 = " in text, text
        assert "field_" not in text

        # a stack closure record carries its captures: the slice captured by value is one field, reassembled from
        # its ptr/len/cap words
        text = self.texts["main.sortItems"]
        assert "sort.Slice(items, main.sortItems.func1{cap_0: items})" in text, text
        text = self.texts["main.sortItems.func1"]
        assert "func main.sortItems.func1(ctx *struct { F uintptr; cap_0 []main.item }, i int, j int) bool" in text, (
            text
        )
        assert "ctx.cap_0[j].score < ctx.cap_0[i].score" in text, text

    def check_calls_through_func_values(self):
        text = self.texts["main.applyAll"]
        assert re.search(r"\bf\(", text) and "(*(*int64)(&f))" not in text, text
        text = self.texts["main.main"]
        # the (func() int, func()) results are two variables, both called; the first is captured by the goroutine
        m = re.search(r"(\w+), (\w+) := main\.counter\(\)", text)
        assert m, text
        get, inc = m.groups()
        assert re.search(rf"\b{get}\(\)", text) and re.search(rf"\b{inc}\(\)", text), text
        assert "(*&" not in text, text
        assert re.search(rf"go main\.main\.func1\{{X0: \w+, X1: {get}\}}\(\)", text), text
        text = self.texts["main.main.func1"]
        assert "main.scaler(ctx.X1())" in text and "ctx.X0 <- " in text, text


class TestClosuresStrippedGo127(GoDecompilationTarget):
    """The same shapes without symbols or DWARF: descriptors and the pclntab carry the names and layouts."""

    BINARY = go_binary("go1.27.1", "closures_stripped")
    FUNCS = ("main.init", "main.scaler", "main.scaler.func1", "main.counter", "main.counter.func1")

    def test_closures_and_package_variables(self):
        text = self.texts["main.init"]
        assert re.search(r"main\.var_\d+ error", text), text
        assert re.search(r"main\.var_\d+ \[\]string", text), text
        # the map type survives as the runtime's hmap pointer once the variable model is cached
        assert re.search(r"main\.var_\d+ (map\[string\]int|\*runtime\.hmap)", text), text
        assert re.search(r"main\.var_\d+ = v\d+$", text, re.MULTILINE), text
        assert "g_" not in text[text.index("func main.init") :], text
        # strings.Split inlines to strings.genSplit(s, sep, 0, -1)
        assert 'strings.Split("carol,alice,bob", ",")' in text, text
        assert "genSplit" not in text

        assert re.search(r"return main\.scaler\.func1\{X0: \w+\}", self.texts["main.scaler"])
        assert "func main.scaler.func1(ctx *struct { F uintptr; X0 int }, " in self.texts["main.scaler.func1"]
        assert re.search(
            r"return main\.counter\.func1\{X0: (\w+)\}, main\.counter\.func2\{X0: \1\}", self.texts["main.counter"]
        )
        assert "*ctx.X0 = " in self.texts["main.counter.func1"]


class TestStackClosureSelfReference(unittest.TestCase):
    def test_record_ends_at_its_own_address(self):
        # i386 esbuild matchTSConfigPaths: _context_offsets over-claimed a word, and the slot there held &record (an
        # open-coded defer's func value). Folding it as a capture made the closure contain its own reference, which
        # _ExprRewriter expanded until RecursionError. No fixture has that shape, so it is injected into sortItems.
        path = go_binary("go1.27.1", "closures")
        addr = go_func_addrs(path, "main.sortItems")["main.sortItems"]
        proj, cfg = load_project_with_scoped_cfg(path, addr, call_tree_depth=1)

        orig_fold = GoRuntimeRewriter._fold_stack_closure
        orig_offsets = GoRuntimeRewriter._context_offsets
        orig_slot = GoRuntimeRewriter._stack_slot_assignment
        state = {}

        def fold(self, block, stmt):
            state["slot"] = stmt.dst if isinstance(stmt, Assignment) else None
            state["rewriter"], state["block"] = self, block
            return orig_fold(self, block, stmt)

        def offsets(self, code):
            out = dict(orig_offsets(self, code))
            slot = state["slot"]
            if out and slot is not None:
                # the first word past the record (the body reads only part of the captured slice)
                end = max(off + size for off, size in out.items())
                while orig_slot(state["block"], slot.stack_offset + end, None) is not None:
                    end += self.project.arch.bytes
                state["end"] = end
                out[end] = self.project.arch.bytes
            return out

        def slot_assignment(block, stack_offset, after_idx):
            slot, end = state.get("slot"), state.get("end")
            if slot is not None and end is not None and stack_offset == slot.stack_offset + end:
                o = state["rewriter"]
                dst = VirtualVariable(o._new_idx(), o._new_varid(), slot.bits, VVC.STACK, oident=stack_offset)
                ref = UnaryOp(o._new_idx(), "Reference", slot.copy(), bits=slot.bits)
                return Assignment(o._new_idx(), dst, ref)
            return orig_slot(block, stack_offset, after_idx)

        with (
            mock.patch.object(GoRuntimeRewriter, "_fold_stack_closure", fold),
            mock.patch.object(GoRuntimeRewriter, "_context_offsets", offsets),
            mock.patch.object(GoRuntimeRewriter, "_stack_slot_assignment", staticmethod(slot_assignment)),
        ):
            dec = proj.analyses.Decompiler(addr, cfg=cfg.model, flavor="go", fail_fast=True)
        assert "end" in state
        text = dec.codegen.text
        assert "sort.Slice(items, main.sortItems.func1{cap_0: items})" in text, text


if __name__ == "__main__":
    unittest.main()
