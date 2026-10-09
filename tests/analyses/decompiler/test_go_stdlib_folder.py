#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest
from unittest import mock

from angr.go.optimization_passes import GoSmallMapFolder

from .test_go_decompiler import GoDecompilationTarget, go_binary


class TestStackClearGo127Inlined(GoDecompilationTarget):
    """
    The zero-fill loops over the two stack map groups (go1.24+ non-escaping map literals) are memsets. The map fold
    removes them altogether, so it is off here.
    """

    BINARY = go_binary("go1.27.1", "strvals_inlined")
    FUNCS = ("main.main",)

    @classmethod
    def setUpClass(cls):
        with mock.patch.object(GoSmallMapFolder, "_check", lambda self: (False, None)):
            super().setUpClass()

    def test_stack_clear(self):
        text = self.texts["main.main"]
        assert re.search(r"memset\(&\w+, 0, 200\)\n", text), text
        assert re.search(r"memset\(&\w+, 0, 264\)\n", text), text
        assert "for " not in text, text


class TestListAccessorLookalikeGo127(GoDecompilationTarget):
    """
    ``len(s.flags)`` reads a map pointer at the offset of ``List.len``: ``s.flags == nil ? 0 : *s.flags`` dereferences
    that pointer, not ``s.root``, so it is no ``Front()``.
    """

    BINARY = go_binary("go1.27.1", "maps2")
    FUNCS = ("main.main",)

    def test_not_list_front(self):
        text = self.texts["main.main"]
        assert "container/list" not in text, text
        assert re.search(r"if \w+\.flags == nil \{", text), text


LISTS_127 = go_binary("go1.27.1", "lists_inlined")


class TestListInsertGo127Inlined(GoDecompilationTarget):
    """list.New and PushBack/PushFront (lazyInit + insert) inlined into their callers fold back into the calls."""

    BINARY = LISTS_127
    FUNCS = ("main.newList", "main.pushBack", "main.pushFront")

    def test_list_insert(self):
        self.run_checks()

    def check_new(self):
        text = self.texts["main.newList"]
        assert "return container/list.New()\n" in text, text
        assert "new(container/list.List)" not in text, text

    def check_push_back(self):
        # at = l.root.prev is read by the call now
        text = self.texts["main.pushBack"]
        assert "return container/list.(*List).PushBack(l, v)\n" in text, text
        assert "new(container/list.Element)" not in text and "root.prev" not in text and ".len" not in text, text

    def check_push_front(self):
        # the unused result makes the call a statement
        text = self.texts["main.pushFront"]
        assert re.search(r"^    container/list\.\(\*List\)\.PushFront\(l, s\)\n", text, re.MULTILINE), text
        assert "new(container/list.Element)" not in text and ".len" not in text, text


class TestListAccessorsGo127Inlined(GoDecompilationTarget):
    """Front/Back and Element.Next/Prev inlined into their callers fold back into the calls."""

    BINARY = LISTS_127
    FUNCS = ("main.front", "main.back", "main.nextValue", "main.prevOf", "main.newFront", "main.newRing")

    def test_list_accessors(self):
        self.run_checks()

    def check_front_back(self):
        assert "return container/list.(*List).Front(l)\n" in self.texts["main.front"], self.texts["main.front"]
        assert "return container/list.(*List).Back(l)\n" in self.texts["main.back"], self.texts["main.back"]

    def check_front_of_new(self):
        text = self.texts["main.newFront"]
        m = re.search(r"(\w+) := container/list\.New\(\)\n", text)
        assert m, text
        assert f"return container/list.(*List).Front({m.group(1)})\n" in text, text

    def check_next(self):
        text = self.texts["main.nextValue"]
        m = re.search(r"(\w+) := container/list\.\(\*Element\)\.Next\(e\)\n", text)
        assert m, text
        assert f"if {m.group(1)} == nil {{" in text and f"return {m.group(1)}.Value\n" in text, text
        assert "e.list" not in text, text

    def check_prev(self):
        text = self.texts["main.prevOf"]
        assert "*out = container/list.(*Element).Prev(e)\n" in text, text
        assert "e.list" not in text, text

    def check_new_of_other_type(self):
        # n and head sit at List.len and List.root.next, but r is a new(main.ring)
        text = self.texts["main.newRing"]
        assert "container/list" not in text, text
        assert re.search(r"if \w+\.n == 0 \{", text), text


if __name__ == "__main__":
    unittest.main()
