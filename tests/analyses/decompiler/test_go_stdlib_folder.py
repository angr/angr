#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary


class TestStackClearGo127Inlined(GoDecompilationTarget):
    """The zero-fill loops over the two stack map groups (go1.24+ non-escaping map literals) are memsets."""

    BINARY = go_binary("go1.27.1", "strvals_inlined")
    FUNCS = ("main.main",)

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


if __name__ == "__main__":
    unittest.main()
