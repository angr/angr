#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, go_binary


class MultiWordMaps(GoDecompilationTarget):
    """Map slots written or read through offsets (struct keys, slice values), and maps made into struct fields."""

    FUNCS = ("main.newStore", "main.put", "main.get", "main.flag", "main.bump")

    def test_no_raw_map_runtime_calls(self):
        for name, text in self.texts.items():
            with self.subTest(func=name):
                for call in ("mapassign", "mapaccess", "makemap", "&type:"):
                    assert call not in text, f"{call} survived in {name}:\n{text}"

    def test_make_into_fields(self):
        text = self.texts["main.newStore"]
        for ty in ("map[main.key][]int", "map[string]struct{}", "map[main.key]int"):
            assert f"= make({ty})\n" in text, text

    def test_struct_key_and_slice_value(self):
        assert "s.byKey[k] = v\n" in self.texts["main.put"], self.texts["main.put"]
        assert re.search(r"^\s+(\w+), ok := s\.byKey\[k\]\n\s+return \1, ok\n", self.texts["main.get"], re.MULTILINE)

    def test_empty_struct_value(self):
        assert "s.flags[name] = struct{}{}\n" in self.texts["main.flag"], self.texts["main.flag"]

    def test_increment_with_struct_key(self):
        assert "s.counts[k] = s.counts[k] + 1\n" in self.texts["main.bump"], self.texts["main.bump"]


class TestMapValuesGo122(MultiWordMaps):
    BINARY = go_binary("go1.22.5", "maps2")


class TestMapValuesGo127(MultiWordMaps):
    BINARY = go_binary("go1.27.1", "maps2")


if __name__ == "__main__":
    unittest.main()
