#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses.decompiler"  # pylint:disable=redefined-builtin

import re
import unittest

from .test_go_decompiler import GoDecompilationTarget, TargetChecks, go_binary


class MultiWordMaps(TargetChecks):
    """Map slots written or read through offsets (struct keys, slice values), and maps made into struct fields."""

    FUNCS = ("main.newStore", "main.put", "main.get", "main.flag", "main.bump")

    def test_multi_word_maps(self):
        for name, text in self.texts.items():
            for call in ("mapassign", "mapaccess", "makemap", "&type:"):
                assert call not in text, f"{call} survived in {name}:\n{text}"
        text = self.texts["main.newStore"]
        for ty in ("map[main.key][]int", "map[string]struct{}", "map[main.key]int"):
            assert f"= make({ty})\n" in text, text
        # struct key, slice value
        assert "s.byKey[k] = v\n" in self.texts["main.put"], self.texts["main.put"]
        assert re.search(r"^\s+(\w+), ok := s\.byKey\[k\]\n\s+return \1, ok\n", self.texts["main.get"], re.MULTILINE)
        # empty struct value
        assert "s.flags[name] = struct{}{}\n" in self.texts["main.flag"], self.texts["main.flag"]
        # increment with a struct key
        assert "s.counts[k] = s.counts[k] + 1\n" in self.texts["main.bump"], self.texts["main.bump"]


class TestMapValuesGo122(MultiWordMaps, GoDecompilationTarget):
    BINARY = go_binary("go1.22.5", "maps2")


class TestMapValuesGo127(MultiWordMaps, GoDecompilationTarget):
    BINARY = go_binary("go1.27.1", "maps2")


class TestMapValueFromPointerFieldGo127(GoDecompilationTarget):
    """A string/slice map value whose words are loaded from a struct field is that field, not a literal of words."""

    BINARY = go_binary("go1.27.1", "strvals_inlined")
    FUNCS = ("main.byName", "main.byItems")

    def test_map_value_from_pointer_field(self):
        assert "m[r.id] = r.name\n" in self.texts["main.byName"], self.texts["main.byName"]
        assert "m[r.id] = r.items\n" in self.texts["main.byItems"], self.texts["main.byItems"]


if __name__ == "__main__":
    unittest.main()
