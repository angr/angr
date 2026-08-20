#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.analyses"  # pylint:disable=redefined-builtin

import types
import unittest

from angr.knowledge_plugins.cfg import MemoryData, MemoryDataSort
from angr.sigs.suggest_signature import MIN_STRING_LEN, collect_query_strings


def cfg_model_with(*items: tuple[str, bytes]) -> types.SimpleNamespace:
    """
    Build the smallest stand-in for a CFG model that collect_query_strings reads: memory data whose content is
    already filled in, so nothing is loaded from a project.
    """
    memory_data = {}
    for i, (sort, content) in enumerate(items):
        addr = 0x1000 + i * 0x100
        md = MemoryData(addr, len(content), sort)
        md.content = content
        memory_data[addr] = md
    return types.SimpleNamespace(memory_data=memory_data)


class TestCollectQueryStrings(unittest.TestCase):
    def test_string_ends_at_its_first_nul(self):
        # data recovered past a terminator belongs to whatever follows it in memory
        model = cfg_model_with((MemoryDataSort.String, b"malloc failed here\x00trailing junk"))
        assert collect_query_strings(None, model) == ["malloc failed here"]

    def test_wide_string_ends_at_its_first_nul(self):
        # the shape seen in PE binaries: a short UTF-16 string, its terminator, then unrelated bytes that decode
        # into nonsense characters
        content = "AF".encode("utf-16-le") + b"\x00\x00" + b"\xb0\x6b\x03\x40\x01\x00"
        model = cfg_model_with((MemoryDataSort.UnicodeString, content))
        # "AF" is below the minimum length, so nothing is queried with at all
        assert collect_query_strings(None, model) == []

    def test_wide_string_long_enough_is_kept_without_its_tail(self):
        content = "hello world".encode("utf-16-le") + b"\x00\x00" + b"\xb0\x6b\x03\x40"
        model = cfg_model_with((MemoryDataSort.UnicodeString, content))
        assert collect_query_strings(None, model) == ["hello world"]

    def test_no_collected_string_contains_a_nul(self):
        model = cfg_model_with(
            (MemoryDataSort.String, b"a plain string"),
            (MemoryDataSort.String, b"before the nul\x00after the nul"),
            (MemoryDataSort.String, b"trailing nuls\x00\x00\x00"),
            (MemoryDataSort.UnicodeString, "wide string here".encode("utf-16-le") + b"\x00\x00\x30\x6b"),
        )
        collected = collect_query_strings(None, model)
        assert collected == ["a plain string", "before the nul", "trailing nuls", "wide string here"]
        assert all("\x00" not in s for s in collected)

    def test_short_strings_are_dropped_and_results_deduplicated(self):
        model = cfg_model_with(
            (MemoryDataSort.String, b"tiny"),
            (MemoryDataSort.String, b"long enough"),
            (MemoryDataSort.String, b"long enough"),
        )
        assert collect_query_strings(None, model) == ["long enough"]
        assert len("tiny") < MIN_STRING_LEN

    def test_long_strings_are_truncated_to_what_metadata_stores(self):
        model = cfg_model_with((MemoryDataSort.String, b"x" * 200))
        (collected,) = collect_query_strings(None, model)
        assert collected == "x" * 70

    def test_other_memory_data_sorts_are_ignored(self):
        model = cfg_model_with((MemoryDataSort.Integer, b"ignore this"))
        assert collect_query_strings(None, model) == []


if __name__ == "__main__":
    unittest.main()
