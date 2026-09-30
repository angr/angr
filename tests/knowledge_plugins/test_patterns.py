#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import angr
from angr.analyses.decompiler.known_patterns import (
    KnownPattern,
    PAny,
    PAnyStmt,
    PAssign,
    PatternParam,
    PConst,
    PStmtSeq,
    PVVar,
)
from angr.angrdb import AngrDB
from angr.knowledge_base import KnowledgeBase
from angr.knowledge_plugins.patterns import Patterns, StoredPattern
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _pattern(name="p", call_name=None):
    return KnownPattern(
        name=name,
        display_name=name,
        call_name=call_name or name,
        pattern=PStmtSeq((PAssign(PVVar(name="a0"), PConst(value=7), optional=True), PAnyStmt(weight=2.0))),
        params=(PatternParam("a0", "int"),),
        returnty="void",
    )


class TestPatternsPlugin(unittest.TestCase):
    def test_is_a_default_plugin(self):
        kb = KnowledgeBase(None, name="t")
        assert isinstance(kb.patterns, Patterns)
        assert len(kb.patterns) == 0

    def test_add_get_remove(self):
        kb = KnowledgeBase(None, name="t")
        stored = kb.patterns.add(_pattern("swap"), min_similarity=0.6, origin_func=0x401000)

        assert "swap" in kb.patterns
        assert kb.patterns.get("swap") is stored
        assert stored.min_similarity == 0.6
        assert stored.origin_func == 0x401000
        assert kb.patterns.by_call_name("swap") is stored
        assert kb.patterns.remove("swap")
        assert not kb.patterns.remove("swap")

    def test_names_and_call_names_are_unique(self):
        kb = KnowledgeBase(None, name="t")
        kb.patterns.add(_pattern("a", call_name="do_a"))
        with self.assertRaises(ValueError):
            kb.patterns.add(_pattern("a", call_name="other"))
        with self.assertRaises(ValueError):
            kb.patterns.add(_pattern("b", call_name="do_a"))
        kb.patterns.add(_pattern("a", call_name="do_a"), replace=True)
        assert len(kb.patterns) == 1

    def test_enabled_filter(self):
        kb = KnowledgeBase(None, name="t")
        kb.patterns.add(_pattern("on"))
        kb.patterns.add(_pattern("off"), enabled=False)
        assert [p.name for p in kb.patterns.enabled_patterns()] == ["on"]
        kb.patterns.set_enabled("off", True)
        assert len(kb.patterns.enabled_patterns()) == 2

    def test_records_round_trip(self):
        kb = KnowledgeBase(None, name="t")
        kb.patterns.add(_pattern("p"), enabled=False, min_similarity=0.75, origin_func=0x1234)
        records = kb.patterns.to_records()

        kb2 = KnowledgeBase(None, name="t2")
        kb2.patterns.load_records(records)
        back = kb2.patterns.get("p")
        assert isinstance(back, StoredPattern)
        assert back.pattern == _pattern("p")
        assert back.enabled is False
        assert back.min_similarity == 0.75
        assert back.origin_func == 0x1234

    def test_pattern_with_a_callable_is_refused_at_store_time(self):
        kb = KnowledgeBase(None, name="t")
        bad = KnownPattern(name="bad", display_name="bad", call_name="bad", pattern=PAny(), params=(), where=bool)
        kb.patterns.add(bad)
        with self.assertRaises(ValueError):
            kb.patterns.to_records()


class TestPatternsAngrDB(unittest.TestCase):
    """Stored patterns and their settings survive an AngrDB dump/load cycle, removals included."""

    def test_roundtrip(self):
        proj = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        kb = proj.kb
        kb.patterns.add(_pattern("first"), min_similarity=0.5, origin_func=0x400580, require_verified=False)
        kb.patterns.add(_pattern("second"), enabled=False)

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            kb2 = AngrDB(nullpool=True).load(db_file).kb

            assert sorted(p.name for p in kb2.patterns) == ["first", "second"]
            first = kb2.patterns.get("first")
            assert first.pattern == _pattern("first")
            assert first.min_similarity == 0.5
            assert first.origin_func == 0x400580
            assert first.require_verified is False
            assert kb2.patterns.get("second").require_verified is True
            assert kb2.patterns.get("second").enabled is False

            kb.patterns.remove("second")
            AngrDB(proj, nullpool=True).dump(db_file)
            kb3 = AngrDB(nullpool=True).load(db_file).kb
            assert [p.name for p in kb3.patterns] == ["first"]


if __name__ == "__main__":
    unittest.main()
