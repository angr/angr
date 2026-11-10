#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.angrdb"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import sqlalchemy

import angr
from angr.angrdb import AngrDB
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


def _project() -> angr.Project:
    return angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)


def _roundtrip(proj: angr.Project, db_file: str) -> angr.Project:
    AngrDB(proj, nullpool=True).dump(db_file)
    return AngrDB(nullpool=True).load(db_file)


class TestAngrDBKbPlugins(unittest.TestCase):
    """
    Knowledge base plugins stored as JSON documents must survive an AngrDB dump/load cycle.
    """

    def test_obfuscations(self):
        proj = _project()
        o = proj.kb.obfuscations
        o.obfuscated_strings_analyzed = True
        o.type1_deobfuscated_strings[0x1000] = b"recovered string"
        o.type1_string_loader_candidates.add(0x1100)
        o.type2_deobfuscated_strings[0x1200] = b"\x00\xff"
        o.type2_string_loader_candidates.add(0x1300)
        o.type3_deobfuscated_strings[0x1400] = b"type3"
        o.type1_deobfuscated_apis[0x2000] = ("kernel32.dll", "CreateFileA")
        o.type2_deobfuscated_apis[0x2100] = "ReadFile"
        o.type3_deobfuscated_apis[0x2200] = ("ntdll.dll", "NtClose")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            o2 = _roundtrip(proj, db_file).kb.obfuscations
            assert o2.obfuscated_strings_analyzed is True
            assert o2.obfuscated_apis_analyzed is False
            assert o2.type1_deobfuscated_strings == {0x1000: b"recovered string"}
            assert o2.type1_string_loader_candidates == {0x1100}
            assert o2.type2_deobfuscated_strings == {0x1200: b"\x00\xff"}
            assert o2.type2_string_loader_candidates == {0x1300}
            assert o2.type3_deobfuscated_strings == {0x1400: b"type3"}
            assert o2.type1_deobfuscated_apis == {0x2000: ("kernel32.dll", "CreateFileA")}
            assert o2.type2_deobfuscated_apis == {0x2100: "ReadFile"}
            assert o2.type3_deobfuscated_apis == {0x2200: ("ntdll.dll", "NtClose")}

            # removals must persist across a re-dump into the same database
            del o.type1_deobfuscated_strings[0x1000]
            assert _roundtrip(proj, db_file).kb.obfuscations.type1_deobfuscated_strings == {}

    def test_custom_strings(self):
        proj = _project()
        cs = proj.kb.custom_strings
        first = cs.allocate(b"hello")
        second = cs.allocate(b"\x00w\x00s")

        with tempfile.TemporaryDirectory() as td:
            cs2 = _roundtrip(proj, os.path.join(td, "test.adb")).kb.custom_strings
            assert cs2[first] == b"hello"
            assert cs2[second] == b"\x00w\x00s"
            # new strings must not reuse the IDs of loaded ones
            assert cs2.allocate(b"new") == cs.string_id

    def test_database_without_plugin_data_table(self):
        proj = _project()
        proj.kb.obfuscations.type1_deobfuscated_strings[0x1000] = b"s"
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)

            engine = sqlalchemy.create_engine(f"sqlite:///{db_file}", poolclass=sqlalchemy.pool.NullPool)
            with engine.begin() as conn:
                conn.execute(sqlalchemy.text("DROP TABLE kb_plugin_data"))

            proj2 = AngrDB(nullpool=True).load(db_file)
            assert proj2.kb.obfuscations.type1_deobfuscated_strings == {}


if __name__ == "__main__":
    unittest.main()
