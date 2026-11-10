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
from angr.go.signature import GoVariable
from angr.sim_type import SimStruct, SimTypeInt, SimTypePointer, TypeRef
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

    def test_types(self):
        proj = _project()
        types = proj.kb.types
        node = SimStruct({"value": SimTypeInt(), "next": SimTypeInt()}, name="node")
        node.fields["next"] = SimTypePointer(node)
        types["node"] = TypeRef("node", node)
        types["uint_t"] = TypeRef("uint_t", SimTypeInt(signed=False), qualifier=["const"])
        types["node_ptr"] = TypeRef("node_ptr", SimTypePointer(types.get_own("node")))

        with tempfile.TemporaryDirectory() as td:
            types2 = _roundtrip(proj, os.path.join(td, "test.adb")).kb.types
            assert list(types2.iter_own_keys()) == ["node", "uint_t", "node_ptr"]
            node2 = types2.get_own("node")
            assert isinstance(node2.type, SimStruct)
            assert node2.type.fields["next"].pts_to is node2.type
            assert node2.type.size == types.get_own("node").size
            uint2 = types2.get_own("uint_t")
            assert uint2.type == SimTypeInt(signed=False).with_arch(proj.arch)
            assert uint2.qualifier == ["const"]
            # entries referring to other entries share them again
            assert types2.get_own("node_ptr").type.pts_to is node2

    def test_patches(self):
        proj = _project()
        proj.kb.patches.add_patch(0x400580, b"\x90\x90", comment="nop it")
        proj.kb.patches.add_patch(0x400590, b"\xcc")

        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            patches2 = _roundtrip(proj, db_file).kb.patches
            assert list(patches2.keys()) == [0x400580, 0x400590]
            assert patches2.get_patch(0x400580).new_bytes == b"\x90\x90"
            assert patches2.get_patch(0x400580).comment == "nop it"
            assert patches2.get_patch(0x400590).comment is None

            proj.kb.patches.remove_patch(0x400580)
            assert list(_roundtrip(proj, db_file).kb.patches.keys()) == [0x400590]

    def test_indirect_jumps(self):
        proj = _project()
        proj.kb.unresolved_indirect_jumps.add(0x400600)
        proj.kb.indirect_jumps.update_resolved_addrs(0x400610, [0x400700, 0x400710])

        with tempfile.TemporaryDirectory() as td:
            kb2 = _roundtrip(proj, os.path.join(td, "test.adb")).kb
            assert kb2.unresolved_indirect_jumps == {0x400600}
            assert kb2.resolved_indirect_jumps == {0x400610: [0x400700, 0x400710]}

    def test_go_signatures(self):
        proj = _project()
        sigs = proj.kb.go_signatures
        sigs.go_version = "go1.22.1"
        sigs.set_inferred(
            "main.f",
            ["int", "string"],
            results={0: ("error", 2)},
            caller_results={2: ("int", 1)},
            result_words=3,
            groups={0: (2, None)},
            return_words=3,
            fp_results={0: "float64"},
        )
        sigs.set_callsite_inferred(0x400580, caller_results={0: ("int", 1)}, result_words=1)
        sigs.set_closure_context(0x400590, "struct { F uintptr; X0 int }")
        keys = ["main.f", "callsite:0x400580", "closure:0x400590"]

        with tempfile.TemporaryDirectory() as td:
            proj2 = _roundtrip(proj, os.path.join(td, "test.adb"))
            assert proj2.kb.has_plugin("go_signatures")
            sigs2 = proj2.kb.go_signatures
            assert sigs2.go_version == "go1.22.1"
            assert sigs2.inferred_record("main.f") == sigs.inferred_record("main.f")
            assert sigs2.inferred_record("main.f").results == {0: ("error", 2)}
            assert sigs2.callsite_record(0x400580) == sigs.callsite_record(0x400580)
            assert sigs2.closure_context(0x400590) == "struct { F uintptr; X0 int }"
            # saved decompilations stay current only if versions and fingerprints are unchanged
            assert sigs2.version == sigs.version == 3
            for key in keys:
                assert sigs2.record_version(key) == sigs.record_version(key)
                assert sigs2.record_fingerprint(key) == sigs.record_fingerprint(key)

    def test_go_globals(self):
        proj = _project()
        go_globals = proj.kb.go_globals
        go_globals.note(GoVariable("runtime.firstmoduledata", 0x601000, "runtime.moduledata"))
        go_globals.mark_loaded()

        with tempfile.TemporaryDirectory() as td:
            proj2 = _roundtrip(proj, os.path.join(td, "test.adb"))
            assert proj2.kb.has_plugin("go_globals")
            go_globals2 = proj2.kb.go_globals
            assert go_globals2.loaded
            assert go_globals2.variable_at(0x601000) == GoVariable(
                "runtime.firstmoduledata", 0x601000, "runtime.moduledata"
            )
            assert go_globals2.addr_of("runtime.firstmoduledata") == 0x601000

    def test_go_plugins_not_created(self):
        # Go plugins must stay untouched for databases of non-Go binaries
        proj = _project()
        with tempfile.TemporaryDirectory() as td:
            proj2 = _roundtrip(proj, os.path.join(td, "test.adb"))
            assert not proj.kb.has_plugin("go_signatures")
            assert not proj2.kb.has_plugin("go_signatures")
            assert not proj2.kb.has_plugin("go_globals")

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
            assert not proj2.kb.patches.has_patches()
            assert list(proj2.kb.types.iter_own_keys()) == []


if __name__ == "__main__":
    unittest.main()
