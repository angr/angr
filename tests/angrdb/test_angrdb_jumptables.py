#!/usr/bin/env python3
from __future__ import annotations

__package__ = __package__ or "tests.angrdb"  # pylint:disable=redefined-builtin

import os
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAngrDBJumpTables(unittest.TestCase):
    def test_jump_tables_roundtrip(self):
        """Verify that CFGModel.jump_tables survive an AngrDB dump/load cycle."""
        bin_path = os.path.join(test_location, "x86_64", "fmt-rust-stripped")
        proj = angr.Project(bin_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True)

        orig_jt = cfg.model.jump_tables
        assert len(orig_jt) > 0, "expected jump tables from CFGFast"

        # dump and reload
        with tempfile.TemporaryDirectory() as td:
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)
            proj2 = AngrDB(nullpool=True).load(db_file)

        loaded_jt = proj2.kb.cfgs["CFGFast"].jump_tables

        # same set of keys
        assert set(orig_jt.keys()) == set(loaded_jt.keys()), (
            f"jump_tables keys mismatch: "
            f"only_in_orig={set(orig_jt.keys()) - set(loaded_jt.keys())}, "
            f"only_in_loaded={set(loaded_jt.keys()) - set(orig_jt.keys())}"
        )

        # compare every IndirectJump field-by-field
        for addr in orig_jt:
            orig = orig_jt[addr]
            loaded = loaded_jt[addr]

            assert orig.addr == loaded.addr
            assert orig.ins_addr == loaded.ins_addr
            assert orig.func_addr == loaded.func_addr
            assert orig.jumpkind == loaded.jumpkind
            assert orig.stmt_idx == loaded.stmt_idx
            assert set(orig.resolved_targets) == set(loaded.resolved_targets)
            assert orig.jumptable == loaded.jumptable
            assert orig.type == loaded.type

            # compare the JumptableInfo list
            assert len(orig.jumptables) == len(loaded.jumptables), (
                f"jumptables count mismatch at {hex(addr)}: "
                f"{len(orig.jumptables)} vs {len(loaded.jumptables)}"
            )
            for i, (jt_orig, jt_loaded) in enumerate(zip(orig.jumptables, loaded.jumptables)):
                assert jt_orig.addr == jt_loaded.addr, (
                    f"jumptable[{i}].addr mismatch at {hex(addr)}"
                )
                assert jt_orig.size == jt_loaded.size
                assert jt_orig.entry_size == jt_loaded.entry_size
                assert jt_orig.entries == jt_loaded.entries


if __name__ == "__main__":
    unittest.main()