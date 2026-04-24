#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.angrdb"  # pylint:disable=redefined-builtin

import os
import shutil
import tempfile
import unittest

import angr
from angr.angrdb import AngrDB

from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestAngrDBLoadMissingBinary(unittest.TestCase):
    def test_load_after_original_binary_deleted(self):
        """AngrDB.load() must work even when the original binary no longer exists on disk.

        Regression test for https://github.com/angr/angr/issues/6367:
        previously the loader extracted binaries to a TemporaryDirectory,
        which caused a PermissionError on Windows when CLE memory-mapped
        the temp files and the context manager tried to delete them.
        The fix uses BytesIO so no temporary files are created at all.
        """
        src_bin = os.path.join(test_location, "x86_64", "fauxware")

        with tempfile.TemporaryDirectory() as td:
            # Copy the binary into a temporary location
            tmp_bin = os.path.join(td, "fauxware")
            shutil.copy2(src_bin, tmp_bin)

            # Create a project from the temporary copy and dump it
            proj = angr.Project(tmp_bin, auto_load_libs=False)
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)

            # Delete the original binary
            os.unlink(tmp_bin)
            assert not os.path.exists(tmp_bin)

            # Load should succeed without PermissionError
            proj2 = AngrDB(nullpool=True).load(db_file)

        # Verify the reloaded project is functional
        assert proj2.arch.name == proj.arch.name
        assert proj2.entry == proj.entry

    def test_load_ignores_different_binary_at_original_path(self):
        """AngrDB.load() must always use the stored binary content, even when
        a (potentially different) file exists at the original path.
        """
        fauxware = os.path.join(test_location, "x86_64", "fauxware")

        with tempfile.TemporaryDirectory() as td:
            tmp_bin = os.path.join(td, "target_binary")
            shutil.copy2(fauxware, tmp_bin)

            proj = angr.Project(tmp_bin, auto_load_libs=False)
            db_file = os.path.join(td, "test.adb")
            AngrDB(proj, nullpool=True).dump(db_file)

            original_entry = proj.entry
            original_arch = proj.arch.name

            # Overwrite the file at the original path with a completely
            # different binary.  If the loader were to read from disk
            # instead of the DB content, it would get the wrong binary.
            different_bin = os.path.join(test_location, "i386", "fauxware")
            shutil.copy2(different_bin, tmp_bin)

            # Sanity-check: the replacement really is different
            replacement_proj = angr.Project(tmp_bin, auto_load_libs=False)
            assert replacement_proj.arch.name != original_arch or replacement_proj.entry != original_entry

            # Load from DB — should get the *original* binary, not the
            # replacement sitting at the same path
            proj2 = AngrDB(nullpool=True).load(db_file)

        assert proj2.arch.name == original_arch
        assert proj2.entry == original_entry


if __name__ == "__main__":
    unittest.main()
