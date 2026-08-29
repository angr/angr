#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.rtdb"  # pylint:disable=redefined-builtin

import os
import shutil
import tempfile
import unittest
from unittest import mock

import angr
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")


class TestRuntimeDbBaseDir(unittest.TestCase):
    """
    Test the directory that a run-time database is created in.
    """

    def test_rtdb_base_set_after_angr_is_imported(self):
        # angr is imported when this module is imported, so setting RTDB_BASE here puts us in the situation of a
        # pytest fixture, a conftest.py, or any wrapper that configures the environment after importing angr.
        binary = os.path.join(test_location, "x86_64", "fauxware")
        with tempfile.TemporaryDirectory() as tmpdir, mock.patch.dict(os.environ, {"RTDB_BASE": tmpdir}):
            proj = angr.Project(binary, auto_load_libs=False)
            proj.kb.rtdb.open_db("testdb")
            try:
                assert os.listdir(tmpdir) == ["fauxware_angr_rtdb"], (
                    f"RTDB_BASE was set to {tmpdir}, which holds {os.listdir(tmpdir)}"
                )
            finally:
                proj.kb.rtdb.cleanup()

    def test_rtdb_defaults_to_the_directory_of_the_main_binary(self):
        with tempfile.TemporaryDirectory() as bindir, mock.patch.dict(os.environ):
            os.environ.pop("RTDB_BASE", None)
            binary = shutil.copy(os.path.join(test_location, "x86_64", "fauxware"), bindir)
            proj = angr.Project(binary, auto_load_libs=False)
            proj.kb.rtdb.open_db("testdb")
            try:
                assert sorted(os.listdir(bindir)) == ["fauxware", "fauxware_angr_rtdb"], (
                    f"the directory holding the binary holds {os.listdir(bindir)}"
                )
            finally:
                proj.kb.rtdb.cleanup()


if __name__ == "__main__":
    unittest.main()
