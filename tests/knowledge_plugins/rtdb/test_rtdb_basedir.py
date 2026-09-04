#!/usr/bin/env python3
# pylint:disable=no-self-use
from __future__ import annotations

__package__ = __package__ or "tests.knowledge_plugins.rtdb"  # pylint:disable=redefined-builtin

import os
import shutil
import tempfile
import unittest
from unittest import mock

import lmdb

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

    def test_rtdb_base_that_does_not_exist_yet_is_created(self):
        with tempfile.TemporaryDirectory() as bindir, tempfile.TemporaryDirectory() as parent:
            binary = shutil.copy(os.path.join(test_location, "x86_64", "fauxware"), bindir)
            basedir = os.path.join(parent, "rtdb", "bases")
            with mock.patch.dict(os.environ, {"RTDB_BASE": basedir}):
                proj = angr.Project(binary, auto_load_libs=False)
                proj.kb.rtdb.open_db("testdb")
                try:
                    assert os.listdir(bindir) == ["fauxware"], (
                        f"the directory holding the binary holds {os.listdir(bindir)}"
                    )
                    assert os.listdir(basedir) == ["fauxware_angr_rtdb"], (
                        f"RTDB_BASE was set to {basedir}, which holds {os.listdir(basedir)}"
                    )
                finally:
                    proj.kb.rtdb.cleanup()

    def test_rtdb_base_that_cannot_be_created_falls_back(self):
        with tempfile.TemporaryDirectory() as bindir, tempfile.TemporaryDirectory() as parent:
            binary = shutil.copy(os.path.join(test_location, "x86_64", "fauxware"), bindir)
            # a regular file at the path, so that creating the directory fails for every user
            basedir = os.path.join(parent, "occupied")
            with open(basedir, "w", encoding="utf-8"):
                pass
            with mock.patch.dict(os.environ, {"RTDB_BASE": basedir}):
                proj = angr.Project(binary, auto_load_libs=False)
                proj.kb.rtdb.open_db("testdb")
                try:
                    assert sorted(os.listdir(bindir)) == ["fauxware", "fauxware_angr_rtdb"], (
                        f"the directory holding the binary holds {os.listdir(bindir)}"
                    )
                finally:
                    proj.kb.rtdb.cleanup()

    def test_a_directory_is_only_handed_out_once(self):
        reserve = angr.knowledge_plugins.rtdb.rtdb.RuntimeDb._reserve_unique_db_dir  # pylint:disable=protected-access
        with tempfile.TemporaryDirectory() as basedir:
            paths = [reserve(basedir, "fauxware") for _ in range(3)]
            assert len(set(paths)) == 3, f"the same directory was handed out more than once: {paths}"
            assert sorted(os.listdir(basedir)) == sorted(os.path.basename(p) for p in paths)

    def test_a_reserved_directory_is_given_back_when_the_database_cannot_be_opened(self):
        binary = os.path.join(test_location, "x86_64", "fauxware")
        with tempfile.TemporaryDirectory() as basedir:
            proj = angr.Project(binary, auto_load_libs=False)
            rtdb = proj.kb.rtdb
            with mock.patch("lmdb.open", side_effect=lmdb.Error("no")):
                assert rtdb._open_new_lmdb_under(basedir, "fauxware") is None  # pylint:disable=protected-access
            assert os.listdir(basedir) == []
            # an exception _attempt_creating_lmdb does not catch leaves by the other path
            with mock.patch("lmdb.open", side_effect=KeyboardInterrupt), self.assertRaises(KeyboardInterrupt):
                rtdb._open_new_lmdb_under(basedir, "fauxware")  # pylint:disable=protected-access
            assert os.listdir(basedir) == []

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
