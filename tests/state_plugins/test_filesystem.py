#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.state_plugins"  # pylint:disable=redefined-builtin

import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import angr
from angr.state_plugins.filesystem import SimHostFilesystem
from angr.state_plugins.posix import Flags
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

# The fields os.stat_result carries on Windows. st_rdev, st_blksize and st_blocks are Unix-only.
WINDOWS_STAT_FIELDS = (
    "st_mode",
    "st_ino",
    "st_dev",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_atime",
    "st_mtime",
    "st_ctime",
    "st_atime_ns",
    "st_mtime_ns",
    "st_ctime_ns",
)

_host_stat = os.stat


def windows_stat(path, *args, **kwargs):
    """
    What os.stat reports for the same file on a Windows host.
    """
    s = _host_stat(path, *args, **kwargs)
    return SimpleNamespace(
        st_file_attributes=0x80,
        st_reparse_tag=0,
        **{name: getattr(s, name) for name in WINDOWS_STAT_FIELDS},
    )


class TestSimHostFilesystem(unittest.TestCase):
    def _host_dir(self):
        """
        A host directory holding a five thousand byte hello.txt.
        """
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, True)
        with open(os.path.join(tmpdir, "hello.txt"), "wb") as fp:
            fp.write(b"hello" * 1000)
        return tmpdir

    @unittest.skipIf(sys.platform == "win32", "the fields compared here exist only on Unix")
    def test_stat_reports_the_host_values(self):
        tmpdir = self._host_dir()
        host = os.stat(os.path.join(tmpdir, "hello.txt"))

        stat = SimHostFilesystem(tmpdir)._get_stat("hello.txt")

        assert stat is not None
        assert stat.st_size == host.st_size
        assert stat.st_rdev == host.st_rdev
        assert stat.st_blksize == host.st_blksize
        assert stat.st_blocks == host.st_blocks

    def test_stat_on_a_host_without_the_unix_only_fields(self):
        tmpdir = self._host_dir()

        with mock.patch("os.stat", windows_stat):
            stat = SimHostFilesystem(tmpdir)._get_stat("hello.txt")

        assert stat is not None
        assert stat.st_size == 5000
        assert stat.st_rdev == 0
        assert stat.st_blksize == 0x1000
        assert stat.st_blocks == 5000 // 512 + 1

    def test_fstat_of_a_mounted_file_on_a_host_without_the_unix_only_fields(self):
        tmpdir = self._host_dir()
        project = angr.Project(os.path.join(test_location, "x86_64", "fauxware"), auto_load_libs=False)
        state = project.factory.blank_state(concrete_fs=True, chroot=tmpdir)
        fd = state.posix.open(b"/hello.txt", Flags.O_RDONLY)
        assert fd is not None

        with mock.patch("os.stat", windows_stat):
            stat = state.posix.fstat(fd)

        assert stat.st_size == 5000


if __name__ == "__main__":
    unittest.main()
