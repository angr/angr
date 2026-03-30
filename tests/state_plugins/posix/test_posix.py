#!/usr/bin/env python3
# pylint: disable=missing-class-docstring,no-self-use,line-too-long
from __future__ import annotations

import unittest

import claripy

from angr import SimState, SimFile
from angr.storage.file import SimFileDescriptorDuplex


class TestPosix(unittest.TestCase):
    def test_file_create(self):
        # Create a state first
        state = SimState(arch="AMD64", mode="symbolic")

        # Create a file
        fd = state.posix.open(b"test", 1)

        assert fd == 3

    def test_file_read(self):
        state = SimState(arch="AMD64", mode="symbolic")

        content = claripy.BVV(0xBADF00D, 32)
        content_size = content.size() // 8

        fd = state.posix.open(b"test", 1)
        simfd = state.posix.get_fd(fd)
        simfd.write_data(content)
        simfd.seek(0)
        simfd.read(0xC0000000, content_size)

        data = state.memory.load(0xC0000000, content_size)

        assert data is content

    def test_file_seek(self):
        # TODO: Make this test more complete

        state = SimState(arch="AMD64", mode="symbolic")

        # Normal seeking
        fd = state.posix.open(b"test1", 1)
        simfd = state.posix.get_fd(fd)
        simfd.seek(0, "start")
        assert state.solver.is_true(simfd.tell() == 0)
        state.posix.close(fd)

        # TODO: test case: seek cannot go beyond the file size or current file pos

        # seek should not work for stdin/stdout/stderr
        assert state.solver.is_false(state.posix.get_fd(0).seek(0))
        assert state.solver.is_false(state.posix.get_fd(1).seek(0))
        assert state.solver.is_false(state.posix.get_fd(2).seek(0))

        # Seek from the end
        state.fs.insert("test2", SimFile(name="qwer", size=20))
        fd = state.posix.open(b"test2", 1)
        simfd = state.posix.get_fd(fd)
        simfd.seek(0, "end")
        assert state.solver.is_true(simfd.tell() == 20)
        state.posix.close(fd)

        # seek to a symbolic position (whence symbolic end)
        fd = state.posix.open(b"unknown_size", 1)
        simfd = state.posix.get_fd(fd)
        real_end = state.fs.get("unknown_size").size
        simfd.seek(0, "end")
        assert real_end is simfd.tell()
        state.posix.close(fd)


    def test_stderr_is_duplex(self):
        """On a real system all three stdio fds are read+write on the same tty.
        Verify that stderr (fd 2) is duplex so concrete code that reads from it
        (e.g. glibc checking isatty) does not crash."""
        state = SimState(arch="AMD64", mode="symbolic")

        stderr_fd = state.posix.get_fd(2)
        assert isinstance(stderr_fd, SimFileDescriptorDuplex)

        # Writing to stderr should succeed.
        data = claripy.BVV(b"err")
        stderr_fd.write_data(data, size=3)

        # Reading from stderr should also succeed (reads from stdin stream).
        read_data, read_size = stderr_fd.read_data(1)
        assert read_data is not None


if __name__ == "__main__":
    unittest.main()
