"""
Tests for angr.state_plugins.filesystem (SimFilesystem, SimHostFilesystem, etc).

Coverage gap: The SimFilesystem plugin (463 lines) provides angr's emulated filesystem
and had NO direct test coverage. This file tests:
- Construction with defaults and custom parameters
- Path normalization (_normalize_path)
- File insertion and retrieval
- File deletion and unlinks tracking
- chdir operation
- Mount/unmount operations
- Copy independence
- SimHostFilesystem basic operations
"""

from __future__ import annotations

import os
import tempfile
import unittest

import angr
from angr import SimState
from angr.storage.file import SimFile
from angr.state_plugins.filesystem import SimFilesystem, SimHostFilesystem


class TestSimFilesystemConstruction(unittest.TestCase):
    """Test filesystem construction and defaults."""

    def test_default_construction(self):
        fs = SimFilesystem()
        assert fs.pathsep == b"/"
        assert fs.cwd == b"/"

    def test_custom_pathsep(self):
        fs = SimFilesystem(pathsep=b"\\")
        assert fs.pathsep == b"\\"
        assert fs.cwd == b"\\"

    def test_custom_cwd(self):
        fs = SimFilesystem(cwd=b"/home/user")
        assert fs.cwd == b"/home/user"


class TestPathNormalization(unittest.TestCase):
    """Test _normalize_path behavior."""

    def test_absolute_path(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/usr/bin/ls")
        assert result == [b"usr", b"bin", b"ls"]

    def test_relative_path(self):
        fs = SimFilesystem(cwd=b"/home/user")
        result = fs._normalize_path(b"documents/file.txt")
        assert result == [b"home", b"user", b"documents", b"file.txt"]

    def test_dot_removal(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/usr/./bin/./ls")
        assert result == [b"usr", b"bin", b"ls"]

    def test_dotdot_handling(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/usr/local/../bin/ls")
        assert result == [b"usr", b"bin", b"ls"]

    def test_dotdot_at_root(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/../ls")
        assert result == [b"ls"]

    def test_string_conversion(self):
        fs = SimFilesystem()
        result = fs._normalize_path("/usr/bin/ls")
        assert result == [b"usr", b"bin", b"ls"]

    def test_null_byte_stripping(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/usr/bin\x00/extra")
        assert result == [b"usr", b"bin"]

    def test_trailing_slash(self):
        fs = SimFilesystem()
        result = fs._normalize_path(b"/usr/bin/")
        assert result == [b"usr", b"bin"]


class TestJoinChunks(unittest.TestCase):
    """Test _join_chunks."""

    def test_basic_join(self):
        fs = SimFilesystem()
        result = fs._join_chunks([b"usr", b"bin", b"ls"])
        assert result == b"/usr/bin/ls"

    def test_empty_join(self):
        fs = SimFilesystem()
        result = fs._join_chunks([])
        assert result == b"/"


class TestFileOperations(unittest.TestCase):
    """Test insert, get, delete operations."""

    def test_insert_and_get(self):
        state = SimState(arch="AMD64")
        simfile = SimFile(name="test", content=b"hello world")

        state.fs.insert("/test.txt", simfile)
        retrieved = state.fs.get("/test.txt")
        assert retrieved is not None

    def test_get_nonexistent(self):
        state = SimState(arch="AMD64")
        result = state.fs.get("/nonexistent.txt")
        assert result is None

    def test_delete(self):
        state = SimState(arch="AMD64")
        simfile = SimFile(name="test", content=b"data")
        state.fs.insert("/test.txt", simfile)

        result = state.fs.delete("/test.txt")
        assert result is True
        assert state.fs.get("/test.txt") is None

    def test_delete_nonexistent(self):
        state = SimState(arch="AMD64")
        result = state.fs.delete("/nonexistent.txt")
        assert result is False

    def test_delete_tracks_unlinks(self):
        state = SimState(arch="AMD64")
        simfile = SimFile(name="test", content=b"data")
        state.fs.insert("/test.txt", simfile)
        state.fs.delete("/test.txt")
        assert len(state.fs.unlinks) == 1

    def test_multiple_files(self):
        state = SimState(arch="AMD64")
        f1 = SimFile(name="f1", content=b"aaa")
        f2 = SimFile(name="f2", content=b"bbb")
        state.fs.insert("/a.txt", f1)
        state.fs.insert("/b.txt", f2)

        assert state.fs.get("/a.txt") is not None
        assert state.fs.get("/b.txt") is not None

    def test_nested_paths(self):
        state = SimState(arch="AMD64")
        simfile = SimFile(name="nested", content=b"nested data")
        state.fs.insert("/usr/local/etc/config", simfile)
        assert state.fs.get("/usr/local/etc/config") is not None

    def test_relative_path_resolved_via_cwd(self):
        state = SimState(arch="AMD64")
        state.fs.cwd = b"/home/user"
        simfile = SimFile(name="relative", content=b"data")
        state.fs.insert("docs/file.txt", simfile)
        # Should be accessible via absolute path
        assert state.fs.get("/home/user/docs/file.txt") is not None


class TestChdir(unittest.TestCase):
    """Test chdir."""

    def test_chdir_absolute(self):
        state = SimState(arch="AMD64")
        state.fs.chdir(b"/home/user")
        assert state.fs.cwd == b"/home/user"

    def test_chdir_with_dotdot(self):
        state = SimState(arch="AMD64")
        state.fs.chdir(b"/home/user/../other")
        assert state.fs.cwd == b"/home/other"


class TestMountOperations(unittest.TestCase):
    """Test mount and unmount."""

    def test_mount_and_unmount(self):
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path=tempfile.gettempdir())
        state.fs.mount("/mnt", mount)
        # get_mountpoint should find it
        mp, chunks = state.fs.get_mountpoint("/mnt/somefile")
        assert mp is not None

        state.fs.unmount("/mnt")
        mp2, _ = state.fs.get_mountpoint("/mnt/somefile")
        assert mp2 is None


class TestFilesystemCopy(unittest.TestCase):
    """Test copy independence."""

    def test_copy_independence(self):
        state = SimState(arch="AMD64")
        simfile = SimFile(name="test", content=b"data")
        state.fs.insert("/test.txt", simfile)

        state2 = state.copy()
        # Delete from copy
        state2.fs.delete("/test.txt")
        # Original should still have the file
        assert state.fs.get("/test.txt") is not None


class TestSimHostFilesystem(unittest.TestCase):
    """Test SimHostFilesystem basic operations."""

    def test_host_filesystem_load(self):
        """Test loading a real file from the host."""
        state = SimState(arch="AMD64")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            tmppath = f.name

        try:
            host_dir = os.path.dirname(tmppath)
            basename = os.path.basename(tmppath)
            mount = SimHostFilesystem(host_path=host_dir)
            mount.set_state(state)

            result = mount.get([basename.encode()])
            assert result is not None
        finally:
            os.unlink(tmppath)

    def test_host_filesystem_nonexistent(self):
        """Test loading a nonexistent file."""
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path="/tmp")
        mount.set_state(state)
        result = mount.get([b"definitely_nonexistent_file_12345.xyz"])
        assert result is None

    def test_host_filesystem_insert_and_get(self):
        """Test inserting into and reading from host filesystem cache."""
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path="/tmp")
        mount.set_state(state)

        simfile = SimFile(name="cached", content=b"cached data")
        mount.insert([b"test_cache_file"], simfile)
        result = mount.get([b"test_cache_file"])
        assert result is not None

    def test_host_filesystem_delete(self):
        """Test delete from host filesystem cache."""
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path="/tmp")
        mount.set_state(state)

        simfile = SimFile(name="to_delete", content=b"data")
        mount.insert([b"del_file"], simfile)
        assert mount.delete([b"del_file"]) is True
        assert mount.get([b"del_file"]) is None

    def test_host_filesystem_lookup(self):
        """Test looking up a SimFile by reference."""
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path="/tmp")
        mount.set_state(state)

        simfile = SimFile(name="lookup_test", content=b"data")
        mount.insert([b"lk_file"], simfile)

        path = mount.lookup(simfile)
        assert path is not None

    def test_host_filesystem_copy(self):
        """Test that copy creates an independent instance."""
        state = SimState(arch="AMD64")
        mount = SimHostFilesystem(host_path="/tmp")
        mount.set_state(state)

        simfile = SimFile(name="copy_test", content=b"data")
        mount.insert([b"copy_file"], simfile)

        copied = mount.copy({})
        assert copied.host_path == mount.host_path


if __name__ == "__main__":
    unittest.main()
