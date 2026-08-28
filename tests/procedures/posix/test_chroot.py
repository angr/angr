#!/usr/bin/env python3
# pylint:disable=missing-class-docstring,no-self-use,protected-access
from __future__ import annotations

__package__ = __package__ or "tests.procedures.posix"  # pylint:disable=redefined-builtin

import os
import shutil
import tempfile
import unittest

import angr
from angr.errors import SimMergeError
from angr.state_plugins.filesystem import SimFilesystem, SimHostFilesystem
from angr.state_plugins.posix import Flags
from angr.storage.file import SimFile
from tests.common import bin_location

test_location = os.path.join(bin_location, "tests")

PATH_ADDR = 0xC0000000
STATE_OPTIONS = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}


def call_chroot(state, path):
    """
    Call the chroot SimProcedure on the given state with the given path. Returns the return value.
    """
    state.memory.store(PATH_ADDR, path + b"\0")
    proc = angr.SIM_PROCEDURES["posix"]["chroot"]()
    state.scratch.sim_procedure = proc
    return state.solver.eval(proc.execute(state, arguments=[PATH_ADDR]).ret_expr)


def read_fd(state, fd, size):
    """
    Read the given number of bytes from a file descriptor of the given state.
    """
    simfd = state.posix.get_fd(fd)
    assert simfd is not None
    data, _ = simfd.read_data(size)
    return data


class TestChroot(unittest.TestCase):
    def _host_root(self):
        """
        A host directory holding jail/inside.txt and outside.txt, plus a state chrooted into it.
        """
        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, True)
        os.mkdir(os.path.join(tmpdir, "jail"))
        with open(os.path.join(tmpdir, "jail", "inside.txt"), "wb") as fp:
            fp.write(b"inside")
        with open(os.path.join(tmpdir, "outside.txt"), "wb") as fp:
            fp.write(b"outside")

        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.blank_state(concrete_fs=True, chroot=tmpdir, cwd=b"/", add_options=STATE_OPTIONS)
        state.libc.errno_location = 0xA0000000
        return tmpdir, state

    def test_chroot_binary(self):
        # the binary calls chroot("./newRoot") from /home/user and then reports whether it succeeded
        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.entry_state(fs={"/home/user/newRoot/test.txt": SimFile("test.txt", content=b"jailed")})

        simgr = project.factory.simgr(state)
        simgr.run()

        assert len(simgr.deadended) == 1
        deadended = simgr.deadended[0]
        assert b"Successfully changed root directory" in deadended.posix.dumps(1)

        assert deadended.fs.root == b"/home/user/newRoot"
        # the seeded file is now at the root of the guest's view...
        fd = deadended.posix.open(b"/test.txt", Flags.O_RDONLY)
        data = read_fd(deadended, fd, 6)
        assert deadended.solver.eval(data, cast_to=bytes) == b"jailed"
        # ...and its old path no longer resolves
        assert deadended.fs.get(b"/home/user/newRoot/test.txt") is None

    def test_chroot_does_not_expose_the_host_filesystem(self):
        # regression test: chroot used to mount a SimHostFilesystem at the guest-supplied path
        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.blank_state(add_options=STATE_OPTIONS)

        assert call_chroot(state, b"/etc") == 0
        assert not any(isinstance(mount, SimHostFilesystem) for mount in state.fs._mountpoints.values())
        assert state.fs.get(b"/passwd") is None

        # opening /passwd gets a symbolic file, not the contents of the host's /etc/passwd
        fd = state.posix.open(b"/passwd", Flags.O_RDONLY)
        assert state.solver.symbolic(read_fd(state, fd, 4))

    def test_chroot_on_host_filesystem_warns(self):
        tmpdir, state = self._host_root()

        with self.assertLogs("angr.procedures.posix.chroot", level="WARNING") as logs:
            assert call_chroot(state, b"/jail") == 0
        assert any("host filesystem" in record.getMessage() for record in logs.records)

        assert state.fs.root == b"/jail"
        # the guest can reach what is under the new root, and nothing above it
        fd = state.posix.open(b"/inside.txt", Flags.O_RDONLY)
        assert fd >= 0
        assert state.solver.eval(read_fd(state, fd, 6), cast_to=bytes) == b"inside"
        assert state.fs.get(b"/outside.txt") is None
        assert state.fs.get(b"/../outside.txt") is None
        assert os.path.exists(os.path.join(tmpdir, "outside.txt"))

    def test_chroot_errors(self):
        _, state = self._host_root()

        # a path that does not exist on the host
        assert call_chroot(state, b"/nonexistent") == -1
        assert state.solver.eval(state.libc.errno) == state.posix.ENOENT
        assert state.fs.root == b"/"

        # a path that is a regular file on the host
        assert call_chroot(state, b"/outside.txt") == -1
        assert state.solver.eval(state.libc.errno) == state.posix.ENOTDIR
        assert state.fs.root == b"/"

        # an empty path
        assert call_chroot(state, b"") == -1
        assert state.solver.eval(state.libc.errno) == state.posix.ENOENT
        assert state.fs.root == b"/"

    def test_chroot_on_emulated_file(self):
        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.blank_state(fs={"/tmp/file": SimFile("file", content=b"x")}, add_options=STATE_OPTIONS)
        state.libc.errno_location = 0xA0000000

        assert call_chroot(state, b"/tmp/file") == -1
        assert state.solver.eval(state.libc.errno) == state.posix.ENOTDIR
        assert state.fs.root == b"/"

        # directories are implicit in the emulated filesystem, so chrooting into one always works
        assert call_chroot(state, b"/tmp") == 0
        assert state.fs.root == b"/tmp"
        assert state.fs.get(b"/file") is not None

    def test_relative_chdir_then_chroot(self):
        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.blank_state(
            fs={"/tmp/jail/file": SimFile("file", content=b"x")}, cwd=b"/tmp", add_options=STATE_OPTIONS
        )

        state.memory.store(PATH_ADDR, b"jail\0")
        chdir = angr.SIM_PROCEDURES["linux_kernel"]["chdir"]()
        state.scratch.sim_procedure = chdir
        assert state.solver.eval(chdir.execute(state, arguments=[PATH_ADDR]).ret_expr) == 0
        assert state.fs.cwd == b"/tmp/jail"

        # chroot resolves relative paths against the cwd too
        assert call_chroot(state, b".") == 0
        assert state.fs.root == b"/tmp/jail"
        assert state.fs.cwd == b"/"
        assert state.fs.get(b"/file") is not None

    def test_filesystem_chroot(self):
        fs = SimFilesystem(files={"/a/b/c/file": SimFile("file", content=b"x")}, cwd=b"/a/b")

        fs.chroot(b"/a")
        assert fs.root == b"/a"
        assert fs.cwd == b"/b"  # the cwd was inside the new root, so it was re-anchored
        assert fs.get(b"c/file") is not None
        assert fs.get(b"/b/c/file") is not None
        assert fs.get(b"/a/b/c/file") is None

        # chroot is relative to the current root and composes
        fs.chroot(b"/b")
        assert fs.root == b"/a/b"
        assert fs.cwd == b"/"
        assert fs.get(b"/c/file") is not None

        # ".." cannot climb above the root
        assert fs.get(b"/../../a/b/c/file") is None
        assert fs.get(b"/../c/file") is not None

        # files created after the chroot land under the new root
        fs.insert(b"/new", SimFile("new", content=b"y"))
        assert b"/a/b/new" in fs._files

        # the cwd is re-anchored when it ends up outside of the new root
        fs.chdir(b"/c")
        fs.chroot(b"/d")
        assert fs.root == b"/a/b/d"
        assert fs.cwd == b"/"

    def test_filesystem_chroot_copy_and_merge(self):
        project = angr.Project(os.path.join(test_location, "x86_64", "chroot_test"), auto_load_libs=False)
        state = project.factory.blank_state()
        state.fs.chroot(b"/jail")

        # the root survives a state copy, and filesystems with different roots cannot be merged
        assert state.copy().fs.root == b"/jail"
        other = project.factory.blank_state()
        other.fs.chroot(b"/elsewhere")
        self.assertRaisesRegex(SimMergeError, "root", state.fs.merge, [other.fs], [None, None])


if __name__ == "__main__":
    unittest.main()
