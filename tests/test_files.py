# pylint: disable=missing-class-docstring,disable=no-self-use
import os
import unittest

import angr
from angr.state_plugins.posix import Flags

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..")


class TestFile(unittest.TestCase):
    def test_files(self):
        s = angr.SimState(arch="AMD64")
        s.posix.get_fd(1).write_data(b"HELLO")
        s.posix.get_fd(1).write_data(b"WORLD")
        assert s.posix.dumps(1) == b"HELLOWORLD"
        assert s.posix.stdout.concretize() == [b"HELLO", b"WORLD"]

        s = angr.SimState(arch="AMD64")
        s.posix.get_fd(1).write_data(b"A" * 0x1000, 0x800)
        assert s.posix.dumps(1) == b"A" * 0x800

    def test_file_read_missing_content(self):
        # test in tracing mode since the Reverse operator will not be optimized away
        s = angr.SimState(arch="AMD64", mode="tracing")
        fd = s.posix.open(b"/tmp/oops", Flags.O_RDWR)
        length = s.posix.get_fd(fd).read(0xC00000, 100)

        data = s.memory.load(0xC00000, length, endness="Iend_BE")
        assert data.op != "Reverse", "Byte strings read directly out of a file should not have Reverse operators."
        assert data.op == "BVS"
        assert len(data.variables) == 1
        assert "oops" in next(iter(data.variables))

    def test_concrete_fs_resolution(self):
        bin_path = os.path.join(test_location, "binaries", "tests", "i386", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        state = proj.factory.entry_state(concrete_fs=True)
        fd = state.posix.open(bin_path, Flags.O_RDONLY)
        stat = state.posix.fstat(fd)
        size = stat.st_size
        int_size = state.solver.eval(size)

        assert stat
        assert int_size != 0
        assert not state.solver.symbolic(size)

    def test_sim_fs_resolution(self):
        bin_path = os.path.join(test_location, "binaries", "tests", "i386", "fauxware")
        proj = angr.Project(bin_path, auto_load_libs=False)
        state = proj.factory.entry_state()
        fd = state.posix.open(bin_path, Flags.O_RDONLY)
        stat = state.posix.fstat(fd)
        size = stat.st_size

        assert stat
        assert state.solver.symbolic(size)


if __name__ == "__main__":
    unittest.main()
