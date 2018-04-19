
import sys

import nose.tools

from angr import SimState, SimFile

def test_file_create():
    # Create a state first
    state = SimState(arch="AMD64", mode='symbolic')

    # Create a file
    fd = state.posix.open("test", 1)

    nose.tools.assert_equal(fd, 3)

def test_file_read():
    state = SimState(arch="AMD64", mode='symbolic')

    content = state.se.BVV(0xbadf00d, 32)
    content_size = content.size() / 8

    fd = state.posix.open("test", 1)
    simfd = state.posix.get_fd(fd)
    simfd.write_data(content)
    simfd.seek(0)
    simfd.read(0xc0000000, content_size)

    data = state.memory.load(0xc0000000, content_size)

    nose.tools.assert_is(data, content)

def test_file_seek():

    # TODO: Make this test more complete

    state = SimState(arch="AMD64", mode='symbolic')

    # Normal seeking
    fd = state.posix.open("test1", 1)
    simfd = state.posix.get_fd(fd)
    simfd.seek(0, 'start')
    nose.tools.assert_true(state.solver.is_true(simfd.tell() == 0))
    state.posix.close(fd)

    # TODO: test case: seek cannot go beyond the file size or current file pos

    # seek should not work for stdin/stdout/stderr
    nose.tools.assert_true(state.solver.is_false(state.posix.get_fd(0).seek(0)))
    nose.tools.assert_true(state.solver.is_false(state.posix.get_fd(1).seek(0)))
    nose.tools.assert_true(state.solver.is_false(state.posix.get_fd(2).seek(0)))

    # Seek from the end
    state.fs.insert('test2', SimFile(name='qwer', size=20))
    fd = state.posix.open("test2", 1)
    simfd = state.posix.get_fd(fd)
    simfd.seek(0, 'end')
    nose.tools.assert_true(state.solver.is_true(simfd.tell() == 20))
    state.posix.close(fd)

    # seek to a symbolic position (whence symbolic end)
    fd = state.posix.open("unknown_size", 1)
    simfd = state.posix.get_fd(fd)
    real_end = state.fs.get("unknown_size").size
    simfd.seek(0, 'end')
    nose.tools.assert_is(real_end, simfd.tell())
    state.posix.close(fd)

def main():
    g = globals()
    if len(sys.argv) > 1:
        f = "test_" + sys.argv[1]
        if f in g and hasattr(g[f], "__call__"):
            g[f]()
    else:
        for f, func in g.iteritems():
            if f.startswith("test_") and hasattr(func, "__call__"):
                func()

if __name__ == "__main__":
    main()
