
import sys

import nose.tools

from simuvex import SimState

def test_file_create():
    # Create a state first
    state = SimState(arch="AMD64", mode='symbolic')

    # Create a file
    fd = state.posix.open("test", "wb")

    nose.tools.assert_equal(fd, 3)

def test_file_read():
    state = SimState(arch="AMD64", mode='symbolic')

    content = state.se.BVV(0xbadf00d, 32)
    content_size = content.size() / 8

    fd = state.posix.open("test", "wb")
    state.posix.write(fd, content, content_size)
    state.posix.seek(fd, 0, 0)
    state.posix.read(fd, 0xc0000000, content_size)

    data = state.memory.load(0xc0000000, content_size)

    nose.tools.assert_true(state.se.is_true(data == content))

def test_file_seek():

    # TODO: Make this test more complete

    SEEK_SET = 0
    SEEK_CUR = 1
    SEEK_END = 2

    state = SimState(arch="AMD64", mode='symbolic')

    # Normal seeking
    fd = state.posix.open("test", "wb")
    r = state.posix.seek(fd, 0, SEEK_SET)
    nose.tools.assert_equal(r, 0)
    state.posix.close(fd)

    # TODO: test case: seek cannot go beyond the file size or current file pos
    # TODO: test case: seek should not work for stdin/stdout/stderr

    # Seek from the end
    fd = state.posix.open("test", "wb")
    state.posix.files[fd].size = 20
    state.posix.seek(fd, 0, SEEK_END)
    nose.tools.assert_true(state.se.is_true(state.posix.files[fd].pos == 20))
    state.posix.close(fd)

    # cannot seek from a file whose size is unknown
    fd = state.posix.open("unknown_size", "wb")
    r = state.posix.seek(fd, 0, SEEK_END)
    nose.tools.assert_equal(r, -1)
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
