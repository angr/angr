import sys


from angr import SimState, SimFile


def test_file_create():
    # Create a state first
    state = SimState(arch="AMD64", mode="symbolic")

    # Create a file
    fd = state.posix.open(b"test", 1)

    assert fd == 3


def test_file_read():
    state = SimState(arch="AMD64", mode="symbolic")

    content = state.solver.BVV(0xBADF00D, 32)
    content_size = content.size() // 8

    fd = state.posix.open(b"test", 1)
    simfd = state.posix.get_fd(fd)
    simfd.write_data(content)
    simfd.seek(0)
    simfd.read(0xC0000000, content_size)

    data = state.memory.load(0xC0000000, content_size)

    assert data is content


def test_file_seek():
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


def main():
    g = globals()
    if len(sys.argv) > 1:
        f = "test_" + sys.argv[1]
        if f in g and hasattr(g[f], "__call__"):
            g[f]()
    else:
        for f, func in g.items():
            if f.startswith("test_") and hasattr(func, "__call__"):
                func()


if __name__ == "__main__":
    main()
