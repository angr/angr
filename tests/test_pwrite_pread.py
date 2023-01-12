import sys

from angr import SimState, SimFile, SIM_PROCEDURES


def test_pwrite():
    pwrite = SIM_PROCEDURES["posix"]["pwrite64"]()

    state = SimState(arch="AMD64", mode="symbolic")
    simfile = SimFile("concrete_file", content="hello world!\n")
    state.fs.insert("test", simfile)
    fd = state.posix.open(b"test", 1)

    buf_addr = 0xD0000000
    state.memory.store(buf_addr, b"test!")
    pwrite.execute(state, arguments=[fd, buf_addr, 5, 6])

    simfd = state.posix.get_fd(fd)
    simfd.seek(0)
    res = 0xC0000000
    simfd.read(res, 13)
    data = state.solver.eval(state.mem[res].string.resolved, cast_to=bytes)

    assert data == b"hello test!!\n"

    state.posix.close(fd)


def test_pread():
    pwrite = SIM_PROCEDURES["posix"]["pread64"]()

    state = SimState(arch="AMD64", mode="symbolic")
    simfile = SimFile("concrete_file", content="hello world!\n")
    state.fs.insert("test", simfile)
    fd = state.posix.open(b"test", 1)

    buf1_addr = 0xD0000000
    buf2_addr = 0xD0001000
    pwrite.execute(state, arguments=[fd, buf1_addr, 6, 6])
    pwrite.execute(state, arguments=[fd, buf2_addr, 5, 0])

    data1 = state.solver.eval(state.mem[buf1_addr].string.resolved, cast_to=bytes)
    data2 = state.solver.eval(state.mem[buf2_addr].string.resolved, cast_to=bytes)

    assert data1 == b"world!"
    assert data2 == b"hello"

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
