import angr

def test_files():
    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data("HELLO")
    s.posix.get_fd(1).write_data("WORLD")
    assert s.posix.dumps(1) == "HELLOWORLD"
    assert s.posix.stdout.concretize() == ["HELLO", "WORLD"]

    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data("A"*0x1000, 0x800)
    assert s.posix.dumps(1) == "A"*0x800

if __name__ == '__main__':
    test_files()
