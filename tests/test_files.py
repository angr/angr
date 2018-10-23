import angr

def test_files():
    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data(b"HELLO")
    s.posix.get_fd(1).write_data(b"WORLD")
    assert s.posix.dumps(1) == b"HELLOWORLD"
    assert s.posix.stdout.concretize() == [b"HELLO", b"WORLD"]

    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data(b"A"*0x1000, 0x800)
    assert s.posix.dumps(1) == b"A"*0x800

if __name__ == '__main__':
    test_files()
