import simuvex

def test_files():
    s = simuvex.SimState()
    s.posix.write(0, "HELLO", 5)
    s.posix.write(0, "WORLD", 5)
    assert s.posix.dumps(0) == "HELLOWORLD"

    s = simuvex.SimState()
    s.posix.write(0, "A"*0x1000, 0x1000)
    assert s.posix.dumps(0) == "A"*0x1000

if __name__ == '__main__':
    test_files()
