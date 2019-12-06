
import nose.tools

import angr
from angr.state_plugins.posix import Flags


def test_files():
    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data(b"HELLO")
    s.posix.get_fd(1).write_data(b"WORLD")
    assert s.posix.dumps(1) == b"HELLOWORLD"
    assert s.posix.stdout.concretize() == [b"HELLO", b"WORLD"]

    s = angr.SimState(arch='AMD64')
    s.posix.get_fd(1).write_data(b"A"*0x1000, 0x800)
    assert s.posix.dumps(1) == b"A"*0x800


def test_file_read_missing_content():

    # test in tracing mode since the Reverse operator will not be optimized away
    s = angr.SimState(arch='AMD64', mode="tracing")
    fd = s.posix.open(b"/tmp/oops", Flags.O_RDWR)
    length = s.posix.get_fd(fd).read(0xc00000, 100)

    data = s.memory.load(0xc00000, length, endness="Iend_BE")
    nose.tools.assert_not_equal(data.op, 'Reverse', "Byte strings read directly out of a file should not have Reverse "
                                                    "operators.")
    nose.tools.assert_equal(data.op, "BVS")
    nose.tools.assert_equal(len(data.variables), 1)
    nose.tools.assert_in("oops", next(iter(data.variables)))  # file name should be part of the variable name


if __name__ == '__main__':
    test_files()
    test_file_read_missing_content()
