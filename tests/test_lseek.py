import nose
import archinfo

import logging
l = logging.getLogger('angr.tests.syscalls.lseek')

from angr import SIM_PROCEDURES
from angr import SimState, SimPosixError, SimFile


FAKE_ADDR = 0x100000

lseek = lambda state, arguments: SIM_PROCEDURES['linux_kernel']['lseek']().execute(state, arguments=arguments)

# Taken from unistd.h
SEEK_SET = 0 # Seek from beginning of file.
SEEK_CUR = 1 # Seek from current position.
SEEK_END = 2 # Seek from end of file.
# GNU Extensions
SEEK_DATA = 3 # Seek to next data.
SEEK_HOLE = 4 # Seek to next hole.

def test_lseek_set():
    state = SimState(arch="AMD64", mode="symbolic")

    # This could be any number above 2 really
    fd = 3

    # Create a file
    state.fs.insert('/tmp/qwer', SimFile(name='qwer', size=100))
    assert fd == state.posix.open('/tmp/qwer', 2)

    # Part 1

    # Seek to the top of the file
    current_pos = lseek(state,[fd,0,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the start
    nose.tools.assert_equal(current_pos,0)

    # Part 2

    # Seek to the top of the file
    current_pos = lseek(state,[fd,8,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the start
    nose.tools.assert_equal(current_pos,8)

    # Part 3

    # Seek to the top of the file
    current_pos = lseek(state,[fd,3,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the start
    nose.tools.assert_equal(current_pos,3)

def test_lseek_cur():
    state = SimState(arch="AMD64", mode="symbolic")

    # This could be any number above 2 really
    fd = 3

    # Create a file
    state.fs.insert('/tmp/qwer', SimFile(name='qwer', size=100))
    assert fd == state.posix.open('/tmp/qwer', 2)

    # Part 1

    # Add 12
    current_pos = lseek(state,[fd,12,SEEK_CUR]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the start
    nose.tools.assert_equal(current_pos,12)

    # Part 2

    # Remove 3
    current_pos = lseek(state,[fd,-3,SEEK_CUR]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the start
    nose.tools.assert_equal(current_pos,9)

def test_lseek_end():
    state = SimState(arch="AMD64", mode="symbolic")

    fd = 3

    # Create a file
    state.fs.insert('/tmp/qwer', SimFile(name='qwer', size=16))
    assert fd == state.posix.open('/tmp/qwer', 2)

    # Part 1

    # Add 5
    current_pos = lseek(state,[fd,0,SEEK_END]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the end + offset
    nose.tools.assert_equal(current_pos, 16)

    # Part 2

    # Minus 6. End of file never actually changed
    current_pos = lseek(state,[fd,-6,SEEK_END]).ret_expr
    current_pos = state.se.eval(current_pos)

    # We should be at the end + offset
    nose.tools.assert_equal(current_pos,10)

def test_lseek_unseekable():
    state = SimState(arch="AMD64", mode="symbolic")

    # Illegal seek
    current_pos = lseek(state,[0,0,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # Assert we have a negative return value
    nose.tools.assert_true(current_pos & (1 << 63) != 0)

    # Illegal seek
    current_pos = lseek(state,[1,0,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # Assert we have a negative return value
    nose.tools.assert_true(current_pos & (1 << 63) != 0)

    # Illegal seek
    current_pos = lseek(state,[2,0,SEEK_SET]).ret_expr
    current_pos = state.se.eval(current_pos)

    # Assert we have a negative return value
    nose.tools.assert_true(current_pos & (1 << 63) != 0)

@nose.tools.raises(SimPosixError)
def test_lseek_symbolic_whence():
    # symbolic whence is currently not possible
    state = SimState(arch="AMD64", mode="symbolic")

    # This could be any number above 2 really
    fd = 3

    # Create a file
    assert fd == state.posix.open('/tmp/qwer', 1)

    whence = state.se.BVS('whence',64)

    # This should cause the exception
    lseek(state,[fd,0,whence])

def test_lseek_symbolic_seek():
    # symbolic seek is currently not possible
    state = SimState(arch="AMD64", mode="symbolic")

    # This could be any number above 2 really
    fd = 3

    # Create a file
    assert fd == state.posix.open('/tmp/qwer', 1)

    seek = state.se.BVS('seek',64)

    # This should NOT cause an exception
    lseek(state,[fd,seek,SEEK_SET])

if __name__ == '__main__':
    g = globals().copy()
    for func_name, func in g.iteritems():
        if func_name.startswith("test_") and hasattr(func, "__call__"):
            func()
