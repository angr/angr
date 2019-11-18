import angr
import nose

def test_file_unlink():
    # Initialize a blank state with an arbitrary errno location
    state = angr.SimState(arch="AMD64", mode="symbolic")
    state.libc.errno_location = 0xa0000000
    state.libc.errno = 0

    # Create a file 'test'
    fd = state.posix.open(b'test', 1)
    state.posix.close(fd)

    # Ensure 'test' was in fact created
    nose.tools.assert_in(b'/test', state.fs._files)

    # Store the filename in memory
    path_addr = 0xb0000000
    state.memory.store(path_addr, b'test\x00')

    # Unlink 'test': should return 0 and leave ERRNO unchanged
    unlink = angr.SIM_PROCEDURES['posix']['unlink']()
    state.scratch.sim_procedure = unlink
    rval = unlink.execute(state, arguments=[path_addr]).ret_expr
    nose.tools.assert_equal(rval, 0)
    nose.tools.assert_equal(state.solver.eval(state.libc.errno), 0)

    # Check that 'test' was in fact deleted
    nose.tools.assert_equal(state.fs._files, {})

    # Unlink again: should return -1 and set ERRNO to ENOENT
    unlink = angr.SIM_PROCEDURES['posix']['unlink']()
    state.scratch.sim_procedure = unlink
    rval = unlink.execute(state, arguments=[path_addr]).ret_expr
    nose.tools.assert_equal(rval, -1)
    nose.tools.assert_equal(state.solver.eval(state.libc.errno), state.posix.ENOENT)
