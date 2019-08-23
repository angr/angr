import angr
import nose
from unittest.mock import patch, PropertyMock

@patch('angr.state_plugins.libc.SimStateLibc.errno',
       new_callable=PropertyMock)
def test_file_unlink(mock_errno):
    class TestProc(angr.SimProcedure):
        def run(self, argc, argv):
            # Load the unlink SimProcedure
            unlink = angr.SIM_PROCEDURES['posix']['unlink']
            
            # Create a file 'test'
            fd = self.state.posix.open(b'test', 1)
            self.state.posix.close(fd)

            # Ensure 'test' was in fact created
            nose.tools.assert_in(b'/home/user/test', self.state.fs._files)

            # Store the filename in memory
            malloc = angr.SIM_PROCEDURES['libc']['malloc']
            addr = self.inline_call(malloc, len('test')).ret_expr
            self.state.memory.store(addr, b'test\x00')
            
            # Unlink 'test': should return 0 and leave ERRNO unchanged
            rval = self.inline_call(unlink, addr).ret_expr
            nose.tools.assert_equal(rval, 0)
            mock_errno.assert_not_called()

            # Check that 'test' was in fact deleted
            nose.tools.assert_equal(self.state.fs._files, {})

            # Unlink again: should return -1 and set ERRNO to ENOENT
            rval = self.inline_call(unlink, addr).ret_expr
            nose.tools.assert_equal(rval, -1)
            mock_errno.assert_called_once_with(self.state.posix.ENOENT)

    # Load the 'fauxware' binary and hook TestProc
    project = angr.Project('../../binaries/tests/x86_64/fauxware')
    project.hook_symbol('main', TestProc())
    simgr = project.factory.simulation_manager()
    simgr.run()
