import angr
import nose

def test_unsupported_syscall_simos():
    p = angr.load_shellcode(b'\xcd\x80', 'x86')
    state = p.factory.entry_state()
    state.regs.eax = 4

    # test that by default trying to perform a syscall without SimUserspace causes the state to go errored
    simgr = p.factory.simulation_manager(state)
    simgr.step()
    nose.tools.assert_equal(len(simgr.active), 1)
    simgr.step()
    nose.tools.assert_equal(len(simgr.active), 0)
    nose.tools.assert_equal(len(simgr.errored), 1)

    # test that when we set BYPASS_UNSUPPORTED_SYSCALLS, we get a syscall stub instead
    state.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
    simgr = p.factory.simulation_manager(state)
    simgr.step()
    nose.tools.assert_equal(len(simgr.active), 1)
    simgr.step()
    nose.tools.assert_equal(len(simgr.active), 1)
    nose.tools.assert_equal(len(simgr.errored), 0)

if __name__ == '__main__':
    test_unsupported_syscall_simos()
