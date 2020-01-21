import nose
import angr
from archinfo import ArchX86

import os

test_location = os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', 'binaries', 'tests')


class StdcallStub1Arg(angr.SimProcedure):
    def run(self, arg1):
        return 0

def test_i386():
    after_puts = 0x40105b
    else_paths = [0x401062, 0x401009]

    p = angr.Project(os.path.join(test_location, 'i386', 'simple_windows.exe'), auto_load_libs=False)
    p.hook_symbol("GetTickCount64", StdcallStub1Arg(cc=angr.calling_conventions.SimCCStdcall(ArchX86()),
        display_name="GetTickCount64"), replace=True) # stubbed until 64 bit return works

    s = p.factory.entry_state(args=("simple_windows.exe", "angr_can_windows?", "1497715489"))
    simgr = p.factory.simulation_manager(s)
    simgr.explore(find=after_puts, avoid=else_paths, num_find=10)

    nose.tools.assert_equal(len(simgr.avoid), 0)
    nose.tools.assert_greater(len(simgr.found), 0)
    for f in simgr.found:
        nose.tools.assert_in(b"ok", f.posix.dumps(1))

if __name__ == "__main__":
    test_i386()
