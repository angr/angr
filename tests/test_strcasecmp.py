import nose
import angr
import claripy

import os

test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_i386():
    p = angr.Project(test_location + "/i386/test_strcasecmp", auto_load_libs=False)
    arg1 = claripy.BVS('arg1', 20*8)
    s = p.factory.entry_state(args=("test_strcasecmp", arg1))
    sm = p.factory.simulation_manager(s)
    sm.explore()

    sm.move('deadended', 'found', filter_func=lambda s: b"Welcome" in s.posix.dumps(1))

    nose.tools.assert_equal(len(sm.found), 1)

    f = sm.found[0]
    sol = f.solver.eval(arg1, cast_to=bytes)
    nose.tools.assert_in(b'\x00', sol)
    nose.tools.assert_equal(sol[:sol.index(b'\x00')].lower(), b'letmein')
    nose.tools.assert_in(b'wchar works', f.posix.dumps(1))

if __name__ == "__main__":
    test_i386()
