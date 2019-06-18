import nose
import angr

import logging
l = logging.getLogger('angr_tests.dataflowgraph')

import os
test_location = os.path.dirname(os.path.realpath(__file__))

def test_sprintf():
    p = angr.Project(os.path.join(test_location, "..", "..", "binaries", "tests", "x86_64", "sprintf_test"))
    a = p.factory.simulation_manager().explore(find=0x4005c0)
    state = a.found[0]

    str1 = state.solver.eval(state.memory.load(0x600ad0, 13), cast_to=bytes)
    nose.tools.assert_equal(str1, b'Immediate: 3\n')

    str2 = state.solver.eval(state.memory.load(0x600a70, 7), cast_to=bytes)
    nose.tools.assert_equal(str2, b'Int: 3\n')

    str3 = state.solver.eval(state.memory.load(0x600ab0, 8), cast_to=bytes)
    nose.tools.assert_equal(str3, b'Char: c\n')

    str4 = state.solver.eval(state.memory.load(0x600a50, 14), cast_to=bytes)
    nose.tools.assert_equal(str4, b'Uninit int: 0\n')

    str5 = state.solver.eval(state.memory.load(0x600a90, 24), cast_to=bytes)
    nose.tools.assert_equal(str5, b'Str on stack: A string.\n')

    str6 = state.solver.eval(state.memory.load(0x600a30, 21), cast_to=bytes)
    nose.tools.assert_equal(str6, b'Global str: GLOB_STR\n')

if __name__ == "__main__":
    test_sprintf()
