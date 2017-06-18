import nose
import angr

import logging
l = logging.getLogger('angr_tests.dataflowgraph')

import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def test_sprintf():
    p = angr.Project(os.path.join(test_location, "../../binaries/tests/x86_64/sprintf_test"))
    a = p.surveyors.Explorer(find=0x4005c0)
    a.run()
    state = a.found[0]

    str1 = state.se.any_str(state.memory.load(0x600ad0, 13))
    nose.tools.assert_equal(str1, 'Immediate: 3\n')

    str2 = state.se.any_str(state.memory.load(0x600a70, 7))
    nose.tools.assert_equal(str2, 'Int: 3\n')

    str3 = state.se.any_str(state.memory.load(0x600ab0, 8))
    nose.tools.assert_equal(str3, 'Char: c\n')

    str4 = state.se.any_str(state.memory.load(0x600a50, 14))
    nose.tools.assert_equal(str4, 'Uninit int: 0\n')

    str5 = state.se.any_str(state.memory.load(0x600a90, 24))
    nose.tools.assert_equal(str5, 'Str on stack: A string.\n')

    str6 = state.se.any_str(state.memory.load(0x600a30, 21))
    nose.tools.assert_equal(str6, 'Global str: GLOB_STR\n')

if __name__ == "__main__":
    test_sprintf()
