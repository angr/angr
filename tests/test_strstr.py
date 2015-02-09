#!/usr/bin/env python
import nose
import logging
l = logging.getLogger("angr_tests")

try:
    # pylint: disable=W0611,F0401
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr

# load the tests
import os
test_location = str(os.path.dirname(os.path.realpath(__file__)))
strstr_amd64 = None

def setup_module():
    setup_amd64()

def setup_amd64():
    global strstr_amd64
    strstr_amd64 = angr.Project(test_location + "blob/x86_64/strstr",  exclude_sim_procedures=['strstr'])

def test_amd64():
    explorer = angr.surveyors.Explorer(strstr_amd64, find=[0x4005FB]).run()
    s = explorer.found[0].state
    result = s.mem_value(s.reg_value(16), 9).any_str()
    nose.tools.assert_equals(result, 'hi there\x00')

if __name__ == "__main__":
    setup_amd64()
    test_amd64()
