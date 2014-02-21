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
memset_amd64 = None

def setup_module():
    setup_amd64()

def setup_amd64():
    global memset_amd64
    memset_amd64 = angr.Project(test_location + "/memset/memset-amd64", load_libs=True, default_analysis_mode='symbolic', use_sim_procedures=True, exclude_sim_procedures=['memset'])

def test_amd64():
    explorer = angr.surveyors.Explorer(memset_amd64, find=[0x400608]).run()
    s = explorer.found[0].last_run.initial_state
    result = s.mem_value(s.reg_value(16), 50).any_str()
    nose.tools.assert_equals(result, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00')

if __name__ == "__main__":
    setup_amd64()
    test_amd64()
