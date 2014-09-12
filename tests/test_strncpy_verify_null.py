#!/usr/bin/env python

#verifying that the null bytes in strncpy-size test were from the right place

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
strncpy_verify_null_amd64 = None

def setup_module():
    setup_amd64()

def setup_amd64():
    global strncpy_verify_null_amd64
    strncpy_verify_null_amd64 = angr.Project(test_location + "/build/x86/64/strncpy_null", load_libs=True, default_analysis_mode='symbolic', use_sim_procedures=True, exclude_sim_procedures=['strncpy'])

def test_amd64():
    explorer = angr.surveyors.Explorer(strncpy_verify_null_amd64,max_repeats=50, find=[0x40064C]).run()
    s = explorer.found[0].last_run.initial_state
    result = s.mem_value(s.reg_value(16), 40).any_str()
    nose.tools.assert_equals(result, 'just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAA\x00')

if __name__ == "__main__":
    setup_amd64()
    test_amd64()
