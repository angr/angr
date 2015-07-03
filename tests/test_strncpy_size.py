#!/usr/bin/env python

## Not that great of a test, have to verify the source of the null bytes in another test

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
import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_amd64():
    strncpy_size_amd64 = angr.Project(test_location + "/x86_64/strncpy-size", load_options={'auto_load_libs': True}, exclude_sim_procedures=['strncpy'])
    explorer = angr.surveyors.Explorer(strncpy_size_amd64,max_repeats=50, find=[0x40064C]).run()
    s = explorer.found[0].state
    result = s.se.any_str(s.memory.load(s.registers.load(16), 40))
    nose.tools.assert_equals(result, 'just testing things\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

if __name__ == "__main__":
    test_amd64()
