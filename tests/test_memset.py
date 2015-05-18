#!/usr/bin/env python

import logging
l = logging.getLogger("angr_tests")

import angr
import nose
import os
test_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries/tests'))

def test_amd64():
    memset_amd64 = angr.Project(test_location + "/x86_64/memset", load_options={'auto_load_libs': True}, exclude_sim_procedures=['memset'])
    explorer = angr.surveyors.Explorer(memset_amd64, find=[0x400608]).run()
    s = explorer.found[0].state
    result = s.se.any_str(s.mem_expr(s.reg_expr(16), 50))
    nose.tools.assert_equals(result, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\x00')

if __name__ == "__main__":
    try:
        __import__('standard_logging')
        __import__('angr_debug')
    except ImportError:
        pass

    test_amd64()
