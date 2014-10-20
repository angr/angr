#!/usr/bin/env python

import os
import logging
import time
l = logging.getLogger("angr_tests")

import nose
import pprint

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr
import simuvex

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))
slicing_tests = {}

def test_control_flow_slicing():
    slicing_tests[0] = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "Control Flow Slicing"
    start = time.time()
    cfg = slicing_tests[0].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration

    target = cfg.get_any_irsb(0x400594)
    anno_cfg = slicing_tests[0].slice_to(0x400594, -1, cfg_only=True)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x40057c), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x400594), None)
    nose.tools.assert_equal(anno_cfg.get_whitelisted_statements(0x4005a4), [ ])

if __name__ == "__main__":
    import sys
    sys.setrecursionlimit(1000000)

    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    test_control_flow_slicing()
