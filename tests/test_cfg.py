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
cfg_tests = {}

def setup_module():
    global cfg_tests
    cfg_tests[0] = angr.Project(test_location + "/blob/x86_64/cfg_0",
                            use_sim_procedures=True,
                            default_analysis_mode='symbolic')

def test_cfg_0():
    global cfg_tests
    start = time.time()
    cfg = cfg_tests[0].construct_cfg(simple=False, context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    print "Contains %d members in BBL dict." % len(cfg.get_bbl_dict())
    pprint.pprint(cfg.get_bbl_dict())
    start = time.time()
    cfg = cfg_tests[0].construct_cfg(simple=True)
    end = time.time()
    duration = end - start
    print "Simple: Done in %f seconds." % duration
    print "Contains %d members in BBL dict." % len(cfg.get_bbl_dict())

if __name__ == "__main__":
    logging.getLogger("simuvex.s_memory").setLevel(logging.DEBUG)
    setup_module()
    test_cfg_0()
