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
scout_tests = {}

def setup_module():
    global scout_tests
    scout_tests[0] = angr.Project(test_location + "/blob/x86_64/cfg_0",
                            use_sim_procedures=True,
                            default_analysis_mode='symbolic')

def test_scout_0():
    global scout_tests
    start = time.time()
    scout = angr.Scout(scout_tests[0],
                       starting_point=scout_tests[0].ld.main_bin.get_min_addr(),
                       ending_point=scout_tests[0].ld.main_bin.get_max_addr())
    scout.reconnoiter()
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    print "Contains %d members in the call map." % len(scout._call_map)
    pprint.pprint(scout._call_map.nodes())

if __name__ == "__main__":
    # logging.getLogger("simuvex.s_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.scout").setLevel(logging.DEBUG)
    setup_module()
    test_scout_0()
