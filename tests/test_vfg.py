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
vfg_tests = {}

def setup_module():
    global scout_tests
    vfg_tests[0] = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')

def test_cfg_0():
    print "CFG 0"
    start = time.time()
    vfg = vfg_tests[0].construct_vfg(start=0x40057c, context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = vfg.get_bbl_dict()
    graph = vfg.get_graph()
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    logging.getLogger("claripy.claripy").setLevel(logging.ERROR)
    setup_module()
    test_cfg_0()
