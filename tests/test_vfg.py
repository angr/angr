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
    vfg_tests[0] = angr.Project(test_location + "/blob/mipsel/darpa_ping",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')

def test_vfg_0():
    print "VFG 0"
    start = time.time()
    cfg = vfg_tests[0].analyses.CFG(context_sensitivity_level=1)
    #vfg = vfg_tests[0].construct_vfg(start=0x401630, context_sensitivity_level=2, interfunction_level=2)
    #vfg = vfg_tests[0].construct_vfg(start=0x855f8624, context_sensitivity_level=2, interfunction_level=2)
    vfg = vfg_tests[0].analyses.VFG(cfg, function_start=0x402f54, context_sensitivity_level=2)
    #vfg = vfg_tests[0].construct_vfg(start=0x403350, context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = vfg.get_bbl_dict()
    graph = vfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    import sys
    # logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    logging.getLogger("claripy.claripy").setLevel(logging.ERROR)
    setup_module()
    test_vfg_0()
