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

def test_cfg_0():
    cfg_tests[0] = angr.Project(test_location + "/blob/x86_64/cfg_0",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 0"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[0].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.get_graph()
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

def test_cfg_1():
    cfg_tests[1] = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 1"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[1].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

def test_cfg_2():
    cfg_tests[2] = angr.Project(test_location + "/blob/armel/test_division",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 2"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[2].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

def test_cfg_3():
    cfg_tests[3] = angr.Project(test_location + "/blob/mips/test_arrays_mips",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 3"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[3].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

def test_cfg_4():
    cfg_tests[4] = angr.Project(test_location + "/blob/mipsel/darpa_ping",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 4"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[4].construct_cfg(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)
    test_cfg_4()
