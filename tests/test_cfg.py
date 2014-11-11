#!/usr/bin/env python

import os
import logging
import time
import pickle

l = logging.getLogger("angr_tests")

import nose
import pprint
import networkx

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))
cfg_tests = {}

def compare_cfg(standard, g):
    '''
    Standard graph comes with addresses only, and it is based on instructions, not on basic blocks
    '''

    # Convert the IDA-style CFG into VEX-style CFG
    s_graph = networkx.DiGraph()
    all_nodes = sorted(standard.nodes())
    addr_to_basicblock = {}
    last_basicblock = None
    for n in all_nodes:
        if last_basicblock is None:
            last_basicblock = (n, n)

        block = last_basicblock
        successors = standard.successors(n)
        if len(successors) == 1:
            last_basicblock = (block[0], successors[0])
        else:
            # Save the existing block
            addr_to_basicblock[block[0]] = block

            # Create edges
            for s in successors:
                s_graph.add_edge(block[0], s)

            # Clear last_basicblock so that we create a new basicblock next time
            last_basicblock = None

    graph = networkx.DiGraph()
    for src, dst in g.edges():
        graph.add_edge(src.addr, dst.addr)

    # Graph comparison
    for src, dst in s_graph.edges():
        if graph.has_edge(src, dst):
            continue
        else:
            # Edge doesn't exist in our CFG
            l.error("Edge (0x%x, 0x%x) only exists in IDA's CFG.", src, dst)

    for src, dst in graph.edges():
        if s_graph.has_edge(src, dst):
            continue
        else:
            # Edge doesn't exist in our CFG
            l.error("Edge (0x%x, 0x%x) only exists in our CFG.", src, dst)

def test_cfg_0():
    binary_path = test_location + "/blob/x86_64/cfg_0"
    binary_cfg_path = binary_path + ".cfg"

    cfg_tests[0] = angr.Project(binary_path,
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 0"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[0].analyze('CFG', context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    bbl_dict = cfg.get_bbl_dict()

    l.info("CFG generated in %f seconds." % duration)
    l.info("Contains %d members in BBL dict." % len(bbl_dict))

    if os.path.isfile(binary_cfg_path):
        # Compare the graph with a predefined CFG
        standard = pickle.load(open(binary_cfg_path, "rb"))
        graph = cfg.graph

        compare_cfg(standard, graph)

def test_cfg_1():
    cfg_tests[1] = angr.Project(test_location + "/blob/x86_64/cfg_1",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 1"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[1].analyze('CFG', context_sensitivity_level=2)
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
    cfg = cfg_tests[2].analyze('CFG', context_sensitivity_level=2)
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
    cfg = cfg_tests[3].analyze('CFG', context_sensitivity_level=2)
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
    cfg = cfg_tests[4].analyze('CFG', context_sensitivity_level=1)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

def test_cfg_5():
    cfg_tests[5] = angr.Project(test_location + "/blob/mipsel/busybox",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')
    print "CFG 5"
    global scout_tests
    start = time.time()
    cfg = cfg_tests[5].analyze('CFG', context_sensitivity_level=1)
    end = time.time()
    duration = end - start
    print "Normal: Done in %f seconds." % duration
    bbl_dict = cfg.get_bbl_dict()
    graph = cfg.graph
    print "Contains %d members in BBL dict." % len(bbl_dict)
    print graph.nodes()

    import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    import sys

    sys.setrecursionlimit(1000000)

    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)
    test_cfg_0()
    # test_cfg_1()
    # test_cfg_2()
    # test_cfg_3()
    # test_cfg_4()
    # test_cfg_5()
