#!/usr/bin/env python

import os
import logging
import time
import pickle
import sys

l = logging.getLogger("angr.tests.test_cfg")

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

def compare_cfg(standard, g, function_list):
    '''
    Standard graph comes with addresses only, and it is based on instructions, not on basic blocks
    '''

    def get_function_name(addr):
        start = 0
        end = len(function_list) - 1

        while start <= end:
            mid = (start + end) / 2
            f = function_list[mid]
            if addr < f['start']:
                end = mid - 1
            elif addr > f['end']:
                start = mid + 1
            else:
                return f['name']

        return None

    # Sort function list
    function_list = sorted(function_list, key=lambda x: x['start'])

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
        if len(successors) == 1 and successors[0] >= block[0]:
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
            l.error("Edge (%s-0x%x, %s-0x%x) only exists in IDA CFG.", get_function_name(src), src, get_function_name(dst), dst)

    for src, dst in graph.edges():
        if s_graph.has_edge(src, dst):
            continue
        else:
            # Edge doesn't exist in our CFG
            l.error("Edge (%s-0x%x, %s-0x%x) only exists in angr's CFG.", get_function_name(src), src, get_function_name(dst), dst)

def perform_test(binary_path, cfg_path=None):
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic')
    start = time.time()
    cfg = proj.analyze('CFG', context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    bbl_dict = cfg.get_bbl_dict()

    l.info("CFG generated in %f seconds." % duration)
    l.info("Contains %d members in BBL dict." % len(bbl_dict))

    if cfg_path is not None and os.path.isfile(cfg_path):
        # Compare the graph with a predefined CFG
        info = pickle.load(open(cfg_path, "rb"))
        standard = info['cfg']
        functions = info['functions']
        graph = cfg.graph

        compare_cfg(standard, graph, functions)
    else:
        l.warning("No standard CFG specified.")

def _test_cfg_0():
    binary_path = test_location + "/blob/x86_64/cfg_0"
    cfg_path = binary_path + ".cfg"
    print "CFG 0"

    perform_test(binary_path, cfg_path)

def _test_cfg_1():
    binary_path = test_location + "/blob/x86_64/cfg_1"
    cfg_path = binary_path + ".cfg"
    print "CFG 1"

    perform_test(binary_path, cfg_path)

def _test_cfg_2():
    binary_path = test_location + "/blob/armel/test_division"
    cfg_path = binary_path + ".cfg"
    print "CFG 2"

    perform_test(binary_path, cfg_path)

def _test_cfg_3():
    binary_path = test_location + "/blob/mips/test_arrays_mips"
    cfg_path = binary_path + ".cfg"

    print "CFG 3"

    perform_test(binary_path, cfg_path)

def _test_cfg_4():
    binary_path = test_location + "/blob/mipsel/darpa_ping"
    cfg_path = binary_path + ".cfg"

    print "CFG 4"

    perform_test(binary_path, cfg_path)

def _test_cfg_5():
    binary_path = test_location + "/blob/mipsel/busybox"
    cfg_path = binary_path + ".cfg"

    print "CFG 5"

    perform_test(binary_path, cfg_path)

def run_all_tests():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('_test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.cfg").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) > 1:
        globals()['_test_' + sys.argv[1]]()
    else:
        run_all_tests()
