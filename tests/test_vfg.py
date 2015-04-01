#!/usr/bin/env python

import os
import logging
import time
import pickle
l = logging.getLogger("angr_tests")

import nose
import pprint

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import ana
import angr
import simuvex

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))
vfg_tests = {}

def setup_module():
    global scout_tests
    vfg_tests[0] = angr.Project(test_location + "/blob/x86_64/basic_buffer_overflows",
                                use_sim_procedures=True,
                                default_analysis_mode='symbolic')

def test_vfg_0():
    print "VFG 0"

    # setup datalayer so that we can pickle CFG
    ana.set_dl(pickle_dir="/tmp")
    cfg_dump_filename = "/tmp/test_vfg_0.cfg_dump"

    cfg_loaded = False
    while not cfg_loaded:
        if os.path.isfile(cfg_dump_filename):
            try:
                cfg = pickle.load(open(cfg_dump_filename, "rb"))
                cfg_loaded = True

            except Exception:
                os.remove(cfg_dump_filename)

        else:
            cfg = vfg_tests[0].analyses.CFG(context_sensitivity_level=1)
            pickle.dump(cfg, open(cfg_dump_filename, "wb"))

            cfg_loaded = True

    start = time.time()
    #vfg = vfg_tests[0].construct_vfg(start=0x401630, context_sensitivity_level=2, interfunction_level=2)
    #vfg = vfg_tests[0].construct_vfg(start=0x855f8624, context_sensitivity_level=2, interfunction_level=2)
    vfg = vfg_tests[0].analyses.VFG(cfg, function_start=0x40068f, context_sensitivity_level=2, interfunction_level=4)
    #vfg = vfg_tests[0].construct_vfg(start=0x403350, context_sensitivity_level=2)
    end = time.time()
    duration = end - start

    print "Normal: Done in %f seconds." % duration
    nodes = vfg._nodes
    print "Contains %d VFGNodes." % len(nodes)

    import ipdb; ipdb.set_trace()

if __name__ == "__main__":
    import sys
    # logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("cle.elf").setLevel(logging.DEBUG)
    logging.getLogger("cle.ld").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.vfg").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    logging.getLogger("claripy.claripy").setLevel(logging.ERROR)
    setup_module()
    test_vfg_0()
