#!/usr/bin/env python

import os
import logging
import time
import pickle
import sys

l = logging.getLogger("angr.tests.test_ddg")

import nose

try:
    import standard_logging
    import angr_debug
except ImportError:
    pass

import angr

# Load the tests
test_location = str(os.path.dirname(os.path.realpath(__file__)))

def perform_test(binary_path):
    proj = angr.Project(binary_path,
                        use_sim_procedures=True,
                        default_analysis_mode='symbolic')
    start = time.time()
    cfg = proj.analyses.CFG(context_sensitivity_level=2)
    end = time.time()
    duration = end - start
    bbl_dict = cfg.get_bbl_dict()

    l.info("CFG generated in %f seconds." % duration)

    ddg = proj.analyses.DDG(cfg)

    __import__('ipdb').set_trace()


def _test_ddg_0():
    binary_path = test_location + "/blob/x86_64/cfg_0"
    print "DDG 0"

    perform_test(binary_path)

def run_all_tests():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('_test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        all_functions[f]()

if __name__ == "__main__":
    logging.getLogger("simuvex.plugins.abstract_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.surveyors.Explorer").setLevel(logging.DEBUG)
    #logging.getLogger("simuvex.plugins.symbolic_memory").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.cfg").setLevel(logging.DEBUG)
    logging.getLogger("angr.analyses.ddg").setLevel(logging.DEBUG)
    # logging.getLogger("s_irsb").setLevel(logging.DEBUG)
    # Temporarily disable the warnings of claripy backend
    #logging.getLogger("claripy.backends.backend").setLevel(logging.ERROR)
    #logging.getLogger("claripy.claripy").setLevel(logging.ERROR)

    if len(sys.argv) > 1:
        globals()['_test_' + sys.argv[1]]()
    else:
        run_all_tests()

